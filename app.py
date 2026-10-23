from werkzeug.middleware.proxy_fix import ProxyFix
import os
import uuid
import logging
from datetime import datetime
import click
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, abort, send_from_directory)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
import boto3
S3_BUCKET = os.environ.get('S3_BUCKET')
s3 = boto3.client('s3', region_name=os.environ.get('AWS_DEFAULT_REGION')) if S3_BUCKET else None

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
app.config.update(
    SECRET_KEY='demo-secret-change-me',
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(BASE_DIR, 'portal.db'),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,   # demo on http://localhost
    SESSION_COOKIE_SAMESITE='Lax',
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('portal')

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri='memory://')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

CATEGORIES = ['Hostel', 'Mess', 'Library', 'IT', 'Academics']
STATUSES = ['Submitted', 'Assigned', 'In progress', 'Resolved']
ALLOWED = {'png', 'jpg', 'jpeg', 'pdf'}


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='student')
    department = db.Column(db.String(20))


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='Submitted')
    anonymous = db.Column(db.Boolean, default=False)
    attachment = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User')


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


def can_view(t):
    if current_user.role == 'admin':
        return True
    if current_user.role == 'officer':
        return t.category == current_user.department
    return t.user_id == current_user.id


@app.get('/healthz')
def healthz():
    return 'ok'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        pw = request.form['password']
        if len(pw) < 8 or not name or '@' not in email:
            flash('Enter a name, a valid email and a password of 8+ characters.')
        elif User.query.filter_by(email=email).first():
            flash('That email is already registered.')
        else:
            db.session.add(User(name=name, email=email,
                                password_hash=generate_password_hash(pw)))
            db.session.commit()
            flash('Account created. Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute', methods=['POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        user = User.query.filter_by(email=email).first()
        ip = get_remote_address()
        if user and check_password_hash(user.password_hash,
                                        request.form['password']):
            login_user(user)
            log.info('LOGIN_OK user=%s ip=%s', email, ip)
            return redirect(url_for('tickets'))
        log.warning('FAILED_LOGIN user=%s ip=%s', email, ip)
        flash('Wrong email or password.')
    return render_template('login.html')


@app.post('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.get('/')
@login_required
def tickets():
    q = Ticket.query.order_by(Ticket.created_at.desc())
    if current_user.role == 'student':
        q = q.filter_by(user_id=current_user.id)
    elif current_user.role == 'officer':
        q = q.filter_by(category=current_user.department)
    return render_template('tickets.html', tickets=q.all())


@app.route('/tickets/new', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if current_user.role != 'student':
        abort(403)
    if request.method == 'POST':
        category = request.form['category']
        if category not in CATEGORIES:
            abort(400)
        saved_name = None
        f = request.files.get('attachment')
        if f and f.filename:
            ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
            if ext not in ALLOWED:
                flash('Only png, jpg and pdf files are allowed.')
                return render_template('new.html', categories=CATEGORIES)
            saved_name = '%s.%s' % (uuid.uuid4().hex, ext)
            if s3:
                s3.upload_fileobj(f, S3_BUCKET, saved_name)
            else:
                f.save(os.path.join(UPLOAD_DIR, saved_name))
        t = Ticket(title=request.form['title'].strip()[:120],
                   description=request.form['description'].strip(),
                   category=category,
                   anonymous='anonymous' in request.form,
                   attachment=saved_name,
                   user_id=current_user.id)
        db.session.add(t)
        db.session.commit()
        log.info('TICKET_CREATED id=%s category=%s', t.id, category)
        return redirect(url_for('detail', tid=t.id))
    return render_template('new.html', categories=CATEGORIES)

@app.get('/tickets/<int:tid>')
@login_required
def detail(tid):
    t = db.get_or_404(Ticket, tid)
    if not can_view(t):
        log.warning('ACCESS_DENIED user=%s ticket=%s', current_user.email, tid)
        abort(403)
    hide = t.anonymous and current_user.role == 'officer'
    owner = 'Anonymous' if hide else t.user.name
    return render_template('detail.html', t=t, owner=owner, statuses=STATUSES)


@app.post('/tickets/<int:tid>/status')
@login_required
def set_status(tid):
    t = db.get_or_404(Ticket, tid)
    if current_user.role not in ('officer', 'admin') or not can_view(t):
        abort(403)
    s = request.form['status']
    if s not in STATUSES:
        abort(400)
    t.status = s
    db.session.commit()
    return redirect(url_for('detail', tid=tid))


@app.get('/tickets/<int:tid>/file')
@login_required
def ticket_file(tid):
    t = db.get_or_404(Ticket, tid)
    if not can_view(t):
        log.warning('ACCESS_DENIED user=%s file_of_ticket=%s',
                    current_user.email, tid)
        abort(403)
    if not t.attachment:
        abort(404)
    if s3:
         url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': S3_BUCKET, 'Key': t.attachment,
                'ResponseContentDisposition': 'attachment'},
        ExpiresIn=60)
    return redirect(url)

    return send_from_directory(UPLOAD_DIR, t.attachment, as_attachment=True)


@app.cli.command('promote')
@click.argument('email')
@click.argument('role')
@click.argument('department', required=False)
def promote(email, role, department):
    u = User.query.filter_by(email=email.lower()).first()
    if not u:
        raise click.ClickException('No such user')
    u.role = role
    u.department = department
    db.session.commit()
    print('done')


if __name__ == '__main__':
    app.run(debug=False)
