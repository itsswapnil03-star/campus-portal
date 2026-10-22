RUN (inside the campus-portal folder, venv activated):
  flask --app app run
Open http://localhost:5000

PROMOTE USERS (second terminal, venv activated, after registering them):
  flask --app app promote officer@test.com officer Hostel
  flask --app app promote admin@test.com admin
