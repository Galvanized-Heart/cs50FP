
import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from functools import wraps

# Configure app
app = Flask(__name__)

# Configure session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure SQLite database
db = SQL("sqlite:///workouts.db")

"""
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE workouts (
    workout_id INTEGER PRIMARY KEY,
    user_id INTEGER,
    workout_type TEXT,
    workout_difficulty TEXT,
    comments TEXT,
    time INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE exercises (
    exercise_id INTEGER PRIMARY KEY,
    workout_id INTEGER,
    sets INTEGER NOT NULL,
    reps INTEGER NOT NULL,
    hold_time INTEGER,
    rest_time INTEGER,
    exercise_difficulty TEXT,
    comments TEXT,
    muscle_group TEXT,
    FOREIGN KEY (workout_id) REFERENCES workouts(workout_id)
);
"""

@app.after_request
def after_request(response):
    # Ensure responses aren't cached
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
##########################################


###################
#### HOMEPAGE #####
###################

@app.route('/')
@login_required
def index():
    """Homepage"""

    return render_template("index.html")
##########################################


###################
##### LOG IN ######
###################

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            error = "must provide username"
            return render_template("login.html", error=error)

        # Ensure password was submitted
        elif not request.form.get("password"):
            error = "must provide password"
            return render_template("login.html", error=error)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            error = "invalid username and/or password"
            return render_template("register.html", error=error)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("login.html")
##########################################


###################
##### LOG OUT #####
###################

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
##########################################


###################
#### REGISTER #####
###################

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register new user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            error = "must provide username"
            return render_template("register.html", error=error)

        # Ensure password was submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            error = "must provide password"
            return render_template("register.html", error=error)

        # Get user input for username and password
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Verify passwords match
        if password != confirmation:
            error = "passwords do not match"
            return render_template("register.html", error=error)

        # Verify if username exists
        if len(db.execute("SELECT * FROM users WHERE username = ?", username)) > 0:
            error = "username is already taken"
            return render_template("register.html", error=error)

        # Encrypt password
        hash = generate_password_hash(password)

        # Save account info in database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        # Remember which user has logged in
        session["user_id"] = db.execute("SELECT * FROM users WHERE username = ?", username)[0]["user_id"]

        # Redirect user to homepage
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("register.html")
    ##########################################
