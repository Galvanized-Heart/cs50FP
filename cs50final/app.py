
import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
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

@app.route('/')
def index():
    return 'Hello, World!'
