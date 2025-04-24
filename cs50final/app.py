
from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
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
    workout_name TEXT,
    workout_difficulty TEXT,
    comments TEXT,
    start_time TEXT ,
    end_time TEXT,
    num_exercises INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE exercises (
    exercise_id INTEGER PRIMARY KEY,
    workout_id INTEGER,
    exercise_name TEXT,
    sets INTEGER,
    reps INTEGER,
    hold_time INTEGER,
    rest_time INTEGER,
    exercise_difficulty TEXT,
    comments TEXT,
    FOREIGN KEY (workout_id) REFERENCES workouts(workout_id)
);
"""

###############################################################################
###############################################################################
###############################################################################

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

###############################################################################
###############################################################################
###############################################################################


###################
#### HOMEPAGE #####
###################

@app.route('/')
@login_required
def index():
    
    # Fetch info about recent workouts
    recent_workouts = db.execute("SELECT workout_id,start_time,workout_name,num_exercises,workout_difficulty FROM workouts WHERE user_id = ? ORDER BY workout_id DESC LIMIT 5", session["user_id"])

    # Fetch average number of execises for 20 most recent workouts
    avg_20 = db.execute("SELECT AVG(num_exercises) FROM workouts WHERE user_id = ? ORDER BY workout_id DESC LIMIT 20", session["user_id"])[0]["AVG(num_exercises)"]

    if avg_20 is None:
        avg_20 = 0

    # Fetch difficulties for 20 most recent workouts
    diff_20 = db.execute("SELECT workout_difficulty FROM workouts WHERE user_id = ? ORDER BY workout_id DESC LIMIT 20", session["user_id"])

    if diff_20 is None:
        diff_20 = 0

    # Find most common difficulty
    counter = {
        "None": 0,
        "Easy": 0,
        "Moderate": 0,
        "Hard": 0
    }

    for i in diff_20:
        if i["workout_difficulty"] == None:
            counter["None"] += 1
            
        elif i["workout_difficulty"] == "Easy":
            counter["Easy"] += 1

        elif i["workout_difficulty"] == "Moderate":
            counter["Moderate"] += 1

        elif i["workout_difficulty"] == "Hard":
            counter["Hard"] += 1

    diff_20 = max(counter, key=lambda k: counter[k])

    # Count all recorded workouts by user
    total_workouts = db.execute("SELECT COUNT(*) FROM workouts WHERE user_id = ?", session["user_id"])[0]["COUNT(*)"]

    return render_template("index.html", recent_workouts=recent_workouts, avg_20=format(avg_20,".2f"), diff_20=diff_20, total_workouts=total_workouts)


###################
##### LOG IN ######
###################

@app.route("/login", methods=["GET", "POST"])
def login():

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


###################
##### LOG OUT #####
###################

@app.route("/logout")
def logout():

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


###################
#### REGISTER #####
###################

@app.route("/register", methods=["GET", "POST"])
def register():

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


###################
##### HISTORY #####
###################

@app.route('/history')
@login_required
def history():
    
    # Fetch all of the user's workout data
    all_workouts = db.execute("SELECT workout_id,start_time,workout_name,num_exercises,workout_difficulty FROM workouts WHERE user_id = ?", session["user_id"])

    return render_template("history.html", all_workouts=all_workouts)


###########################
####### ADD WORKOUT #######
###########################

@app.route('/add_workout', methods=["GET", "POST"])
@login_required
def add_workout():

    # Check for workout session
    if session.get("workout_id") is None:

        # Create new workout for user, set #exercises to 0
        db.execute("INSERT INTO workouts (user_id, num_exercises) VALUES (?,?)", session["user_id"], 0)

        # Create session for most current workout
        session["workout_id"] = db.execute("SELECT workout_id FROM workouts WHERE user_id = ? ORDER BY workout_id DESC LIMIT 1", session["user_id"])[0]["workout_id"]

    # User reached route via POST
    if request.method == "POST":
        
        # Access form data
        data = request.form
        """
        ([
            ('w_stim', 'None'), ('w_etim', 'None'), ('w_comm', ''), 
            # If there is no w_diff, user did not select a difficulty

            ('e_id', '29'), ('e_id', '30'), ('e_id', '31'), 
            ('e_name', 'None'), ('e_name', 'None'), ('e_name', 'None'), 
            ('e_sets', ''), ('e_sets', ''), ('e_sets', ''), 
            ('e_reps', ''), ('e_reps', ''), ('e_reps', ''), 
            ('e_hold', ''), ('e_hold', ''), ('e_hold', ''), 
            ('e_rest', ''), ('e_rest', ''), ('e_rest', ''),
            ('e_comm', 'None'), ('e_comm', 'None'), ('e_comm', 'None')

            # Since the amount of e_diff coming in could vary depending on user selection,
            # it would be too complicated to try and align them with the correct e_id in
            # this data structure. It would be ideal to have the dictionaries premade for the workout
            # and each exercise.
        ])
        """

        # Create dicts for respective workout and exercise data
        dict_workout = {}
        dict_exercises = {}

        # Parse workout and exercise data
        for key, value in data.lists():
            if key[0] == "w":
                dict_workout[key] = value
            else:
                dict_exercises[key] = value

        # Store workout data in db
        db.execute("UPDATE workouts SET workout_name = ?, start_time = ?, end_time = ?, comments = ? WHERE workout_id = ?", dict_workout['w_name'][0], dict_workout["w_stim"][0], dict_workout["w_etim"][0], dict_workout["w_comm"][0], session["workout_id"])

        # If difficulty was added, store that too
        if "w_diff" in dict_workout:
            db.execute("UPDATE workouts SET workout_difficulty = ? WHERE workout_id = ?", dict_workout["w_diff"], session['workout_id'])

        # Store exercise data in db
        for i in range(0,session["exercise_count"]):
            db.execute("UPDATE exercises SET exercise_name = ?, sets = ?, reps = ?, hold_time = ?, rest_time = ?, comments = ? WHERE exercise_id = ?", dict_exercises["e_name"][i], dict_exercises["e_sets"][i], dict_exercises["e_reps"][i], dict_exercises["e_hold"][i], dict_exercises["e_rest"][i], dict_exercises["e_comm"][i], dict_exercises["e_id"][i])

        tag = request.form.get('tag')

        # Catch exercise added/removed
        if type(tag) == str:
            # Path for remove
            if tag.isdigit():
                session["exercise_id"] = tag
                return redirect("/remove_exercise")
            # Path for add
            else:
                return redirect("/add_exercise")
        

        # Remove sessions for current workout and exercise count when saved
        else:
            del session["workout_id"]
            del session["exercise_count"]

            return redirect("/")
    
    # User reached route via GET
    else:

        # Create list of difficulties
        diff = ["Easy", "Moderate", "Hard"]
        
        # Fetch current workout data
        workout_data = db.execute("SELECT * FROM workouts WHERE user_id = ? AND workout_id = ?", session["user_id"], session["workout_id"])[0]

        # Create session for number of exercises in workout
        session["exercise_count"] = workout_data["num_exercises"]

        # Fetch current exercise data
        exercise_data = db.execute("SELECT * FROM exercises WHERE workout_id = ?", session["workout_id"])

        return render_template("add_workout.html", workout_data=workout_data, exercise_data=exercise_data, diff=diff)
    

###########################
###### ADD EXERCISE #######
###########################

@app.route('/add_exercise', methods=["GET"])
@login_required
def add_exercise():
            
    # Create new exercise
    db.execute("INSERT INTO exercises (workout_id) VALUES (?)", session["workout_id"])

    # Increase number of exercises for current workout by 1
    db.execute("UPDATE workouts SET num_exercises = ? WHERE workout_id = ?", session["exercise_count"] + 1, session["workout_id"])

    return redirect("/add_workout")


###############################
####### REMOVE EXERCISE #######
###############################

@app.route('/remove_exercise', methods=["GET"])
@login_required
def remove_exercise():

    # Remove specified exercise
    db.execute("DELETE FROM exercises WHERE exercise_id = ?", session['exercise_id'])

    # Decrease number of exercises for current workout by 1
    db.execute("UPDATE workouts SET num_exercises = ? WHERE workout_id = ?", session["exercise_count"] - 1, session["workout_id"])

    return redirect("/add_workout")


#####################
####### ALIGN #######
#####################

@app.route('/align', methods=["GET"])
@login_required
def align():

    # Create session before going to add_workout
    session["workout_id"] = request.args.get("w_id")


    return redirect("/add_workout")