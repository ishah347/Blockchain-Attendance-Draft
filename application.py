# Python module imports
import qrcode
from Crypto.PublicKey import RSA
from Crypto import Random
from cs50 import SQL
from threading import Timer
import os
from tempfile import mkdtemp
from ast import literal_eval
from werkzeug.security import check_password_hash, generate_password_hash
import datetime as dt
from pytz import timezone
import hashlib
from flask import Flask, request, render_template, Response, session
from flask_session import Session

# Importing local functions
from block import *
from genesis import create_genesis_block
from newBlock import next_block, add_block
from getBlock import find_records
from checkChain import check_integrity
from helpers import apology, login_required, password_check, generate_string

# Flask declarations
app = Flask(__name__)
response = Response()
response.headers.add('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0')

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Initializing blockchain with the genesis block
blockchain = create_genesis_block()
data = []
tz = timezone('EST')

db = SQL("sqlite:///user.db")

# Default Landing page of the app
@app.route('/',  methods = ['GET'])
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure type was submitted
        elif not request.form.get("account_type"):
            return apology("must provide type", 403)

        # Query database for username
        rows1 = db.execute("SELECT * FROM users WHERE username = :username AND account_type = :account_type",
                          username=request.form.get("username"), account_type=request.form.get("account_type"))

        # Ensure username exists and password is correct
        if len(rows1) != 1 or not check_password_hash(rows1[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows1[0]["id"]

        rows2 = db.execute("SELECT account_type FROM users WHERE username = :username AND account_type = :account_type",
                          username=request.form.get("username"), account_type=request.form.get("account_type"))

        # Redirect user to appropriate page
        if rows2[0]["account_type"] == 'Instructor':
            classes = db.execute("SELECT * FROM classes WHERE instructor_id = :userid", userid=session["user_id"])
            return render_template("i_home.html", classes=classes)
        else:
            classes = db.execute("SELECT * FROM registrations WHERE student_id = :userid", userid=session["user_id"])
            return render_template("s_home.html", classes=classes)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure full name was submitted
        if not request.form.get("fullname"):
            return apology("must provide full name", 400)

        # Ensure username was submitted
        elif not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure type was submitted
        elif not request.form.get("account_type"):
            return apology("must provide type", 400)

        # Check if password and the password confirmation are the same
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match", 400)

        # Check if password meets requirements
        elif not password_check(request.form.get("password")):
            return apology("Password must contain at least 8 characters, one number, and one capital letter", 400)

        # Hash and encrypt password
        hash = generate_password_hash(request.form.get("password"))

        # Add everything to database
        result = db.execute("INSERT INTO users (fullname, username, account_type, hash) VALUES(:fullname, :username, :account_type, :hash)",
                            fullname = request.form.get("fullname"),username=request.form.get("username"),account_type=request.form.get("account_type"), hash=hash)

        # Check if username already exists
        if not result:
            return apology("Username already exists", 400)

        # Log in user automatically
        session["user_id"] = result

        # Redirect user to home page
        if request.form.get("account_type") == "Instructor":
            classes = db.execute("SELECT * FROM classes WHERE instructor_id = :userid", userid=session["user_id"])
            return render_template("i_home.html", classes=classes)
        else:
            classes = db.execute("SELECT * FROM registrations WHERE student_id = :userid", userid=session["user_id"])
            return render_template("s_home.html", classes=classes)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    """Changes user's password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure old password was submitted
        if not request.form.get("old password"):
            return apology("must provide old password", 400)

        # Ensure new password was submitted
        elif not request.form.get("new password"):
            return apology("must provide new password", 400)

        # Ensure new password confirmation was submitted
        elif not request.form.get("confirm new password"):
            return apology("must confirm new password", 400)

        # Check if new password and the new password confirmation are the same
        elif request.form.get("new password") != request.form.get("confirm new password"):
            return apology("New passwords don't match", 400)

        # Check if old password given matches the current password
        rows1 = db.execute("SELECT hash FROM users WHERE id = :userid", userid=session["user_id"])
        if not check_password_hash(rows1[0]["hash"], request.form.get("old password")):
            return apology("New password cannot be old password", 400)

        # Add new password to database
        newhash = generate_password_hash(request.form.get("new password"))
        db.execute("UPDATE users SET hash = :newhash WHERE id = :userid",
                   newhash=newhash, userid=session["user_id"])

        rows2 = db.execute("SELECT account_type FROM users WHERE id = :userid", userid=session["user_id"])

        # Redirect user to appropriate page
        if rows2[0]["account_type"] == "Instructor":
            classes = db.execute("SELECT * FROM classes WHERE instructor_id = :userid", userid=session["user_id"])
            return render_template("i_home.html", classes=classes)
        else:
            classes = db.execute("SELECT * FROM registrations WHERE student_id = :userid", userid=session["user_id"])
            return render_template("s_home.html", classes=classes)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("changepassword.html")

@app.route("/drop_class", methods=["GET", "POST"])
@login_required
def drop_class():
    """Allows student to drop class."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure class was submitted
        if not request.form.get("class_name"):
            return apology("must choose class", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for hash
        row = db.execute("SELECT hash FROM users WHERE id = :user_id AND account_type = :account_type",
                          user_id=session["user_id"], account_type="Student")

        # Ensure password is correct
        if not check_password_hash(row[0]["hash"], request.form.get("password")):
            return apology("incorrect password", 403)

        # Delete class from registration database
        class_name = request.form.get("class_name")
        db.execute("DELETE FROM registrations WHERE class_name = :class_name AND student_id = :user_id", class_name=class_name, user_id=session["user_id"])

        # Return to student home
        classes = db.execute("SELECT * FROM registrations WHERE student_id = :userid", userid=session["user_id"])
        return render_template("s_home.html", classes=classes)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("drop_class.html")

@app.route("/add_class", methods=["GET", "POST"])
@login_required
def add_class():
    """Allows student to add class."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure class was submitted
        if not request.form.get("class_name"):
            return apology("must choose class", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for hash
        row = db.execute("SELECT hash FROM users WHERE id = :user_id AND account_type = :account_type",
                          user_id=session["user_id"], account_type="Student")

        # Ensure password is correct
        if not check_password_hash(row[0]["hash"], request.form.get("password")):
            return apology("incorrect password", 403)

        # Create a key for the student and instructor
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)

        private_key = key.exportKey(format='PEM', passphrase=None, pkcs=1)
        public_key = key.publickey().exportKey(format='PEM', passphrase=None, pkcs=1)

        # Add registration to registration database
        class_name = request.form.get("class_name")
        rows1 = db.execute("SELECT * FROM classes WHERE class_name = :class_name", class_name=class_name)
        if len(rows1) != 1:
            return apology("invalid class", 403)
        rows2 = db.execute("SELECT fullname FROM users WHERE id = :user_id", user_id=session["user_id"])
        db.execute("INSERT INTO registrations (student_id, class_name, instructor_name, student_name, student_key, instructor_key) VALUES(:student_id, :class_name, :instructor_name, :student_name, :student_key, :instructor_key)",
                     student_id=session["user_id"], class_name=class_name, instructor_name=rows1[0]["instructor_name"], student_name=rows2[0]["fullname"], student_key=private_key.decode(), instructor_key=public_key.decode())

        # Return to student home
        classes = db.execute("SELECT * FROM registrations WHERE student_id = :userid", userid=session["user_id"])
        return render_template("s_home.html", classes=classes)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("add_class.html")

@app.route("/create_class", methods=["GET", "POST"])
@login_required
def create_class():
    """Allows instructor to create class."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure class was submitted
        if not request.form.get("class_name"):
            return apology("must write name of class", 403)

        # Ensure start time was submitted
        if not request.form.get("start_time"):
            return apology("must write start time", 403)

        # Ensure class was submitted
        if not request.form.get("end_time"):
            return apology("must write end time", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for hash
        row = db.execute("SELECT hash FROM users WHERE id = :user_id AND account_type = :account_type",
                          user_id=session["user_id"], account_type="Instructor")

        # Ensure password is correct
        if not check_password_hash(row[0]["hash"], request.form.get("password")):
            return apology("incorrect password", 403)

        # Add class to classes database
        rows = db.execute("SELECT fullname FROM users WHERE id = :user_id", user_id=session["user_id"])
        db.execute("INSERT INTO classes ('instructor_id', 'instructor_name', 'class_name', 'start_time', 'end_time') VALUES(:instructor_id, :instructor_name, :class_name, :start_time, :end_time)",
                       instructor_id=session["user_id"], instructor_name=rows[0]["fullname"], class_name=request.form.get("class_name"), start_time=request.form.get("start_time"), end_time=request.form.get("end_time"))

        # Return to student home
        classes = db.execute("SELECT * FROM classes WHERE instructor_id = :userid", userid=session["user_id"])
        return render_template("i_home.html", classes=classes)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("create_class.html")

@app.route("/s_home", methods=["GET", "POST"])
@login_required
def s_home():
    """Activities on the student home page"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if(request.form.get("register")):
            return render_template("add_class.html")
        else:
            now = dt.datetime.now(tz)
            rows = db.execute("SELECT * FROM classes WHERE class_name = :class_name", class_name=request.form.get("class"))
            start = dt.datetime.strptime(rows[0]["start_time"], '%H:%M')
            end = dt.datetime.strptime(rows[0]["end_time"], '%H:%M')
            start1 = now.replace(year=now.year, month=now.month, day=now.day, hour=start.hour, minute=start.minute, second=0, microsecond=0)
            end1 = now.replace(year=now.year, month=now.month, day=now.day, hour=end.hour, minute=end.minute, second=0, microsecond=0)
            if start1 <= now < end1:
                return render_template("attend_con.html", c=request.form.get("class"))
            else:
                return apology("class is not in session", 403)
    else:
        return render_template("s_home.html")

@app.route("/attend_con", methods=["GET", "POST"])
@login_required
def attend_con():
    """Allows student to prove attendance"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure hash was submitted
        if not request.form.get("hash"):
            return apology("must enter hash", 403)

        # Ensure class was submitted
        elif not request.form.get("class"):
            return apology("must enter class", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for hash
        rows1 = db.execute("SELECT hash FROM users WHERE id = :user_id AND account_type = :account_type",
                          user_id=session["user_id"], account_type="Student")

        # Ensure password is correct
        if not check_password_hash(rows1[0]["hash"], request.form.get("password")):
            return apology("incorrect password", 403)

        rows2 = db.execute("SELECT * FROM registrations WHERE class_name = :class_name AND student_id = :user_id", class_name=request.form.get("class"), user_id=session["user_id"])

        key = RSA.importKey(rows2[0]["student_key"])

        dec = key.decrypt(literal_eval(request.form.get("hash"))).decode()

        rows3 = db.execute("SELECT * FROM classes WHERE class_name = :class_name", class_name=request.form.get("class"))

        if dec == rows3[0]["daily_phrase"]:
            db.execute("UPDATE registrations SET staus = 'PRESENT' WHERE class_name = :class_name AND student_id = :user_id", class_name=request.form.get("class"), user_id=session["user_id"])
            classes = db.execute("SELECT * FROM registrations WHERE student_id = :userid", userid=session["user_id"])
            return render_template("s_home.html", classes=[])

        else:
            return apology("incorrect hash", 403)
    else:
        return render_template("s_home.html")


@app.route("/i_home", methods=["GET", "POST"])
@login_required
def i_home():
    """Activities on the instructor home page"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if(request.form.get("create")):
            return render_template("create_class.html")
        elif(request.form.get("check")):
            return render_template("integrity.html", integrity = check_integrity(blockchain))
        elif(request.form.get("generate")):
            # Citation: https://stackoverflow.com/questions/32834731/how-to-delete-a-file-by-extension-in-python/32834791
            dir_name = "static/"
            test = os.listdir(dir_name)
            for item in test:
                if item.endswith(".zip"):
                    os.remove(os.path.join(dir_name, item))
                else:
                    continue
            db.execute("UPDATE registrations SET status = 'ABSENT' WHERE class_name = :class_name", class_name=request.form.get("generate"))
            form = []
            data = []
            daily_phrase = generate_string()
            db.execute("UPDATE classes SET daily_phrase = :daily_phrase WHERE class_name = :class_name",
                   daily_phrase=daily_phrase, class_name=request.form.get("generate"))
            rows1 = db.execute("SELECT * FROM registrations WHERE class_name = :class_name", class_name=request.form.get("generate"))
            for row in rows1:
                key = RSA.importKey(row["instructor_key"])
                enc = key.encrypt(daily_phrase.encode(), 32)
                img = qrcode.make(enc)
                img.save("static/%s.jpg" % row["student_name"])
                form.append(row["student_name"])
            # Citation: https://stackoverflow.com/questions/15088037/python-script-to-do-something-at-the-same-time-every-day
            rows2 = db.execute("SELECT * FROM classes WHERE class_name = :class_name", class_name=request.form.get("generate"))
            end = dt.datetime.strptime(rows2[0]["end_time"], '%H:%M')
            x = dt.datetime.now()
            y = x.replace(year=x.year, month=x.month, day=x.day, hour=end.hour, minute=end.minute, second=0, microsecond=0)
            delta_t = y - x
            secs= delta_t.seconds + 1
            t = Timer(secs, add_block(request.form.get("generate"), blockchain))
            t.start()
            return render_template("generate.html", form = form)
        else:
            dates = []
            students = []
            statuses = []
            for block in blockchain:
                if len(block.data) == 1:
                    dates.append(block.data[0][0])
                    students.append(block.data[0][1])
                    statuses.append(block.data[0][2])
                else:
                    continue
            return render_template("attend_list.html", dates=dates, students=students, statuses=statuses)

    else:
        return render_template("i_home.html")

# Start the flask app when program is executed
if __name__ == "__main__":
    app.run()
