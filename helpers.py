from flask import redirect, render_template, request, session
from functools import wraps
import re
import random
import string
from cs50 import SQL
import qrcode

def apology(message, code=400):
    """Renders message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def password_check(p):
    a = (len(p) >= 8)
    b = (re.search('[0-9]',p) is not None)
    c = (re.search('[A-Z]',p) is not None)
    return (a and b and c)

def generate_string():
    min_length = 10
    max_length = 35
    length = random.randint(min_length, max_length)
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_lowercase + string.digits) for _ in range(length))
