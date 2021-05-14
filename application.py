import os
import numpy as np
import datetime

from cs50 import get_string

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    table = db.execute(
        "SELECT * FROM ((shares INNER JOIN users ON users.id = shares.users_id) INNER JOIN symbols ON symbols.id = shares.symbols_id) WHERE users.id = ?", session["user_id"])
    symbol = list()
    shares = list()
    name = list()
    price = list()
    total = list()
    for i in range(len(table)):
        symbol.append(table[i]["symbol"])
        shares.append(table[i]["number"])
        look = lookup(table[i]["symbol"])
        name.append(look["name"])
        price.append(look["price"])
        total.append(usd(look["price"] * table[i]["number"]))

    subtotal = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    return render_template("index.html", symbol=symbol, shares=shares, name=name, price=price, total=total, table=len(table), subtotal=usd(subtotal[0]["cash"]))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # when user hits submit start executing this code
    if request.method == "POST":
        # make sure the symbol feild is not empty
        if not request.form.get("symbol"):
            return apology("Please provide symbol")
        # make sure the symbol entered is valid
        if lookup(request.form.get("symbol")) == None:
            return apology("invalid symbol")
        # make sure user provided a number
        try:
            num = int(request.form.get("shares"))
        except:
            return apology("please provide a number")
        # make sure it's a positve number
        if num < 0:
            return apology("please provide positive number")
        # make sure the user says how many shares he/she wants
        if not request.form.get("shares"):
            return apology("how many shares do you wanna buy?")
        # create a varuble for the symbol the user entered
        symbol = request.form.get("symbol")
        # check it it's already on the data base
        if 1 != len(db.execute("SELECT symbol FROM symbols WHERE symbol = ?", symbol)):
            # if it's not then add it
            db.execute("INSERT INTO symbols (symbol) VALUES (?)", symbol)

        # create varuble for userlogged in
        userid = session["user_id"]
        # create varubale for symbol id
        symbolid = db.execute("SELECT id FROM symbols WHERE symbol = ?", symbol)
        # create varubale for shares amount
        amount = request.form.get("shares")
        cash = db.execute("SELECT cash FROM users WHERE id = ?", userid)

        # make sure user has enough cash
        look = lookup(symbol)
        up = look["price"]
        if up * float(amount) > cash[0]["cash"]:
            return apology("Sorry you don't have enough cash")
        # take money out of cash
        total = up * float(amount)
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total, userid)

        # created an empty var to insert if the user doesn't have the stock yet
        empty = 0
        # add a row if user dosen't have this stock yet
        rows = db.execute("SELECT * FROM shares WHERE users_id = ? AND symbols_id = ?", userid, symbolid[0]["id"])
        if 1 != len(rows):
            db.execute("INSERT INTO shares (number, users_id, symbols_id) VALUES(?, ?, ?)", empty, userid, symbolid[0]["id"])
        # if user already has this stock then just update
        db.execute("UPDATE shares SET number = number + ? WHERE users_id = ? AND symbols_id = ?", amount, userid, symbolid[0]["id"])
        # keep track of history
        db.execute("INSERT INTO history (users_id, symbol, shares, price, time) VALUES(?,?,?,?,?)",
                   userid, symbol, amount, usd(up), datetime.datetime.now())
        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    table = db.execute("SELECT symbol, shares, price, time FROM history WHERE users_id = ?", session["user_id"])
    return render_template("history.html", table=table)


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

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # wait for someone to call the function
    if request.method == "POST":
        # if the symbol doesn't exist then display an error message
        if lookup(request.form.get("symbol")) == None:
            return apology("Invalid Symbol")
            # if all is well then display pricing
        else:
            result = lookup(request.form.get("symbol"))
            return render_template("quoted.html", name=result["name"], price=usd(result["price"]), symbol=result["symbol"])
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # when user submites form via post
    if request.method == "POST":
        # check to see if user entered a usernam
        if not request.form.get("username"):
            return apology("must provide username")
        username = request.form.get("username")
        # check to see if this username is already taken
        if 0 < len(db.execute("SELECT username FROM users WHERE username = ?", username)):
            return apology("username is already taken")
        # check if password was provided
        if not request.form.get("password"):
            return apology("please provide password")
        password = request.form.get("password")
        # check if confirmation was provided
        if not request.form.get("confirmation"):
            return apology("please confirm password")
        confirmation = request.form.get("confirmation")
        # check if passwords match
        if password != confirmation:
            return apology("passwords do not match")
        # if all is wll then add information to data base
        else:
            # but first hash the password
            hashed = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashed)
            # redirect user to main page
            return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        dropdown = db.execute("SELECT symbol FROM symbols WHERE id IN(SELECT symbols_id FROM shares WHERE users_id = ?)",
                              session["user_id"])
        return render_template("sell.html", dropdown=dropdown)
    if request.method == "POST":
        # make sure user selects a valid symbol
        if not request.form.get("symbol"):
            return apology("please select symbol")
        if not request.form.get("shares"):
            return apology("How many shares do you wanna sell?")
        # make sure user is not trying to sell more shares then he has
        table = db.execute("SELECT * FROM ((shares INNER JOIN users ON users.id = shares.users_id) INNER JOIN symbols ON symbols.id = shares.symbols_id) WHERE users.id = ? AND symbols.symbol = ?",
                           session["user_id"], request.form.get("symbol"))
        if table[0]["number"] < int(request.form.get("shares")):
            return apology("Amount of shares entered is more then you have")
        # update cash
        current = lookup(request.form.get("symbol"))
        db.execute("UPDATE users SET cash = cash + ? WHERE id =?",
                   float(request.form.get("shares")) * current["price"], session["user_id"])

        # update amount of shares user owns
        db.execute("UPDATE shares SET number = number - ? WHERE users_id = ? AND symbols_id IN(SELECT id FROM symbols WHERE symbol = ?)",
                   request.form.get("shares"), session["user_id"], request.form.get("symbol"))

        db.execute("INSERT INTO history (users_id, symbol, shares, price, time) VALUES(?,?,?,?,?)", session["user_id"], request.form.get(
            "symbol"), "-" + request.form.get("shares"), usd(current["price"]), datetime.datetime.now())

        # delete row if there are no stocks
        db.execute("DELETE FROM shares WHERE number =?", 0)
        return redirect("/")
    else:
        return render_template("sell.html")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Update Password"""
    if request.method == "POST":
        # make sure user inputs current password
        if not request.form.get("current"):
            return apology("please provide current password")
        # make sure it's correct
        current = db.execute("SELECT hash from users WHERE id = ?",  session["user_id"])
        if len(current) != 1 or not check_password_hash(current[0]["hash"], request.form.get("current")):
            return apology("Incorrect Password")
        # make sure user provides new password
        if not request.form.get("password"):
            return apology("Please provide new password")
        # make sure user entered comfirmation
        if not request.form.get("confirmation"):
            return apology("Please confirm new password")
        # make sure both fields match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match")
        # update password
        db.execute("UPDATE users SET hash = ? WHERE id =?", generate_password_hash(
            request.form.get("password")), session["user_id"])
        return redirect("/login")
    else:
        return render_template("password.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
