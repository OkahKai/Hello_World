import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get all stocks held by user
    stocks = db.execute(""" SELECT shares.share_name, ownership.amount, users.cash FROM shares
                       JOIN ownership
                       ON ownership.share_id = shares.share_id
                       JOIN users
                       ON users.id = ownership.person_id
                       Where ownership.person_id = ? AND ownership.amount >= 1""", session['user_id']
                        )

    # Get the cash the user has
    cash = db.execute(""" SELECT cash FROM users WHERE id = ?""",
                      session['user_id'])[0]['cash']

    total_assets = cash
    for stock in stocks:

        # Get current price of each stock
        current_price = lookup(stock['share_name'])['price']
        stock['current_price'] = current_price

        # Get total price of the share held
        total = stock['amount'] * stock['current_price']
        stock['total'] = total

        # Add shares to total stock
        total_assets = stock['total'] + total_assets
        stock['total'] = usd(stock['total'])
        stock['current_price'] = usd(current_price)

    # Convert the values to usd
    total_assets = usd(total_assets)
    cash = usd(cash)

    # Display the summarized table
    return render_template("index.html", stocks=stocks, total_assets=total_assets, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure stock_symbol was submitted
        if not request.form.get("symbol"):
            return apology("MISSING SYMBOL", 400)

        # Ensure number of shares was submitted
        if not request.form.get("shares"):
            return apology("MISSING SHARES", 400)

        # Ensure number of shares is numeric
        if not request.form.get("shares").isdigit():
            return apology("SHARES MUST BE A NUMBER", 400)

        # Ensure number of shares was valid
        if int(request.form.get("shares")) < 1:
            return apology("Number of shares must be greater than or equal to 1", 400)

        # Get information about the quote
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("INVALID SYMBOL", 400)

        # Get the amount of Money the user has
        cash = db.execute(
            """SELECT cash FROM users
                WHERE id = ?""", session["user_id"]
        )[0]['cash']

        # Compare the cash with stock price
        number_of_shares = int(request.form.get("shares"))
        stock_price = number_of_shares * stock['price']

        # Buy the Stock
        if cash > stock_price:
            cash = cash - stock_price

            # Update the users cash
            db.execute(
                """ UPDATE users SET cash = ? WHERE id = ?""", cash, session["user_id"]
            )

            # Update stock tables
            db.execute(
                """INSERT INTO shares (share_name) SELECT ?
                WHERE NOT EXISTS (SELECT 1 FROM shares WHERE share_name = ?);""",
                stock['symbol'], stock['symbol']
            )

            # Get user id and share id
            user_id = db.execute("SELECT id FROM users WHERE id = ?", session["user_id"])[0]['id']
            share_id = db.execute("SELECT share_id FROM shares WHERE share_name = ?",
                                  stock['symbol'])[0]['share_id']

            # Check if user a share in this stock
            count = db.execute(""" SELECT COUNT(*) FROM ownership WHERE
                               person_id = ? AND share_id = ?;""",
                               user_id, share_id)[0]['COUNT(*)']

            # If user already holds a similar stock update it
            if count == 1:
                db.execute(""" UPDATE ownership SET amount = amount + ?
                           WHERE person_id = ? AND share_id = ?""",
                           number_of_shares, user_id, share_id)

            # Else add it to the table
            if count == 0:
                db.execute("""INSERT INTO ownership (person_id, share_id, amount)
                           VALUES (?, ?, ?);""",
                           user_id, share_id, number_of_shares)

                # Add transaction to history
            db.execute(""" INSERT INTO history (person_id, stock, trans_type, shares, price, time)
                        VALUES (?, ?, ?, ?, ?, ?);""", session['user_id'], stock['symbol'], "BUY", number_of_shares,
                       stock_price, datetime.now()
                       )

            # Redirect user to home page
            return redirect("/")

        # If user doesn't have enough money to buy stock
        else:
            return apology("Not enough Cash")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Print a table of all past transactions
    history = db.execute("SELECT * FROM history WHERE person_id = ?", session['user_id'])

    # convert all the prices to usd
    for transaction in history:
        transaction['price'] = usd(transaction['price'])

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("MUST PROVIDE USERNAME", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("MUST PROVIDE PASSWORD", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("INVALID USERNAME AND/OR PASSWORD", 403)

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

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Check if a symbol was passed in
        if not request.form.get("symbol"):
            return apology("MISSING SYMBOL")

        # Get information about the quote
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("INVALID SYMBOL")

        # Display details about stock
        stock['price'] = usd(stock['price'])
        return render_template('quote.html', stock=stock)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("MISSING USERNAME", 400)

        # Check if username already exist username
        row = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if not len(row) == 0:
            return apology("USER ALREADY EXIST")

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("MISSING PASSWORD", 400)

        # Ensure password was confirmed
        if not request.form.get("confirmation"):
            return apology("COMFIRM PASSWORD", 400)

        # Ensure comfirmed password is correct
        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("PASSWORDS DON'T MATCH")

        # hash the pasword
        hashed_password = generate_password_hash(request.form.get("password"))

        # Insert data into the database
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get(
                "username"), hashed_password
        )

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure stock_symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide Stock Symbol", 400)

        # Ensure number of shares was submitted
        if not request.form.get("shares"):
            return apology("must provide Number of Shares", 400)

        # Ensure number of shares submitted is >= 1
        if int(request.form.get("shares")) < 1:
            return apology("Number of shares must be above 1", 403)

        # Get information about the quote
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Stock does not exist")

        # Get the amount of Money the user has
        cash = db.execute(
            """SELECT cash FROM users
                WHERE id = ?""", session["user_id"]
        )[0]['cash']

        # Get total price of selling stock
        number_of_shares = int(request.form.get("shares"))
        stock_price = number_of_shares * stock['price']

        # Get the stock Id of stock to be sold
        stock_id = db.execute("""SELECT share_id FROM shares WHERE share_name = ?""",
                              stock['symbol'])[0]['share_id']

        # Check if the user holds enough shares to sell
        holding = db.execute("""SELECT amount FROM ownership WHERE share_id = ?
                             AND person_id = ?""", stock_id, session['user_id'])[0]['amount']

        # Sell the Stock
        if holding >= number_of_shares:
            holding = holding - number_of_shares
            cash = cash + stock_price

            # Update the users cash
            db.execute(
                """ UPDATE users SET cash = ? WHERE id = ?""", cash, session["user_id"]
            )

            # Get the user_id and share_id
            user_id = db.execute("SELECT id FROM users WHERE id = ?", session["user_id"])[0]['id']
            share_id = db.execute("SELECT share_id FROM shares WHERE share_name = ?",
                                  stock['symbol'])[0]['share_id']

            # Update ownership table
            db.execute(""" UPDATE ownership SET amount = ?
                           WHERE person_id = ? AND share_id = ?""",
                       holding, user_id, share_id)

            # Add transaction to history
            db.execute(""" INSERT INTO history (person_id, stock, trans_type, shares, price, time)
                        VALUES (?, ?, ?, ?, ?, ?);""", session['user_id'], stock['symbol'], "SELL", number_of_shares,
                       stock_price, datetime.now()
                       )

            # Redirect user to home page
            return redirect("/")

        # If user doesn't have enough stocks to sell
        else:
            return apology("Not enough Stock")

    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Display the options of stock to sell
        return render_template("sell.html")


@app.route("/account")
@login_required
def account():

    # Get username
    username = db.execute("SELECT username FROM users WHERE id = ?",
                          session['user_id'])[0]['username']

    # Get account balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])[0]['cash']
    cash = usd(cash)

    return render_template("account.html", username=username, cash=cash)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("password"):
            return apology("MISSING PASSWORD", 403)

        # Ensure password was submitted
        if not request.form.get("new_password"):
            return apology("MISSING NEW PASSWORD", 403)

        # Ensure password was confirmed
        if not request.form.get("confirmed_password"):
            return apology("COMFIRM PASSWORD", 403)

        # Get all passwords
        password = request.form.get("password")
        new_password = (request.form.get("new_password"))
        confirmed_password = (request.form.get("confirmed_password"))
        correct_password = db.execute(
            "SELECT hash FROM users WHERE id = ?", session['user_id'])[0]['hash']

        # Ensure password is correct
        if not check_password_hash(correct_password, password):
            return apology("WRONG PASSWORD")

        # Ensure passwords match
        if not new_password == confirmed_password:
            return apology("PASSWORDS DON'T MATCH")

        # Insert data into the database
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(
                new_password), session['user_id']
        )

        # Redirect user to login
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("password.html")
