import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import random

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///losowanie.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

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
        if len(rows) != 1 or not check_password_hash(rows[0]["password_hashed"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash('Zalogowany!')
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
    flash('Wylogowany!')
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Check for username
        if not request.form.get("username"):
            return apology("must provide username")

        # Checks if the username is taken or free
        check = []
        tmp = db.execute("SELECT username FROM users")
        index = 0
        while index < len(tmp):
            for key in tmp[index]:
                check.append(tmp[index][key])
            index += 1
        if request.form.get("username") in check:
            return apology("username already taken")

        # Check for password
        elif not request.form.get("password"):
            return apology("must provide password")

        # Checks the passwords
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match")
        else:
            username = request.form.get("username")
            password = request.form.get("password")
            hash = generate_password_hash(password)

            # Adds the user to the database of the users
            db.execute("INSERT INTO users (username, password_hashed) VALUES (?, ?)", username, hash)

            # The user after registration logs in
            rows = db.execute("SELECT * FROM users WHERE username = ?", username)
            session["user_id"] = rows[0]["id"]

            flash('Zarejestrowany!!')
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allows the logged user to changer their password"""
    if request.method == "POST":

        # Checks for the input of the password
        password_old = request.form.get("password_old")
        if not password_old:
            return apology("the password is neeeded")

        # Checks for the correctness of the password
        password_from_db = db.execute("SELECT password_hashed FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(password_from_db[0]["password_hashed"], password_old):
            return apology("invalid password")

        # Checks if the new password is inserted
        password_new = request.form.get("password_new")
        if not password_new:
            return apology("insert the new password")

        # Checks if again the new password is inserted
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("insert again the new password")

        # Checks if the new passwords match
        if not password_new == confirmation:
            return apology("the new passwords do not match")

        # Requires that the new password is different from the old one
        if password_new == password_old:
            return apology("the new password must differ from the old password")

        # If all checks done, updates the hash value stored in the db
        db.execute("UPDATE users SET password_hashed = ? WHERE id = ?",
                   generate_password_hash(password_new), session["user_id"])

        flash('Zmieniono hasło!')
        return redirect("/")

    return render_template("change_password.html")


@app.route("/")
@login_required
def index():
    """Pokazuje osobe wylosowaną bądź nie"""

    # Lista dictionara z użytkownika zalogowanego
    random = db.execute("SELECT random_hashed FROM users WHERE id =?", session["user_id"])

    # Jeżeli nie ma wylosowanego, zwraca stronę informującą o brak zalogowania
    if not random[0]["random_hashed"]:
        return render_template("niewylosowany.html")

    # Tworzy listę wszystkich userów
    tmp = db.execute("SELECT random_hashed FROM users WHERE id = ?", session["user_id"])
    temporary = db.execute("SELECT username FROM users")
    users = []
    index = 0
    while index < len(temporary):
        for key in temporary[index]:
            users.append(temporary[index][key])
        index += 1

    # Iteruje każdego użytkownika i sprawdza czy on wylosował daną osobę
    for user in users:
        print(user)

        # Jak znajdzie to generuje htmla z wylosową osobą
        if check_password_hash(tmp[0]["random_hashed"], user):
            return render_template("wylosowany.html", user = user)

    return apology("coś nie pykło")





@app.route("/losowanie", methods=["GET", "POST"])
@login_required
def losowanie():
    """Losowanie dla admina"""

    # Bierze id zalogowanego użytkownika
    tmp = db.execute("SELECT id FROM users WHERE id =?", session["user_id"])

    # Jeżeli ID = 1, to jest to admin i on może przeprowadzić losowanie
    if tmp[0]["id"] != 1:
        return apology("tylko admin może losować")

    # Losowanie
    if request.method == "POST":

        # Tworzy liste użytkowników zarejestrowanych
        tmp = db.execute("SELECT username FROM users")
        users = []
        index = 0
        while index < len(tmp):
            for key in tmp[index]:
                users.append(tmp[index][key])
            index += 1

        # Drukuje stworzoną listę
        print(f"Użytkownicy: {users}")

        # Proces losowania
        randoms = []
        removes = []
        for user in users:
            removes.append(user)

        # Proces losowania cd.
        for user in users:
            while True:
                tmp = random.randrange(len(removes))

                if user != removes[tmp]:
                    randoms.append(removes[tmp])
                    removes.pop(tmp)
                    break
                elif len(removes) == 1:
                    return apology("error, ostatnia osoba moze wylosowac tylko siebie")

        # Generuje wylosowaną listę losowych osób
        print(f"Wylosowani: {randoms}")

        # Sprawdza czy na pewno się nie pokrywają
        for i in range(len(users)):
            if users[i] == randoms[i]:
                return apology("niepoprawne wylosowanie")

        # Dla każdego użytkownika tworzy zahashowaną wartość i ją przypisuje do bazy danych
        i = 1
        for person in randoms:
            tmp = generate_password_hash(person)
            db.execute("UPDATE users SET random_hashed = ? WHERE id = ?",
                   tmp, i)
            i += 1


        flash('Wylosowano!')
        return redirect ("/")

    return render_template("losowanie.html")