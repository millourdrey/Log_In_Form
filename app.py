from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
)
import sqlite3
import hashlib
import hmac
import secrets
import os
from datetime import date


def generate_password_hash(password):
    """Create a salted PBKDF2 password hash without an extra import."""
    salt = secrets.token_bytes(16)
    iterations = 600_000
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"pbkdf2:sha256:{iterations}${salt.hex()}${digest.hex()}"


def check_password_hash(stored_hash, password):
    """Verify hashes produced by generate_password_hash."""
    try:
        method, salt_hex, digest_hex = stored_hash.split("$", 2)
        algorithm, name, iterations_text = method.split(":", 2)
        if algorithm != "pbkdf2" or name != "sha256":
            return False
        iterations = int(iterations_text)
        if iterations <= 0:
            return False
        digest = hashlib.pbkdf2_hmac(
            name,
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            iterations,
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError, OverflowError):
        return False

app = Flask(__name__, template_folder=".", static_folder=".", static_url_path="/static")

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "development-only-change-me")

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")



def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            dob TEXT NOT NULL,
        gender TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            status TEXT NOT NULL DEFAULT 'active'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            author_id INTEGER NOT NULL,
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
    """)

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "role" not in columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'"
        )
    if "status" not in columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
        )


    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_exists = conn.execute(
        "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1",
    ).fetchone()
    if admin_exists is None:
        conn.execute(
            """INSERT INTO users
               (first_name, last_name, email, username, phone, address, dob, gender, password, role)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'admin')""",
            (
                "System", "Administrator", "admin@example.com", admin_username,
            
                "N/A", "N/A", "2000-01-01", "male",
                generate_password_hash(os.environ.get("ADMIN_PASSWORD", "admin")),




            ),
        )

    conn.commit()
    conn.close()


def validate_account_details(data, password, confirm_password):
    """Return a helpful validation error, or None when an account is valid."""
    required_fields = {
        "first name": data["first_name"],
        "last name": data["last_name"],
        "email": data["email"],
        "username": data["username"],
        "phone number": data["phone"],
        "address": data["address"],
        "date of birth": data["dob"],
        "gender": data["gender"],
    }
    missing = next((name for name, value in required_fields.items() if not value), None)
    if missing:
        return f"Please provide your {missing}."
    if len(data["username"]) < 3:
        return "Username must be at least 3 characters long."
    if "@" not in data["email"]:
        return "Please enter a valid email address."
    try:
        if date.fromisoformat(data["dob"]) > date.today():
            return "Date of birth cannot be in the future."
    except ValueError:
        return "Please enter a valid date of birth."
    if len(password) < 6:
        return "Password must be at least 6 characters long."
    if password != confirm_password:
        return "Passwords do not match."
    return None


def account_form_data():
    """Read and normalize the common fields shared by both account forms."""
    return {
        "first_name": request.form.get("first_name", "").strip(),
        "last_name": request.form.get("last_name", "").strip(),
        "email": request.form.get("email", "").strip().lower(),
        "username": request.form.get("username", "").strip(),
        "phone": request.form.get("phone", "").strip(),
        "address": request.form.get("address", "").strip(),
        "dob": request.form.get("dob", ""),
        "gender": request.form.get("gender", "").strip(),
    }


@app.before_request
def ensure_database():
    """Create the users table when the app is served outside `python app.py`."""
    init_db()

@app.route("/")
def login_page():

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if user and user["status"] != "active":
        flash("This account is inactive. Please contact an administrator.", "error")
        return redirect(url_for("login_page"))

    if user and check_password_hash(user["password"], password):

        session["user_id"] = user["id"]

        return redirect(url_for("dashboard"))

    flash("Invalid username or password.", "error")
    return redirect(url_for("login_page"))



@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    if request.method == "GET":
        return render_template("FillupForm.html")

    data = account_form_data()
    password = request.form.get("password", "")
    error = validate_account_details(data, password, request.form.get("confirm_password", ""))
    if error:
        flash(error, "error")
        return redirect(url_for("signup_page"))

    try:
        conn = get_db()
        conn.execute(
            """INSERT INTO users
               (first_name, last_name, email, username, phone, address, dob, gender, password, role)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'student')""",
            (*data.values(), generate_password_hash(password)),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        flash("That username or email is already registered.", "error")
        return redirect(url_for("signup_page"))
    finally:
        if "conn" in locals():
            conn.close()

    flash("Account created. You can now sign in.", "success")
    return redirect(url_for("login_page"))


@app.route("/admin/accounts", methods=["GET", "POST"])
def create_account():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    current_user = conn.execute(
        "SELECT role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if current_user is None or current_user["role"] != "admin":
        conn.close()
        flash("Only administrators can create accounts.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        accounts = conn.execute(
            """SELECT id, first_name, last_name, username, email, role, status
               FROM users
               WHERE role IN ('staff', 'student')
               ORDER BY role, last_name, first_name"""
        ).fetchall()
        conn.close()
        return render_template("create_account.html", accounts=accounts)

    data = account_form_data()
    role = request.form.get("role", "student")

    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    error = validate_account_details(data, password, confirm_password)
    if error:
        conn.close()
        flash(error, "error")
        return redirect(url_for("create_account"))

    if role not in {"staff", "student"}:
        conn.close()
        flash("Choose either a staff or student account.", "error")
        return redirect(url_for("create_account"))


    hashed_password = generate_password_hash(password)


    try:

        conn.execute("""
            INSERT INTO users
            (
                first_name,
                last_name,
                email,
                username,
                phone,
                address,
                dob,
                gender,
                password,
                role
            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["first_name"],
            data["last_name"],
            data["email"],
            data["username"],
            data["phone"],
            data["address"],
            data["dob"],
            data["gender"],
            hashed_password,
            role,
        ))

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        flash("That username or email is already registered.", "error")
        return redirect(url_for("create_account"))

    conn.close()

    flash(f"{role.title()} account created successfully.", "success")
    return redirect(url_for("create_account"))


@app.route("/admin/announcements", methods=["GET", "POST"])
def announcements():
    """Let administrators publish notices for the school community."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    current_user = conn.execute(
        "SELECT role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if current_user is None or current_user["role"] != "admin":
        conn.close()
        flash("Only administrators can manage announcements.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        if not title or not body:
            flash("Please provide both a title and message.", "error")
        elif len(title) > 120 or len(body) > 2000:
            flash("The announcement is too long.", "error")
        else:
            conn.execute(
                "INSERT INTO announcements (title, body, author_id) VALUES (?, ?, ?)",
                (title, body, session["user_id"]),
            )
            conn.commit()
            conn.close()
            flash("Announcement published.", "success")
            return redirect(url_for("announcements"))

    notices = conn.execute(
        """SELECT announcements.id, announcements.title, announcements.body,
                  announcements.created_at, users.first_name, users.last_name
           FROM announcements
           JOIN users ON users.id = announcements.author_id
           ORDER BY announcements.created_at DESC, announcements.id DESC"""
    ).fetchall()
    conn.close()
    return render_template("announcements.html", notices=notices)


@app.route("/admin/accounts/<int:account_id>/status", methods=["POST"])
def update_account_status(account_id):
    """Allow an administrator to activate or deactivate staff/student accounts."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    new_status = request.form.get("status", "")
    if new_status not in {"active", "inactive"}:
        flash("Invalid account status.", "error")
        return redirect(url_for("create_account"))

    conn = get_db()
    admin = conn.execute(
        "SELECT role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    account = conn.execute(
        "SELECT role FROM users WHERE id = ?", (account_id,)
    ).fetchone()
    if admin is None or admin["role"] != "admin":
        conn.close()
        flash("Only administrators can change account status.", "error")
        return redirect(url_for("dashboard"))
    if account is None or account["role"] not in {"staff", "student"}:
        conn.close()
        flash("Only staff and student accounts can be updated here.", "error")
        return redirect(url_for("create_account"))

    conn.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, account_id))
    conn.commit()
    conn.close()
    flash(f"Account marked {new_status}.", "success")
    return redirect(url_for("create_account"))



@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(url_for("login_page"))


    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    account_statuses = []
    if user is not None and user["role"] == "admin":
        account_statuses = conn.execute(
            """SELECT first_name, last_name, username, role, status
               FROM users
               WHERE role IN ('staff', 'student')
               ORDER BY role, last_name, first_name"""
        ).fetchall()

    notices = conn.execute(
        """SELECT title, body, created_at
           FROM announcements
           ORDER BY created_at DESC, id DESC
           LIMIT 5"""
    ).fetchall()

    conn.close()

    if user is None:
        session.clear()
        return redirect(url_for("login_page"))

    return render_template(
        "dashboard.html",
        user=user,
        account_statuses=account_statuses,
        notices=notices,
    )



@app.route("/profile")
def profile():

    if "user_id" not in session:

        return redirect(url_for("login_page"))


    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    if user is None:
        session.clear()
        return redirect(url_for("login_page"))

    return render_template(
        "profile.html",
        user=user
    )


@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    """Let signed-in users update their own personal details."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if user is None:
        conn.close()
        session.clear()
        return redirect(url_for("login_page"))

    if request.method == "GET":
        conn.close()
        return render_template("edit_profile.html", user=user)

    data = account_form_data()
    # The shared validator also checks the profile fields; password is unchanged here.
    error = validate_account_details(data, "unchanged-password", "unchanged-password")
    if error:
        conn.close()
        flash(error, "error")
        return redirect(url_for("edit_profile"))

    try:
        conn.execute(
            """UPDATE users
               SET first_name = ?, last_name = ?, email = ?, username = ?, phone = ?,
                   address = ?, dob = ?, gender = ?
               WHERE id = ?""",
            (*data.values(), user["id"]),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        flash("That username or email is already registered.", "error")
        return redirect(url_for("edit_profile"))

    conn.close()
    flash("Your profile has been updated.", "success")
    return redirect(url_for("profile"))



@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login_page"))

if __name__ == "__main__":

    init_db()

    app.run(debug=True)
