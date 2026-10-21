from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    send_from_directory,
)
import sqlite3
import hashlib
import hmac
import secrets
import os
import math
from datetime import date, datetime, timedelta


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

app = Flask(__name__, template_folder=".", static_folder=None)

is_production = os.environ.get("APP_ENV", "development").lower() == "production"
secret_key = os.environ.get("FLASK_SECRET_KEY")
if is_production and (not secret_key or len(secret_key) < 32):
    raise RuntimeError("Set FLASK_SECRET_KEY to a random value of at least 32 characters in production.")
if not secret_key:
    secret_key = secrets.token_hex(32)
    app.logger.warning(
        "FLASK_SECRET_KEY is not set; using a temporary key for local development."
    )
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_production,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

DATABASE = os.environ.get(
    "DATABASE_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db"),
)
PUBLIC_STATIC_FILES = {"style.css", "logo.jpg", "prof.jpg", "portal.js"}


@app.get("/static/<path:filename>", endpoint="static")
def serve_public_static_file(filename):
    if filename not in PUBLIC_STATIC_FILES:
        abort(404)
    return send_from_directory(app.root_path, filename)


def get_csrf_token():
    token = session.get("_csrf_token")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


@app.before_request
def protect_state_changing_requests():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get("_csrf_token")
        submitted = request.form.get("csrf_token", "")
        if (
            not isinstance(expected, str)
            or not submitted
            or not hmac.compare_digest(expected, submitted)
        ):
            abort(400, description="The form security token is missing or invalid. Reload the page and try again.")


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; form-action 'self'; base-uri 'self'; "
        "frame-ancestors 'none'; object-src 'none'",
    )
    if request.endpoint != "static":
        response.headers.setdefault("Cache-Control", "no-store")
    if is_production:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response



def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
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
            status TEXT NOT NULL DEFAULT 'active',
            session_version INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS school_classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            section TEXT NOT NULL,
            staff_id INTEGER,
            FOREIGN KEY (staff_id) REFERENCES users(id),
            UNIQUE (name, section)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            FOREIGN KEY (class_id) REFERENCES school_classes(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE (class_id, student_id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            attendance_date TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('present', 'absent', 'late')),
            FOREIGN KEY (class_id) REFERENCES school_classes(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE (class_id, student_id, attendance_date)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            assessment TEXT NOT NULL,
            score REAL NOT NULL,
            max_score REAL NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (class_id) REFERENCES school_classes(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS class_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id INTEGER NOT NULL,
            weekday TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            room TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (class_id) REFERENCES school_classes(id) ON DELETE CASCADE,
            UNIQUE (class_id, weekday, start_time)
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
    if "session_version" not in columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0"
        )


    admin_username = os.environ.get("ADMIN_USERNAME", "admin")
    admin_exists = conn.execute(
        "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1",
    ).fetchone()
    if admin_exists is None:
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if len(admin_password) < 12:
            conn.close()
            raise RuntimeError(
                "Set ADMIN_PASSWORD to at least 12 characters before creating the first administrator."
            )
        conn.execute(
            """INSERT INTO users
               (first_name, last_name, email, username, phone, address, dob, gender, password, role)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'admin')""",
            (
                "System", "Administrator", "admin@example.com", admin_username,
            
                "N/A", "N/A", "2000-01-01", "male",
                generate_password_hash(admin_password),




            ),
        )

    conn.commit()
    conn.close()


def validate_account_details(data, password, confirm_password):
    """Return a helpful validation error, or None when an account is valid."""
    field_limits = {
        "first name": (data["first_name"], 80),
        "last name": (data["last_name"], 80),
        "email": (data["email"], 254),
        "username": (data["username"], 50),
        "phone number": (data["phone"], 40),
        "address": (data["address"], 300),
    }
    too_long = next(
        (name for name, (value, limit) in field_limits.items() if len(value) > limit),
        None,
    )
    if too_long:
        return f"Your {too_long} must be no more than {field_limits[too_long][1]} characters."

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
    if data["email"].count("@") != 1 or any(char.isspace() for char in data["email"]):
        return "Please enter a valid email address."
    if data["gender"] not in {"Male", "Female", "Other", "Prefer not to say"}:
        return "Choose a valid gender option."
    try:
        if date.fromisoformat(data["dob"]) > date.today():
            return "Date of birth cannot be in the future."
    except ValueError:
        return "Please enter a valid date of birth."
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if len(password) > 128:
        return "Password must be no more than 128 characters long."
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
    """Ensure the school database schema exists before handling a request."""
    if request.endpoint != "static":
        init_db()


@app.before_request
def validate_signed_in_account():
    user_id = session.get("user_id")
    if user_id is None or request.endpoint == "static":
        return None

    conn = get_db()
    user = conn.execute(
        "SELECT status, session_version FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if (
        user is None
        or user["status"] != "active"
        or session.get("session_version") != user["session_version"]
    ):
        session.clear()
        if request.endpoint not in {"login_page", "login", "signup_page"}:
            flash("Your session has expired or your account is inactive. Please sign in again.", "error")
            return redirect(url_for("login_page"))
    return None


@app.route("/")
def login_page():

    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or len(username) > 50 or not password or len(password) > 128:
        flash("Invalid username or password.", "error")
        return redirect(url_for("login_page"))

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
        session.clear()
        session["user_id"] = user["id"]
        session["session_version"] = user["session_version"]
        session.permanent = True

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


@app.route("/academics", methods=["GET", "POST"])
def academics():
    """Manage classes and view class, attendance, grade, and schedule information."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    user = conn.execute(
        "SELECT id, role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if user is None:
        conn.close()
        session.clear()
        return redirect(url_for("login_page"))

    role = user["role"]
    if request.method == "POST":
        action = request.form.get("action", "")
        class_id = request.form.get("class_id", type=int)

        if action == "create_class" and role in {"admin", "staff"}:
            name = request.form.get("name", "").strip()
            section = request.form.get("section", "").strip()
            staff_id = user["id"] if role == "staff" else request.form.get("staff_id", type=int)
            staff = conn.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'staff' AND status = 'active'",
                (staff_id,),
            ).fetchone() if staff_id else None
            if not name or not section:
                flash("Enter both a subject/class name and section.", "error")
            elif len(name) > 100 or len(section) > 40:
                flash("The subject/class name or section is too long.", "error")
            elif staff_id and staff is None:
                flash("Choose an active staff account for this class.", "error")
            else:
                try:
                    conn.execute(
                        "INSERT INTO school_classes (name, section, staff_id) VALUES (?, ?, ?)",
                        (name, section, staff_id),
                    )
                    conn.commit()
                    flash("Class created.", "success")
                except sqlite3.IntegrityError:
                    flash("That class and section already exist.", "error")

        elif action == "update_class" and role in {"admin", "staff"}:
            name = request.form.get("name", "").strip()
            section = request.form.get("section", "").strip()
            staff_id = user["id"] if role == "staff" else request.form.get("staff_id", type=int)
            school_class = conn.execute(
                """SELECT id FROM school_classes
                   WHERE id = ? AND (? = 'admin' OR staff_id = ?)""",
                (class_id, role, user["id"]),
            ).fetchone() if class_id else None
            staff = conn.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'staff' AND status = 'active'",
                (staff_id,),
            ).fetchone() if staff_id else None
            if school_class is None:
                flash("Choose an existing class to edit.", "error")
            elif not name or not section:
                flash("Enter both a subject/class name and section.", "error")
            elif len(name) > 100 or len(section) > 40:
                flash("The subject/class name or section is too long.", "error")
            elif staff_id and staff is None:
                flash("Choose an active staff account for this class.", "error")
            else:
                try:
                    conn.execute(
                        """UPDATE school_classes
                           SET name = ?, section = ?, staff_id = ?
                           WHERE id = ?""",
                        (name, section, staff_id, class_id),
                    )
                    conn.commit()
                    flash("Subject/class updated.", "success")
                except sqlite3.IntegrityError:
                    flash("A class with that subject name and section already exists.", "error")

        elif action == "enroll" and role in {"admin", "staff"}:
            student_id = request.form.get("student_id", type=int)
            class_exists = conn.execute(
                """SELECT id FROM school_classes
                   WHERE id = ? AND (? = 'admin' OR staff_id = ?)""",
                (class_id, role, user["id"]),
            ).fetchone() if class_id else None
            student = conn.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'student' AND status = 'active'",
                (student_id,),
            ).fetchone() if student_id else None
            if class_exists is None or student is None:
                flash("Choose an existing class and active student.", "error")
            else:
                try:
                    conn.execute(
                        "INSERT INTO enrollments (class_id, student_id) VALUES (?, ?)",
                        (class_id, student_id),
                    )
                    conn.commit()
                    flash("Student enrolled in the class.", "success")
                except sqlite3.IntegrityError:
                    flash("That student is already enrolled in this class.", "error")

        elif action in {"attendance", "grade"} and role in {"admin", "staff"}:
            school_class = conn.execute(
                """SELECT id FROM school_classes
                   WHERE id = ? AND (? = 'admin' OR staff_id = ?)""",
                (class_id, role, user["id"]),
            ).fetchone() if class_id else None
            student_id = request.form.get("student_id", type=int)
            enrolled = conn.execute(
                "SELECT 1 FROM enrollments WHERE class_id = ? AND student_id = ?",
                (class_id, student_id),
            ).fetchone() if school_class and student_id else None
            if school_class is None or enrolled is None:
                flash("Choose a student enrolled in a class you manage.", "error")
            elif action == "attendance":
                attendance_date = request.form.get("attendance_date", "")
                status = request.form.get("status", "")
                try:
                    date.fromisoformat(attendance_date)
                    valid_date = True
                except ValueError:
                    valid_date = False
                if not valid_date:
                    flash("Enter a valid attendance date.", "error")
                elif status not in {"present", "absent", "late"}:
                    flash("Choose present, absent, or late.", "error")
                else:
                    conn.execute(
                        """INSERT INTO attendance (class_id, student_id, attendance_date, status)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT (class_id, student_id, attendance_date)
                           DO UPDATE SET status = excluded.status""",
                        (class_id, student_id, attendance_date, status),
                    )
                    conn.commit()
                    flash("Attendance saved.", "success")
            else:
                assessment = request.form.get("assessment", "").strip()
                try:
                    score = float(request.form.get("score", ""))
                    max_score = float(request.form.get("max_score", ""))
                    valid_score = (
                        math.isfinite(score)
                        and math.isfinite(max_score)
                        and 0 <= score <= max_score
                        and max_score > 0
                    )
                except ValueError:
                    valid_score = False
                    score = 0
                    max_score = 0
                if not assessment or len(assessment) > 100:
                    flash("Enter an assessment name of no more than 100 characters.", "error")
                elif not valid_score:
                    flash("Enter a score from 0 up to a maximum score greater than 0.", "error")
                else:
                    conn.execute(
                        """INSERT INTO grades (class_id, student_id, assessment, score, max_score)
                           VALUES (?, ?, ?, ?, ?)""",
                        (class_id, student_id, assessment, score, max_score),
                    )
                    conn.commit()
                    flash("Grade saved.", "success")

        elif action == "schedule" and role in {"admin", "staff"}:
            weekday = request.form.get("weekday", "")
            start_time = request.form.get("start_time", "")
            end_time = request.form.get("end_time", "")
            room = request.form.get("room", "").strip()
            school_class = conn.execute(
                """SELECT id FROM school_classes
                   WHERE id = ? AND (? = 'admin' OR staff_id = ?)""",
                (class_id, role, user["id"]),
            ).fetchone() if class_id else None
            try:
                start = datetime.strptime(start_time, "%H:%M")
                end = datetime.strptime(end_time, "%H:%M")
                valid_times = end > start
            except ValueError:
                valid_times = False
            if school_class is None:
                flash("Choose an existing class.", "error")
            elif weekday not in {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}:
                flash("Choose a valid day of the week.", "error")
            elif not valid_times:
                flash("Enter valid times and make sure the end is after the start.", "error")
            elif len(room) > 80:
                flash("Room must be no more than 80 characters.", "error")
            else:
                try:
                    conn.execute(
                        """INSERT INTO class_schedules
                           (class_id, weekday, start_time, end_time, room)
                           VALUES (?, ?, ?, ?, ?)""",
                        (class_id, weekday, start_time, end_time, room),
                    )
                    conn.commit()
                    flash("Class schedule added.", "success")
                except sqlite3.IntegrityError:
                    flash("A schedule already exists for this class, day, and start time.", "error")
        else:
            flash("You do not have permission to perform that action.", "error")

        conn.close()
        return redirect(url_for("academics"))

    if role == "admin":
        classes = conn.execute(
            """SELECT c.id, c.name, c.section, c.staff_id, u.first_name, u.last_name,
                      (SELECT COUNT(*) FROM enrollments e WHERE e.class_id = c.id) AS student_count
               FROM school_classes c LEFT JOIN users u ON u.id = c.staff_id
               ORDER BY c.name, c.section"""
        ).fetchall()
    elif role == "staff":
        classes = conn.execute(
            """SELECT c.id, c.name, c.section, c.staff_id, u.first_name, u.last_name,
                      (SELECT COUNT(*) FROM enrollments e WHERE e.class_id = c.id) AS student_count
               FROM school_classes c LEFT JOIN users u ON u.id = c.staff_id
               WHERE c.staff_id = ? ORDER BY c.name, c.section""",
            (user["id"],),
        ).fetchall()
    elif role == "student":
        classes = conn.execute(
            """SELECT c.id, c.name, c.section, c.staff_id, u.first_name, u.last_name,
                      (SELECT COUNT(*) FROM enrollments e WHERE e.class_id = c.id) AS student_count
               FROM school_classes c
               JOIN enrollments e ON e.class_id = c.id
               LEFT JOIN users u ON u.id = c.staff_id
               WHERE e.student_id = ? ORDER BY c.name, c.section""",
            (user["id"],),
        ).fetchall()
    else:
        classes = []

    class_ids = [item["id"] for item in classes]
    staff_members = conn.execute(
        """SELECT id, first_name, last_name FROM users
           WHERE role = 'staff' AND status = 'active' ORDER BY last_name, first_name"""
    ).fetchall() if role == "admin" else []
    students = conn.execute(
        """SELECT id, first_name, last_name FROM users
           WHERE role = 'student' AND status = 'active' ORDER BY last_name, first_name"""
    ).fetchall() if role in {"admin", "staff"} else []

    enrolled_students = []
    attendance_records = []
    grade_records = []
    schedules = []
    if class_ids:
        placeholders = ",".join("?" for _ in class_ids)
        enrolled_students = conn.execute(
            f"""SELECT e.class_id, u.id AS student_id, u.first_name, u.last_name
                FROM enrollments e JOIN users u ON u.id = e.student_id
                WHERE e.class_id IN ({placeholders}) AND u.status = 'active'
                ORDER BY u.last_name, u.first_name""",
            class_ids,
        ).fetchall()
        if role == "student":
            attendance_records = conn.execute(
                """SELECT a.attendance_date, a.status, c.name, c.section
                   FROM attendance a JOIN school_classes c ON c.id = a.class_id
                   WHERE a.student_id = ? ORDER BY a.attendance_date DESC, c.name""",
                (user["id"],),
            ).fetchall()
            grade_records = conn.execute(
                """SELECT g.assessment, g.score, g.max_score, g.created_at, c.name, c.section
                   FROM grades g JOIN school_classes c ON c.id = g.class_id
                   WHERE g.student_id = ? ORDER BY g.created_at DESC, g.id DESC""",
                (user["id"],),
            ).fetchall()
        else:
            attendance_records = conn.execute(
                f"""SELECT a.attendance_date, a.status, c.name, c.section,
                           u.first_name, u.last_name
                    FROM attendance a JOIN school_classes c ON c.id = a.class_id
                    JOIN users u ON u.id = a.student_id
                    WHERE a.class_id IN ({placeholders})
                    ORDER BY a.attendance_date DESC, c.name, u.last_name""",
                class_ids,
            ).fetchall()
            grade_records = conn.execute(
                f"""SELECT g.assessment, g.score, g.max_score, g.created_at, c.name, c.section,
                           u.first_name, u.last_name
                    FROM grades g JOIN school_classes c ON c.id = g.class_id
                    JOIN users u ON u.id = g.student_id
                    WHERE g.class_id IN ({placeholders})
                    ORDER BY g.created_at DESC, g.id DESC""",
                class_ids,
            ).fetchall()
        schedules = conn.execute(
            f"""SELECT s.weekday, s.start_time, s.end_time, s.room, c.name, c.section
                FROM class_schedules s JOIN school_classes c ON c.id = s.class_id
                WHERE s.class_id IN ({placeholders})
                ORDER BY CASE s.weekday WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2
                     WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5
                     WHEN 'Saturday' THEN 6 ELSE 7 END, s.start_time""",
            class_ids,
        ).fetchall()
    conn.close()

    return render_template(
        "academics.html",
        role=role,
        classes=classes,
        staff_members=staff_members,
        students=students,
        enrolled_students=enrolled_students,
        attendance_records=attendance_records,
        grade_records=grade_records,
        schedules=schedules,
        today=date.today().isoformat(),
    )


@app.route("/admin/announcements", methods=["GET", "POST"])
def announcements():
    """Let administrators and staff publish notices for the school community."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    current_user = conn.execute(
        "SELECT role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if current_user is None or current_user["role"] not in {"admin", "staff"}:
        conn.close()
        flash("Only school administrators and staff can manage announcements.", "error")
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


@app.route("/staff/students")
def staff_students():
    """Show school staff the active student roster."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    current_user = conn.execute(
        "SELECT role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if current_user is None or current_user["role"] not in {"admin", "staff"}:
        conn.close()
        flash("Only school staff can view the student roster.", "error")
        return redirect(url_for("dashboard"))

    students = conn.execute(
        """SELECT id, first_name, last_name, username
           FROM users WHERE role = 'student' AND status = 'active'
           ORDER BY last_name, first_name"""
    ).fetchall()
    conn.close()
    return render_template("staff_students.html", students=students, user_role=current_user["role"])


@app.route("/staff/students/<int:student_id>/edit", methods=["GET", "POST"])
def edit_student(student_id):
    """Allow school staff to update an active student's personal details."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    current_user = conn.execute(
        "SELECT role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if current_user is None or current_user["role"] not in {"admin", "staff"}:
        conn.close()
        flash("Only school staff can edit student details.", "error")
        return redirect(url_for("dashboard"))

    student = conn.execute(
        "SELECT * FROM users WHERE id = ? AND role = 'student' AND status = 'active'",
        (student_id,),
    ).fetchone()
    if student is None:
        conn.close()
        flash("That active student account could not be found.", "error")
        return redirect(url_for("staff_students"))

    if request.method == "GET":
        conn.close()
        return render_template("edit_student.html", student=student)

    data = account_form_data()
    error = validate_account_details(
        data, "unchanged-password", "unchanged-password"
    )
    if error:
        conn.close()
        flash(error, "error")
        return redirect(url_for("edit_student", student_id=student_id))

    try:
        conn.execute(
            """UPDATE users
               SET first_name = ?, last_name = ?, email = ?, username = ?, phone = ?,
                   address = ?, dob = ?, gender = ?
               WHERE id = ? AND role = 'student' AND status = 'active'""",
            (*data.values(), student_id),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        flash("That username or email is already registered.", "error")
        return redirect(url_for("edit_student", student_id=student_id))

    conn.close()
    flash("Student details updated.", "success")
    return redirect(url_for("staff_students"))


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


@app.route("/admin/accounts/<int:account_id>/delete", methods=["POST"])
def delete_account(account_id):
    """Allow administrators to permanently delete staff or student accounts."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    admin = conn.execute(
        "SELECT role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if admin is None or admin["role"] != "admin":
        conn.close()
        flash("Only administrators can delete accounts.", "error")
        return redirect(url_for("dashboard"))

    account = conn.execute(
        "SELECT id, role FROM users WHERE id = ?", (account_id,)
    ).fetchone()
    if account is None or account["role"] not in {"staff", "student"}:
        conn.close()
        flash("Only existing staff or student accounts can be deleted.", "error")
        return redirect(url_for("create_account"))

    conn.execute("BEGIN")
    conn.execute("DELETE FROM announcements WHERE author_id = ?", (account_id,))

    if account["role"] == "staff":
        class_ids = [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM school_classes WHERE staff_id = ?", (account_id,)
            )
        ]
        if class_ids:
            placeholders = ",".join("?" for _ in class_ids)
            conn.execute(
                f"DELETE FROM attendance WHERE class_id IN ({placeholders})",
                class_ids,
            )
            conn.execute(
                f"DELETE FROM grades WHERE class_id IN ({placeholders})",
                class_ids,
            )
            conn.execute(
                f"DELETE FROM enrollments WHERE class_id IN ({placeholders})",
                class_ids,
            )
            conn.execute(
                f"DELETE FROM class_schedules WHERE class_id IN ({placeholders})",
                class_ids,
            )
            conn.execute(
                f"DELETE FROM school_classes WHERE id IN ({placeholders})",
                class_ids,
            )
    else:
        conn.execute("DELETE FROM attendance WHERE student_id = ?", (account_id,))
        conn.execute("DELETE FROM grades WHERE student_id = ?", (account_id,))
        conn.execute("DELETE FROM enrollments WHERE student_id = ?", (account_id,))

    conn.execute("DELETE FROM users WHERE id = ?", (account_id,))
    conn.commit()
    conn.close()
    flash("Account and associated records deleted.", "success")
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


@app.route("/help")
def help_page():
    """Show the signed-in user how to use the portal for their role."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    user = conn.execute(
        "SELECT id, role, first_name FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    conn.close()

    if user is None:
        session.clear()
        return redirect(url_for("login_page"))

    return render_template("how_to_use.html", user=user)



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


@app.route("/profile/password", methods=["GET", "POST"])
def change_password():
    """Let a signed-in user replace their password and revoke old sessions."""
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db()
    user = conn.execute(
        "SELECT id, password FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if user is None:
        conn.close()
        session.clear()
        return redirect(url_for("login_page"))

    if request.method == "GET":
        conn.close()
        return render_template("change_password.html")

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not check_password_hash(user["password"], current_password):
        conn.close()
        flash("Current password is incorrect.", "error")
        return redirect(url_for("change_password"))
    if len(new_password) < 12:
        conn.close()
        flash("New password must be at least 12 characters long.", "error")
        return redirect(url_for("change_password"))
    if len(new_password) > 128:
        conn.close()
        flash("New password must be no more than 128 characters long.", "error")
        return redirect(url_for("change_password"))
    if new_password != confirm_password:
        conn.close()
        flash("New passwords do not match.", "error")
        return redirect(url_for("change_password"))
    if check_password_hash(user["password"], new_password):
        conn.close()
        flash("Choose a new password that is different from your current password.", "error")
        return redirect(url_for("change_password"))

    conn.execute(
        """UPDATE users
           SET password = ?, session_version = session_version + 1
           WHERE id = ?""",
        (generate_password_hash(new_password), user["id"]),
    )
    conn.commit()
    conn.close()
    session.clear()
    flash("Password changed. Please sign in again.", "success")
    return redirect(url_for("login_page"))



@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    return redirect(url_for("login_page"))

if __name__ == "__main__":

    init_db()

    app.run(debug=False)
