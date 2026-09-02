from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

import joblib
import sqlite3
import datetime
import re
import pandas as pd

from urllib.parse import urlparse
from functools import wraps

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# =========================================================
# APP CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = "phishguard-demo-secret-key-change-this"

MODEL_FILE = "phishguard_model_v3.pkl"
DATABASE_FILE = "phishguard.db"


# =========================================================
# LOAD ML MODEL
# =========================================================

model_data = joblib.load(MODEL_FILE)

model = model_data["model"]
FEATURE_NAMES = model_data["features"]

print("MODEL LOADED SUCCESSFULLY")
print("FEATURES:", FEATURE_NAMES)
print("MODEL CLASSES:", model.classes_)


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():

    connection = sqlite3.connect(DATABASE_FILE)

    connection.row_factory = sqlite3.Row

    return connection


# =========================================================
# INITIALIZE DATABASE
# =========================================================

def init_database():

    connection = get_db_connection()

    cursor = connection.cursor()

    # -----------------------------------------------------
    # USERS TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            role TEXT NOT NULL DEFAULT 'user'

        )
    """)

    # -----------------------------------------------------
    # SCAN HISTORY TABLE
    # -----------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            url TEXT NOT NULL,

            result TEXT NOT NULL,

            score INTEGER NOT NULL,

            scan_time TEXT NOT NULL

        )
    """)

    # -----------------------------------------------------
    # ADD user_id COLUMN IF IT DOES NOT EXIST
    # -----------------------------------------------------

    columns = cursor.execute(
        "PRAGMA table_info(scan_history)"
    ).fetchall()

    column_names = [
        column["name"]
        for column in columns
    ]

    if "user_id" not in column_names:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN user_id INTEGER
        """)

    # -----------------------------------------------------
    # CREATE DEFAULT ADMIN
    # -----------------------------------------------------

    admin = cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if admin is None:

        hashed_password = generate_password_hash(
            "admin123"
        )

        cursor.execute("""
            INSERT INTO users
            (username, password, role)
            VALUES (?, ?, ?)
        """, (
            "admin",
            hashed_password,
            "admin"
        ))

    connection.commit()

    connection.close()


# =========================================================
# LOGIN REQUIRED DECORATOR
# =========================================================

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please login to continue.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return decorated_function


# =========================================================
# ADMIN REQUIRED DECORATOR
# =========================================================

def admin_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        if session.get("role") != "admin":

            flash(
                "Admin access required.",
                "danger"
            )

            return redirect(
                url_for("home")
            )

        return function(*args, **kwargs)

    return decorated_function


# =========================================================
# URL FEATURE EXTRACTION
# =========================================================

def extract_features(url):

    url = str(url)

    features = {}

    # -----------------------------------------------------
    # URL LENGTH
    # -----------------------------------------------------

    features["url_length"] = len(url)

    # -----------------------------------------------------
    # DOMAIN
    # -----------------------------------------------------

    try:

        domain = url.split("//")[1].split("/")[0]

    except:

        domain = url.split("/")[0]

    # Remove port number if present

    domain = domain.split(":")[0]

    features["domain_length"] = len(domain)

    # -----------------------------------------------------
    # HTTPS
    # -----------------------------------------------------

    features["is_https"] = (
        1
        if url.lower().startswith("https://")
        else 0
    )

    # -----------------------------------------------------
    # IP ADDRESS
    # -----------------------------------------------------

    parts = domain.split(".")

    is_ip = 0

    if len(parts) == 4:

        if all(
            part.isdigit()
            for part in parts
        ):

            is_ip = 1

    features["is_domain_ip"] = is_ip

    # -----------------------------------------------------
    # SUBDOMAINS
    # -----------------------------------------------------

    features["subdomain_count"] = max(
        domain.count(".") - 1,
        0
    )

    # -----------------------------------------------------
    # SPECIAL CHARACTERS
    # -----------------------------------------------------

    features["question_mark"] = url.count("?")

    features["ampersand"] = url.count("&")

    features["equals"] = url.count("=")

    features["at_symbol"] = url.count("@")

    features["hyphen"] = url.count("-")

    features["dot"] = url.count(".")

    features["slash"] = url.count("/")

    # -----------------------------------------------------
    # LETTERS
    # -----------------------------------------------------

    letters = sum(
        character.isalpha()
        for character in url
    )

    features["letters"] = letters

    # -----------------------------------------------------
    # DIGITS
    # -----------------------------------------------------

    digits = sum(
        character.isdigit()
        for character in url
    )

    features["digits"] = digits

    # -----------------------------------------------------
    # RATIOS
    # -----------------------------------------------------

    length = max(
        len(url),
        1
    )

    features["letter_ratio"] = (
        letters / length
    )

    features["digit_ratio"] = (
        digits / length
    )

    # -----------------------------------------------------
    # OBFUSCATION
    # -----------------------------------------------------

    features["has_obfuscation"] = (
        1
        if (
            "@" in url
            or "%" in url
        )
        else 0
    )

    features["obfuscated_chars"] = (
        url.count("@")
        +
        url.count("%")
    )

    # -----------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -----------------------------------------------------

    suspicious_words = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "update",
        "confirm",
        "bank",
        "payment",
        "paypal",
        "crypto",
        "wallet",
        "recover",
        "reset"

    ]

    lower_url = url.lower()

    keyword_count = sum(
        word in lower_url
        for word in suspicious_words
    )

    features["suspicious_keyword_count"] = keyword_count

    # -----------------------------------------------------
    # RETURN FEATURES IN MODEL ORDER
    # -----------------------------------------------------

    return [
        features[name]
        for name in FEATURE_NAMES
    ]


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(
    url,
    result,
    score,
    user_id
):

    connection = get_db_connection()

    connection.execute("""
        INSERT INTO scan_history
        (
            url,
            result,
            score,
            scan_time,
            user_id
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        result,
        score,
        datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        user_id
    ))

    connection.commit()

    connection.close()


# =========================================================
# GET USER SCAN HISTORY
# =========================================================

def get_scan_history(user_id):

    connection = get_db_connection()

    history = connection.execute("""
        SELECT *
        FROM scan_history
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        user_id,
    )).fetchall()

    connection.close()

    return history


# =========================================================
# GET USER STATISTICS
# =========================================================

def get_statistics(user_id):

    connection = get_db_connection()

    total_scans = connection.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE user_id = ?
    """, (
        user_id,
    )).fetchone()[0]

    safe_urls = connection.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE user_id = ?
        AND result = 'SAFE'
    """, (
        user_id,
    )).fetchone()[0]

    suspicious_urls = connection.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE user_id = ?
        AND result = 'SUSPICIOUS'
    """, (
        user_id,
    )).fetchone()[0]

    high_risk_urls = connection.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE user_id = ?
        AND result = 'PHISHING'
    """, (
        user_id,
    )).fetchone()[0]

    connection.close()

    return {

        "total_scans": total_scans,

        "safe_urls": safe_urls,

        "suspicious_urls": suspicious_urls,

        "high_risk_urls": high_risk_urls

    }


# =========================================================
# SECURITY INDICATORS
# =========================================================

def get_security_indicators(url):

    parsed = urlparse(url)

    indicators = []

    # HTTPS

    if parsed.scheme.lower() == "https":

        indicators.append({

            "name": "HTTPS enabled",

            "status": "PASS"

        })

    else:

        indicators.append({

            "name": "HTTPS enabled",

            "status": "WARNING"

        })

    # IP ADDRESS

    hostname = parsed.hostname or ""

    if re.match(
        r"^\d{1,3}(\.\d{1,3}){3}$",
        hostname
    ):

        indicators.append({

            "name": "IP address detected",

            "status": "WARNING"

        })

    else:

        indicators.append({

            "name": "Domain name detected",

            "status": "PASS"

        })

    # SUSPICIOUS CHARACTERS

    if "@" in url:

        indicators.append({

            "name": "Suspicious @ symbol",

            "status": "WARNING"

        })

    else:

        indicators.append({

            "name": "No @ symbol",

            "status": "PASS"

        })

    # URL LENGTH

    if len(url) > 100:

        indicators.append({

            "name": "Long URL",

            "status": "WARNING"

        })

    else:

        indicators.append({

            "name": "URL length normal",

            "status": "PASS"

        })

    return indicators


# =========================================================
# ANALYSIS REASONS
# =========================================================

def get_analysis_reasons(url):

    reasons = []

    lower_url = url.lower()

    suspicious_words = [

        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "update",
        "confirm",
        "bank",
        "payment",
        "paypal",
        "crypto",
        "wallet",
        "recover",
        "reset"

    ]

    found_words = [

        word
        for word in suspicious_words
        if word in lower_url

    ]

    if found_words:

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_words)
        )

    if "@" in url:

        reasons.append(
            "URL contains an @ symbol."
        )

    if "%" in url:

        reasons.append(
            "URL contains encoded characters."
        )

    hostname = urlparse(url).hostname or ""

    if re.match(
        r"^\d{1,3}(\.\d{1,3}){3}$",
        hostname
    ):

        reasons.append(
            "The URL uses an IP address instead of a domain name."
        )

    if len(url) > 100:

        reasons.append(
            "The URL is unusually long."
        )

    if not reasons:

        reasons.append(
            "No major suspicious URL indicators were detected."
        )

    return reasons


# =========================================================
# HOME / DASHBOARD
# =========================================================

@app.route("/", methods=["GET", "POST"])
@login_required
def home():

    result = None

    score = None

    checked_url = ""

    indicators = []

    reasons = []

    user_id = session["user_id"]

    if request.method == "POST":

        checked_url = request.form.get(
            "url",
            ""
        ).strip()

        if not checked_url:

            flash(
                "Please enter a URL.",
                "warning"
            )

        else:

            try:

                # -------------------------------------------------
                # ADD SCHEME IF MISSING
                # -------------------------------------------------

                if not checked_url.lower().startswith(
                    ("http://", "https://")
                ):

                    checked_url = (
                        "https://"
                        + checked_url
                    )

                # -------------------------------------------------
                # EXTRACT FEATURES
                # -------------------------------------------------

                features = extract_features(
                    checked_url
                )

                # -------------------------------------------------
                # CREATE DATAFRAME
                # -------------------------------------------------

                X = pd.DataFrame(
                    [features],
                    columns=FEATURE_NAMES
                )

                # -------------------------------------------------
                # ML PREDICTION
                #
                # 0 = PHISHING
                # 1 = LEGITIMATE
                # -------------------------------------------------

                prediction = model.predict(X)[0]

                probabilities = model.predict_proba(X)[0]

                # -------------------------------------------------
                # DEBUG INFORMATION
                # -------------------------------------------------

                print("\n========================================")

                print(
                    "SCANNED URL:",
                    checked_url
                )

                print(
                    "FEATURE DATA:"
                )

                print(
                    X.to_string(index=False)
                )

                print(
                    "MODEL PREDICTION:",
                    prediction
                )

                print(
                    "MODEL PROBABILITIES:",
                    probabilities
                )

                print(
                    "MODEL CLASSES:",
                    model.classes_
                )

                print(
                    "========================================\n"
                )

                # -------------------------------------------------
                # CORRECT LABEL MAPPING
                #
                # 0 = PHISHING
                # 1 = LEGITIMATE
                # -------------------------------------------------

                if int(prediction) == 0:

                    result = "PHISHING"

                else:

                    result = "SAFE"

                # -------------------------------------------------
                # PHISHING SCORE
                # -------------------------------------------------

                class_0_index = list(
                    model.classes_
                ).index(0)

                score = int(
                    probabilities[
                        class_0_index
                    ] * 100
                )

                # -------------------------------------------------
                # SECURITY INDICATORS
                # -------------------------------------------------

                indicators = get_security_indicators(
                    checked_url
                )

                # -------------------------------------------------
                # ANALYSIS REASONS
                # -------------------------------------------------

                reasons = get_analysis_reasons(
                    checked_url
                )

                # -------------------------------------------------
                # SAVE SCAN
                # -------------------------------------------------

                save_scan(
                    checked_url,
                    result,
                    score,
                    user_id
                )

            except Exception as error:

                print(
                    "SCAN ERROR:",
                    error
                )

                flash(
                    f"Scan error: {error}",
                    "danger"
                )

    # -----------------------------------------------------
    # GET HISTORY
    # -----------------------------------------------------

    history = get_scan_history(
        user_id
    )

    # -----------------------------------------------------
    # GET STATISTICS
    # -----------------------------------------------------

    statistics = get_statistics(
        user_id
    )

    return render_template(

        "index.html",

        result=result,

        score=score,

        checked_url=checked_url,

        indicators=indicators,

        reasons=reasons,

        history=history,

        statistics=statistics

    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Username and password are required.",
                "warning"
            )

            return redirect(
                url_for("register")
            )

        connection = get_db_connection()

        existing_user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing_user:

            connection.close()

            flash(
                "Username already exists.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        hashed_password = generate_password_hash(
            password
        )

        connection.execute("""
            INSERT INTO users
            (username, password, role)
            VALUES (?, ?, ?)
        """, (
            username,
            hashed_password,
            "user"
        ))

        connection.commit()

        connection.close()

        flash(
            "Registration successful. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db_connection()

        user = connection.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (
            username,
        )).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]

            session["username"] = user["username"]

            session["role"] = user["role"]

            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("home")
            )

        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@admin_required
def admin():

    connection = get_db_connection()

    # -----------------------------------------------------
    # ALL REGISTERED USERS
    # -----------------------------------------------------

    users = connection.execute("""
        SELECT
            id,
            username,
            role
        FROM users
        ORDER BY id ASC
    """).fetchall()

    # -----------------------------------------------------
    # ALL SCAN HISTORY
    # -----------------------------------------------------

    scan_history = connection.execute("""
        SELECT
            scan_history.*,
            users.username
        FROM scan_history
        LEFT JOIN users
        ON scan_history.user_id = users.id
        ORDER BY scan_history.id DESC
    """).fetchall()

    # -----------------------------------------------------
    # ADMIN STATISTICS
    # -----------------------------------------------------

    total_scans = connection.execute("""
        SELECT COUNT(*)
        FROM scan_history
    """).fetchone()[0]

    safe_count = connection.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'SAFE'
    """).fetchone()[0]

    suspicious_count = connection.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'SUSPICIOUS'
    """).fetchone()[0]

    phishing_count = connection.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'PHISHING'
    """).fetchone()[0]

    connection.close()

    # -----------------------------------------------------
    # SEND DATA TO ADMIN TEMPLATE
    # -----------------------------------------------------

    return render_template(

        "admin.html",

        users=users,

        scan_history=scan_history,

        username=session.get("username"),

        total_scans=total_scans,

        safe_count=safe_count,

        suspicious_count=suspicious_count,

        phishing_count=phishing_count

    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    init_database()

    app.run(
        debug=True
    )