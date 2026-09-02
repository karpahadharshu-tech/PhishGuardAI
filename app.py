from flask import Flask, render_template, request
import joblib
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
import re

app = Flask(__name__)

DATABASE = "phishguard.db"
MODEL_FILE = "phishguard_model_v3.pkl"


# ==================================================
# LOAD MODEL
# ==================================================

try:
    model_data = joblib.load(MODEL_FILE)

    if isinstance(model_data, dict) and "model" in model_data:
        model = model_data["model"]
    else:
        model = model_data

    print("PhishGuard AI V3 Model Loaded Successfully!")

except Exception as e:
    print("Model loading error:", e)
    model = None


# ==================================================
# DATABASE
# ==================================================

def init_database():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            score INTEGER NOT NULL,
            scan_time TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ==================================================
# URL FEATURES
# ==================================================

def create_url_features(url):

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    full_url = url.lower()

    features = {}

    features["url_length"] = len(url)
    features["domain_length"] = len(domain)

    features["is_https"] = (
        1 if parsed.scheme == "https" else 0
    )

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    features["is_ip"] = (
        1
        if re.match(
            ip_pattern,
            domain.split(":")[0]
        )
        else 0
    )

    features["dots"] = url.count(".")
    features["hyphens"] = url.count("-")
    features["slashes"] = url.count("/")

    features["digits"] = sum(
        c.isdigit()
        for c in url
    )

    special_chars = "@?=&_%~#"

    features["special_chars"] = sum(
        c in special_chars
        for c in url
    )

    features["subdomains"] = max(
        0,
        len(domain.split(".")) - 2
    )

    features["has_at"] = (
        1 if "@" in url else 0
    )

    features["has_question"] = (
        1 if "?" in url else 0
    )

    features["has_equal"] = (
        1 if "=" in url else 0
    )

    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "security",
        "update",
        "confirm",
        "bank",
        "paypal",
        "payment",
        "wallet",
        "reset"
    ]

    features["suspicious_words"] = sum(
        word in full_url
        for word in suspicious_words
    )

    features["long_url"] = (
        1 if len(url) > 75 else 0
    )

    features["many_digits"] = (
        1 if features["digits"] > 8 else 0
    )

    features["many_hyphens"] = (
        1 if features["hyphens"] > 3 else 0
    )

    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ]

    features["suspicious_tld"] = int(
        any(
            full_url.endswith(tld)
            for tld in suspicious_tlds
        )
    )

    features["url_depth"] = path.count("/")

    return features


# ==================================================
# SAVE SCAN
# ==================================================

def save_scan(url, result, score):

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    scan_time = datetime.now().strftime(
        "%d-%m-%Y %I:%M %p"
    )

    cursor.execute("""
        INSERT INTO scan_history
        (url, result, score, scan_time)
        VALUES (?, ?, ?, ?)
    """, (
        url,
        result,
        score,
        scan_time
    ))

    conn.commit()
    conn.close()


# ==================================================
# GET HISTORY
# ==================================================

def get_scan_history():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT url, result, score, scan_time
        FROM scan_history
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()

    conn.close()

    history = []

    for row in rows:

        history.append({
            "url": row["url"],
            "result": row["result"],
            "score": row["score"],
            "time": row["scan_time"]
        })

    return history


# ==================================================
# STATISTICS
# ==================================================

def get_statistics():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM scan_history"
    )

    total_scans = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'SAFE'
    """)

    safe_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'SUSPICIOUS'
    """)

    suspicious_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'PHISHING'
    """)

    phishing_count = cursor.fetchone()[0]

    conn.close()

    return (
        total_scans,
        safe_count,
        suspicious_count,
        phishing_count
    )


# ==================================================
# SECURITY INDICATORS
# ==================================================

def get_security_indicators(url):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    full_url = url.lower()

    indicators = []

    # HTTPS
    if parsed.scheme == "https":

        indicators.append({
            "name": "HTTPS Security",
            "status": "PASS",
            "icon": "✓"
        })

    else:

        indicators.append({
            "name": "HTTPS Security",
            "status": "WARNING",
            "icon": "⚠"
        })

    # IP ADDRESS
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(
        ip_pattern,
        domain.split(":")[0]
    ):

        indicators.append({
            "name": "IP Address Check",
            "status": "WARNING",
            "icon": "⚠"
        })

    else:

        indicators.append({
            "name": "IP Address Check",
            "status": "PASS",
            "icon": "✓"
        })

    # SUSPICIOUS KEYWORDS
    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "secure",
        "security",
        "update",
        "confirm",
        "bank",
        "paypal",
        "payment",
        "wallet",
        "reset"
    ]

    found_words = [
        word
        for word in suspicious_words
        if word in full_url
    ]

    if found_words:

        indicators.append({
            "name": "Suspicious Keywords",
            "status": "DETECTED",
            "icon": "⚠"
        })

    else:

        indicators.append({
            "name": "Suspicious Keywords",
            "status": "PASS",
            "icon": "✓"
        })

    # URL LENGTH
    if len(url) > 75:

        indicators.append({
            "name": "URL Length",
            "status": "WARNING",
            "icon": "⚠"
        })

    else:

        indicators.append({
            "name": "URL Length",
            "status": "NORMAL",
            "icon": "✓"
        })

    # DIGITS
    digit_count = sum(
        c.isdigit()
        for c in url
    )

    if digit_count > 8:

        indicators.append({
            "name": "Digit Analysis",
            "status": "WARNING",
            "icon": "⚠"
        })

    else:

        indicators.append({
            "name": "Digit Analysis",
            "status": "NORMAL",
            "icon": "✓"
        })

    # SPECIAL CHARACTERS
    special_count = sum(
        c in "@?=&_%~#"
        for c in url
    )

    if special_count > 5:

        indicators.append({
            "name": "Special Characters",
            "status": "WARNING",
            "icon": "⚠"
        })

    else:

        indicators.append({
            "name": "Special Characters",
            "status": "NORMAL",
            "icon": "✓"
        })

    # SUBDOMAINS
    subdomain_count = max(
        0,
        len(domain.split(".")) - 2
    )

    if subdomain_count > 2:

        indicators.append({
            "name": "Domain Structure",
            "status": "WARNING",
            "icon": "⚠"
        })

    else:

        indicators.append({
            "name": "Domain Structure",
            "status": "PASS",
            "icon": "✓"
        })

    # MACHINE LEARNING
    indicators.append({
        "name": "Machine Learning",
        "status": "ANALYZED",
        "icon": "🤖"
    })

    return indicators


# ==================================================
# MAIN ROUTE
# ==================================================

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    score = 0
    reasons = []
    indicators = []
    user_input = ""

    if request.method == "POST":

        user_input = request.form.get(
            "message",
            ""
        ).strip()

        if user_input:

            # Add HTTPS if missing
            if not user_input.startswith(
                ("http://", "https://")
            ):

                user_input = (
                    "https://" + user_input
                )

            # FEATURES
            feature_dict = create_url_features(
                user_input
            )

            # ML PREDICTION
            ml_prediction = 0

            try:

                if model is not None:

                    feature_names = [
                        "url_length",
                        "domain_length",
                        "is_https",
                        "is_ip",
                        "dots",
                        "hyphens",
                        "slashes",
                        "digits",
                        "special_chars",
                        "subdomains",
                        "has_at",
                        "has_question",
                        "has_equal",
                        "suspicious_words",
                        "long_url",
                        "many_digits",
                        "many_hyphens",
                        "suspicious_tld",
                        "url_depth"
                    ]

                    feature_values = [
                        feature_dict[name]
                        for name in feature_names
                    ]

                    ml_prediction = int(
                        model.predict(
                            [feature_values]
                        )[0]
                    )

            except Exception as e:

                print(
                    "ML prediction error:",
                    e
                )

            # SECURITY INDICATORS
            indicators = get_security_indicators(
                user_input
            )

            # MANUAL ANALYSIS
            parsed = urlparse(user_input)

            domain = parsed.netloc.lower()
            full_url = user_input.lower()

            ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

            # HTTPS
            if parsed.scheme != "https":

                reasons.append(
                    "URL does not use HTTPS"
                )

            # IP
            if re.match(
                ip_pattern,
                domain.split(":")[0]
            ):

                reasons.append(
                    "URL uses an IP address instead of a domain name"
                )

            # SUSPICIOUS WORDS
            suspicious_words = [
                "login",
                "signin",
                "verify",
                "verification",
                "account",
                "password",
                "secure",
                "security",
                "update",
                "confirm",
                "bank",
                "paypal",
                "payment",
                "wallet",
                "reset"
            ]

            found_words = [
                word
                for word in suspicious_words
                if word in full_url
            ]

            if found_words:

                reasons.append(
                    "Suspicious keywords detected: "
                    + ", ".join(found_words)
                )

            # DIGITS
            digit_count = sum(
                c.isdigit()
                for c in user_input
            )

            if digit_count > 8:

                reasons.append(
                    "URL contains a high number of digits"
                )

            # HYPHENS
            if user_input.count("-") > 3:

                reasons.append(
                    "URL contains many hyphens"
                )

            # @
            if "@" in user_input:

                reasons.append(
                    "URL contains an @ symbol"
                )

            # LONG URL
            if len(user_input) > 75:

                reasons.append(
                    "URL is unusually long"
                )

            # ==================================================
            # RISK SCORE
            # ==================================================

            score = 0

            if parsed.scheme != "https":
                score += 20

            if re.match(
                ip_pattern,
                domain.split(":")[0]
            ):
                score += 20

            if found_words:
                score += 20

            if digit_count > 8:
                score += 10

            if user_input.count("-") > 3:
                score += 10

            if "@" in user_input:
                score += 15

            if len(user_input) > 75:
                score += 10

            # ML
            if ml_prediction == 1 and score >= 20:
                score += 30

            score = min(score, 100)

            # RESULT
            if score >= 70:

                result = "PHISHING"

            elif score >= 40:

                result = "SUSPICIOUS"

            else:

                result = "SAFE"

            # DEFAULT REASON
            if not reasons:

                if result == "SAFE":

                    reasons.append(
                        "No obvious suspicious URL characteristics detected"
                    )

                elif result == "SUSPICIOUS":

                    reasons.append(
                        "Machine learning model identified moderate phishing risk"
                    )

                else:

                    reasons.append(
                        "Machine learning model identified strong phishing risk"
                    )

            # SAVE
            save_scan(
                user_input,
                result,
                score
            )

    # DASHBOARD
    (
        total_scans,
        safe_count,
        suspicious_count,
        phishing_count
    ) = get_statistics()

    scan_history = get_scan_history()

    return render_template(
        "index.html",
        result=result,
        score=score,
        reasons=reasons,
        indicators=indicators,
        user_input=user_input,
        total_scans=total_scans,
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        phishing_count=phishing_count,
        scan_history=scan_history
    )


# ==================================================
# START
# ==================================================

if __name__ == "__main__":

    init_database()

    app.run(
        debug=True
    )