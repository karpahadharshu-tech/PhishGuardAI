
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


print("Loading dataset...")

df = pd.read_csv("phishing_dataset.csv")

print("Dataset loaded!")
print("Rows:", len(df))


# --------------------------------------------------
# Create reliable URL-based features
# --------------------------------------------------

def create_url_features(url):

    url = str(url)

    features = {}

    # URL length
    features["url_length"] = len(url)

    # Domain
    try:
        domain = url.split("//")[1].split("/")[0]
    except:
        domain = url.split("/")[0]

    features["domain_length"] = len(domain)

    # HTTPS
    features["is_https"] = (
        1 if url.lower().startswith("https://") else 0
    )

    # IP address
    parts = domain.split(".")

    is_ip = 0

    if len(parts) == 4:
        if all(part.isdigit() for part in parts):
            is_ip = 1

    features["is_domain_ip"] = is_ip

    # Subdomains
    features["subdomain_count"] = max(
        domain.count(".") - 1,
        0
    )

    # Special characters
    features["question_mark"] = url.count("?")
    features["ampersand"] = url.count("&")
    features["equals"] = url.count("=")
    features["at_symbol"] = url.count("@")
    features["hyphen"] = url.count("-")
    features["dot"] = url.count(".")
    features["slash"] = url.count("/")

    # Letters
    letters = sum(c.isalpha() for c in url)

    # Digits
    digits = sum(c.isdigit() for c in url)

    features["letters"] = letters
    features["digits"] = digits

    # Ratios
    length = max(len(url), 1)

    features["letter_ratio"] = letters / length
    features["digit_ratio"] = digits / length

    # Obfuscation indicators
    features["has_obfuscation"] = (
        1 if ("@" in url or "%" in url) else 0
    )

    features["obfuscated_chars"] = (
        url.count("@") + url.count("%")
    )

    # Suspicious keywords
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

    return features


# --------------------------------------------------
# Create training data
# --------------------------------------------------

print("\nCreating URL features...")

feature_rows = []

for url in df["URL"]:
    feature_rows.append(
        create_url_features(url)
    )

X = pd.DataFrame(feature_rows)

y = df["label"]


print("Features created:", X.shape[1])


# --------------------------------------------------
# Label mapping
#
# Dataset:
# 0 = PHISHING
# 1 = LEGITIMATE
# --------------------------------------------------

print("\nLabel distribution:")
print(y.value_counts())


# --------------------------------------------------
# Train/Test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# Random Forest
# --------------------------------------------------

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


print("\nTraining PhishGuard AI V3 model...")


model.fit(
    X_train,
    y_train
)


# --------------------------------------------------
# Evaluation
# --------------------------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)


print("\n--------------------------------")
print(
    f"Model Accuracy: {accuracy * 100:.2f}%"
)
print("--------------------------------")


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions
    )
)


# --------------------------------------------------
# Save model
# --------------------------------------------------

joblib.dump(
    {
        "model": model,
        "features": list(X.columns)
    },
    "phishguard_model_v3.pkl"
)


print("\nV3 Model saved successfully!")
print(
    "File: phishguard_model_v3.pkl"
)

