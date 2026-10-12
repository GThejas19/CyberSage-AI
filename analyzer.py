import re
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import joblib


MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.joblib"

try:
    phishing_model = joblib.load(MODEL_PATH)
    print("CyberSage ML model loaded successfully.")
except Exception as error:
    phishing_model = None
    print(f"ML model could not be loaded: {error}")


def normalize_prediction(value):
    """Normalize common model labels."""
    label = str(value).strip().lower()

    if label in {
        "phishing", "phish", "malicious", "malware",
        "fraudulent", "suspicious", "1"
    }:
        return "phishing"

    if label in {
        "legitimate", "legit", "benign", "safe", "ham", "0"
    }:
        return "legitimate"

    return label


def analyze_input(text):
    """Analyze a URL or message using rules and the trained ML model."""

    if not isinstance(text, str) or not text.strip():
        return {
            "risk": "Unknown",
            "score": 0,
            "prediction": "Unavailable",
            "confidence": None,
            "findings": ["Please enter a URL or message."]
        }

    text = text.strip()
    lower_text = text.lower()
    findings = []
    score = 0

    def add_finding(points, message):
        nonlocal score
        score += points
        if message not in findings:
            findings.append(message)

    # --------------------------------------------------
    # 1. URL checks
    # --------------------------------------------------
    url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
    urls = re.findall(url_pattern, text, re.IGNORECASE)

    shorteners = {
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly", "ow.ly", "rb.gy"
    }

    suspicious_host_terms = {
        "verify", "login", "signin", "account",
        "update", "secure", "confirm", "wallet"
    }

    for raw_url in urls[:10]:
        url = raw_url.rstrip(".,!?;:)]}")

        if url.lower().startswith("www."):
            url = "http://" + url

        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()

            if not hostname:
                add_finding(
                    10,
                    "The URL has no recognizable hostname."
                )
                continue

            # Insecure connection: a warning, not proof of phishing.
            if parsed.scheme.lower() == "http":
                add_finding(
                    10,
                    "The URL uses HTTP instead of HTTPS."
                )

            # User information before @ can disguise the destination.
            if "@" in parsed.netloc:
                add_finding(
                    25,
                    "The URL contains an @ symbol in its authority section."
                )

            # IP address used as the hostname.
            try:
                ipaddress.ip_address(hostname)
                add_finding(
                    25,
                    "The URL uses an IP-address hostname."
                )
            except ValueError:
                pass

            # Internationalized domain labels can imitate other domains.
            if "xn--" in hostname:
                add_finding(
                    15,
                    "The hostname contains an internationalized domain label."
                )

            if len(url) > 100:
                add_finding(
                    10,
                    "The URL is unusually long."
                )

            if hostname.count(".") >= 4:
                add_finding(
                    10,
                    "The hostname contains many subdomain levels."
                )

            if hostname in shorteners:
                add_finding(
                    10,
                    "The URL uses a shortener that hides the final destination."
                )

            # These words can be legitimate too, so add only a small warning.
            host_labels = set(re.split(r"[.\-_]", hostname))
            if host_labels.intersection(suspicious_host_terms):
                add_finding(
                    5,
                    "The hostname contains login or account-related wording."
                )

        except (ValueError, UnicodeError):
            add_finding(
                10,
                "The URL could not be parsed normally."
            )

    # --------------------------------------------------
    # 2. Social-engineering and sensitive-information checks
    # --------------------------------------------------
    warning_phrases = [
        "verify your account",
        "urgent action",
        "account suspended",
        "claim your prize",
        "click immediately",
        "confirm your bank details",
        "your account will be blocked",
        "account will be closed",
        "unusual activity detected",
        "act now",
        "limited time offer",
    ]

    for phrase in warning_phrases:
        if phrase in lower_text:
            add_finding(
                10,
                f"Potential social-engineering phrase detected: {phrase}."
            )

    sensitive_requests = [
        "send your password",
        "share your otp",
        "enter your otp",
        "provide your otp",
        "confirm your password",
        "provide your card details",
        "share your banking details",
        "send your password",
        "enter your card number",
    ]

    for phrase in sensitive_requests:
        if phrase in lower_text:
            add_finding(
                25,
                f"Potential request for sensitive information: {phrase}."
            )

    # --------------------------------------------------
    # 3. Keep the rule score between 0 and 100
    # --------------------------------------------------
    rule_score = min(score, 100)

    # --------------------------------------------------
    # 4. Machine-learning prediction
    # --------------------------------------------------
    prediction = "Unavailable"
    confidence = None

    if phishing_model is not None:
        try:
            predicted_class = phishing_model.predict([text])[0]
            prediction = normalize_prediction(predicted_class)

            if (
                hasattr(phishing_model, "predict_proba")
                and hasattr(phishing_model, "classes_")
            ):
                probabilities = phishing_model.predict_proba([text])[0]
                classes = list(phishing_model.classes_)

                predicted_index = next(
                    (
                        i for i, model_class in enumerate(classes)
                        if str(model_class).strip().lower()
                        == str(predicted_class).strip().lower()
                    ),
                    None
                )

                if (
                    predicted_index is not None
                    and predicted_index < len(probabilities)
                ):
                    confidence = round(
                        float(probabilities[predicted_index]) * 100, 1
                    )

            if prediction == "phishing":
                findings.append(
                    "Machine-learning model flagged this input as phishing."
                )
            elif prediction == "legitimate":
                findings.append(
                    "Machine-learning model classified this input as legitimate."
                )
            else:
                findings.append(
                    f"Unrecognized ML class label: {prediction}. "
                    "Check the model's training-label mapping."
                )

            if confidence is not None:
                findings.append(
                    f"Model confidence estimate: {confidence:.1f}% "
                    "(not a guarantee of safety or maliciousness)."
                )

        except Exception as error:
            prediction = "Error"
            confidence = None
            print(f"CyberSage prediction error: {error}")
            findings.append(
                "ML prediction failed; the rule-based result is still available."
            )
    else:
        findings.append(
            "ML model unavailable; only rule-based checks were performed."
        )

    # --------------------------------------------------
    # 5. Combine rule-based and ML results
    # --------------------------------------------------
    score = rule_score

    if prediction == "phishing":
        score = max(score, 60)
        findings.append(
            "The ML phishing classification raises the combined risk score. "
            "This score is heuristic, not a probability."
        )

    score = min(score, 100)

    # Risk thresholds
    if score >= 50:
        risk = "High"
    elif score >= 20:
        risk = "Medium"
    else:
        risk = "Low"

    # Explain when no rule-based indicators were found.
    rule_indicators = (
        "The URL uses HTTP",
        "The URL contains an @",
        "The URL uses an IP-address",
        "The hostname contains",
        "The URL is unusually long",
        "The URL could not be parsed",
        "The URL has no recognizable hostname",
        "Potential social-engineering phrase detected",
        "Potential request for sensitive information",
        "The URL uses a shortener",
    )

    if not any(
        finding.startswith(rule_indicators)
        for finding in findings
    ):
        findings.insert(
            0,
            "No configured rule-based warning indicators were found. "
            "This does not establish that the input is safe."
        )

    return {
        "risk": risk,
        "score": score,
        "prediction": prediction,
        "confidence": confidence,
        "findings": findings
    }