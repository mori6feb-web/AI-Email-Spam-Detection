from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from pathlib import Path
from datetime import datetime
import html
import json
import pickle
import re
import traceback

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "spam_model.pkl"
HISTORY_PATH = ROOT / "analysis_history.json"

with MODEL_PATH.open("rb") as f:
    MODEL = pickle.load(f)


def esc(value):
    return html.escape(str(value), quote=True)


def get_history():
    try:
        if HISTORY_PATH.exists():
            data = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        pass
    return []


def save_history(history):
    HISTORY_PATH.write_text(
        json.dumps(history[-100:], indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def predict_spam(message):
    prediction = MODEL.predict([message])[0]
    label = str(prediction).strip().lower()
    classes = list(getattr(MODEL, "classes_", []))

    spam_labels = ("spam", "1", "true", "yes")

    spam_index = next(
        (i for i, c in enumerate(classes)
         if str(c).strip().lower() in spam_labels),
        None
    )

    if hasattr(MODEL, "predict_proba") and spam_index is not None:
        probabilities = MODEL.predict_proba([message])[0]
        spam_probability = float(probabilities[spam_index])
    else:
        spam_probability = (
            0.75 if label in spam_labels else 0.20
        )

    is_spam = label in spam_labels

    return (
        is_spam,
        max(0.0, min(1.0, spam_probability)),
        label
    )


SUSPICIOUS_WORDS = [
    "urgent", "act now", "immediately",
    "verify your account", "account suspended",
    "account is suspended", "password", "bank details",
    "credit card", "otp", "one-time password",
    "click here", "claim your prize", "free prize",
    "winner", "won a prize", "confirm your identity",
    "reset your password", "limited time",
    "payment failed", "wire transfer", "gift card",
    "login", "log in"
]

PHISHING_WORDS = [
    "verify your account", "account suspended",
    "account is suspended", "account is locked",
    "account will be closed", "password", "bank details",
    "credit card", "otp", "one-time password",
    "confirm your identity", "reset your password",
    "payment failed", "login", "log in"
]

URGENCY_WORDS = [
    "urgent", "act now", "immediately", "right now",
    "within 24 hours", "final warning", "expires today",
    "limited time", "last chance", "do not delay",
    "account will be closed"
]

THREAT_WORDS = [
    "account suspended", "account is suspended",
    "account will be closed", "legal action",
    "final warning", "you will be blocked",
    "account is locked", "arrest"
]

POSITIVE_WORDS = [
    "thank you", "thanks", "great", "happy",
    "please", "appreciate"
]

NEGATIVE_WORDS = [
    "angry", "threat", "failed", "blocked",
    "suspended", "problem", "warning", "fraud"
]

URL_PATTERN = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"
)


def analyze_urls(message):
    urls = URL_PATTERN.findall(message)
    findings = []
    url_risk = 0

    shorteners = (
        "bit.ly", "tinyurl.com", "t.co",
        "goo.gl", "is.gd", "ow.ly"
    )

    for raw_url in urls:
        url = raw_url.rstrip(".,!?;:)]}")
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )
        host = (parsed.hostname or "").lower()
        flags = []

        if not host:
            flags.append("Could not read the link domain")

        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            flags.append(
                "Uses an IP address instead of a normal domain"
            )

        if "@" in url:
            flags.append(
                "Contains an @ symbol that may disguise the destination"
            )

        if host.startswith("xn--") or ".xn--" in host:
            flags.append("Contains a punycode domain")

        if host.count("-") >= 3:
            flags.append("Domain contains several hyphens")

        if len(host) > 45:
            flags.append("Unusually long domain name")

        if parsed.scheme.lower() != "https":
            flags.append("Does not use HTTPS")

        if any(
            host == domain or host.endswith("." + domain)
            for domain in shorteners
        ):
            flags.append(
                "Shortened URL hides the final destination"
            )

        if flags:
            url_risk += min(18, 6 + 3 * len(flags))
        else:
            flags.append(
                "No basic structural warning found; safety is not guaranteed"
            )

        findings.append({
            "url": url,
            "flags": flags
        })

    return urls, findings, min(30, url_risk)


def analyze_message(message, is_spam, spam_probability):
    lower = message.lower()

    suspicious = [
        word for word in SUSPICIOUS_WORDS if word in lower
    ]

    phishing_hits = [
        word for word in PHISHING_WORDS if word in lower
    ]

    urgency_hits = [
        word for word in URGENCY_WORDS if word in lower
    ]

    threat_hits = [
        word for word in THREAT_WORDS if word in lower
    ]

    urls, url_findings, url_risk = analyze_urls(message)

    has_credentials = any(
        word in lower for word in (
            "password", "otp", "one-time password",
            "bank details", "credit card"
        )
    )

    has_account_threat = any(
        word in lower for word in (
            "account suspended",
            "account is suspended",
            "account is locked",
            "account will be closed",
            "verify your account"
        )
    )

    has_urgency = bool(urgency_hits)

    has_ip_url = False

    for url in urls:
        parsed = urlparse(
            url if "://" in url else "http://" + url
        )
        host = (parsed.hostname or "").lower()

        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            has_ip_url = True
            break

    # Rule-based phishing indicator, separate from the ML model.
    phishing_score = min(
        100,
        len(phishing_hits) * 15
        + (25 if has_credentials else 0)
        + (25 if has_account_threat else 0)
        + (15 if has_urgency else 0)
        + (25 if has_ip_url else 0)
        + url_risk
    )

    # Strong combination: credentials + account threat + urgency/link.
    if (
        has_credentials
        and has_account_threat
        and (urls or has_urgency)
    ):
        phishing_score = max(phishing_score, 85)

    elif has_credentials and has_urgency and urls:
        phishing_score = max(phishing_score, 75)

    elif urls and not phishing_hits:
        phishing_score = min(
            45, max(phishing_score, url_risk + 10)
        )

    elif not phishing_hits and not urls and not has_credentials:
        phishing_score = 0

    risk_score = round(min(
        100,
        max(
            spam_probability * 65,
            phishing_score,
            spam_probability * 65
            + min(20, len(suspicious) * 5)
            + min(15, len(urgency_hits) * 5)
            + url_risk * 0.35
        )
    ))

    if risk_score < 30:
        risk_level = "Low"
    elif risk_score < 65:
        risk_level = "Medium"
    else:
        risk_level = "High"

    if threat_hits:
        sentiment = "Threatening / pressure language"
    elif urgency_hits:
        sentiment = "Urgent / pressuring language"
    elif any(word in lower for word in NEGATIVE_WORDS):
        sentiment = "Some negative or cautionary language"
    elif any(word in lower for word in POSITIVE_WORDS):
        sentiment = "Polite / positive language"
    else:
        sentiment = "Neutral or unclear tone"

    explanations = []

    if is_spam:
        explanations.append(
            "The trained model classified this message as spam."
        )
    else:
        explanations.append(
            "The trained model classified this message as likely legitimate."
        )

    if suspicious:
        explanations.append(
            "Warning phrases found: " + ", ".join(suspicious[:8])
        )

    if phishing_hits:
        explanations.append(
            "Credential or account-related wording found: "
            + ", ".join(phishing_hits[:6])
        )

    if urgency_hits:
        explanations.append(
            "Urgency phrases found: " + ", ".join(urgency_hits[:6])
        )

    if urls:
        explanations.append(
            f"Found {len(urls)} URL(s); basic structural checks were applied."
        )

    if phishing_score >= 60:
        explanations.append(
            "Combined wording and link indicators suggest high phishing risk, "
            "even if the spam model predicts legitimate."
        )

    if not suspicious and not phishing_hits and not urgency_hits and not urls:
        explanations.append(
            "No listed warning phrases were found. This does not guarantee safety."
        )

    recommendations = []

    if phishing_score >= 35 or url_risk >= 12:
        recommendations.append(
            "Avoid opening suspicious links. Verify the website independently."
        )

    if has_credentials:
        recommendations.append(
            "Never share passwords or OTPs through email or messages."
        )

    if urgency_hits or threat_hits:
        recommendations.append(
            "Do not act under pressure. Contact the organization using official contact details."
        )

    if is_spam or risk_level == "High" or phishing_score >= 60:
        recommendations.append(
            "Avoid replying, clicking links, or downloading attachments."
        )

    if not recommendations:
        recommendations.append(
            "Check the sender address and message context before trusting it."
        )

    recommendations.append(
        "This student demonstration cannot guarantee that a message or link is safe."
    )

    return {
        "suspicious": suspicious,
        "phishing_hits": phishing_hits,
        "urgency_hits": urgency_hits,
        "threat_hits": threat_hits,
        "urls": urls,
        "url_findings": url_findings,
        "url_risk": url_risk,
        "phishing_score": phishing_score,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "sentiment": sentiment,
        "explanations": explanations,
        "recommendations": recommendations
    }


def highlight_message(message, words):
    result = esc(message)

    for word in sorted(words, key=len, reverse=True):
        pattern = re.compile(re.escape(esc(word)), re.IGNORECASE)

        result = pattern.sub(
            lambda match:
                '<span class="highlight">' + match.group(0) + '</span>',
            result
        )

    return result.replace("\n", "<br>")


def page(body=""):
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Email Security Dashboard</title>
<style>
*{box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#f3f6fb;color:#172033;margin:0}
.wrap{max-width:1100px;margin:24px auto;padding:16px}
.hero{background:linear-gradient(120deg,#14213d,#244b88);color:white;padding:28px;border-radius:18px}
.hero h1{margin-top:0}
nav{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}
nav a{color:white;text-decoration:none;border:1px solid #ffffff66;padding:9px 12px;border-radius:8px}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:16px;margin-top:16px}
.card{background:white;padding:20px;border-radius:14px;box-shadow:0 4px 18px #152c5510;min-width:0}
.s12{grid-column:span 12}
.s6{grid-column:span 6}
.s4{grid-column:span 4}
h2{margin-top:0}
textarea{width:100%;min-height:160px;padding:13px;border:1px solid #cbd5e1;border-radius:9px;font-size:16px}
button,.button{display:inline-block;background:#315be8;color:white;border:0;padding:12px 17px;border-radius:8px;font-size:15px;font-weight:bold;cursor:pointer;text-decoration:none;margin:4px 5px 4px 0}
.muted{color:#64748b;font-size:13px;line-height:1.5}
.result{padding:16px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;overflow-wrap:anywhere}
.spam{color:#b42318;font-weight:bold}
.ham{color:#087443;font-weight:bold}
.stat{font-size:29px;font-weight:bold;margin:9px 0}
.pill{display:inline-block;padding:6px 10px;border-radius:999px;font-size:13px;font-weight:bold}
.low{background:#dcfce7;color:#166534}
.medium{background:#fef3c7;color:#92400e}
.high{background:#fee2e2;color:#991b1b}
.meter,.bar{height:12px;background:#e5e7eb;border-radius:99px;overflow:hidden;margin:10px 0}
.meter span,.bar span{display:block;height:100%;background:#315be8}
.highlight{background:#fff0b3;color:#7c4a03;font-weight:bold;padding:2px 4px;border-radius:4px}
ul{padding-left:22px;line-height:1.65;overflow-wrap:anywhere}
.urlbox{background:#f8fafc;border:1px solid #e2e8f0;padding:10px;border-radius:8px;margin:8px 0;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 8px;text-align:left;border-bottom:1px solid #e2e8f0;font-size:14px;overflow-wrap:anywhere}
footer{color:#64748b;font-size:13px;padding:20px 4px}
@media(max-width:700px){.s6,.s4{grid-column:span 12}.wrap{margin:8px auto;padding:10px}}
</style>
</head>
<body>
<div class="wrap">
<div class="hero">
<h1>AI Email Security Dashboard</h1>
<p>Spam detection | Phishing indicators | Explainable results | Safety advice</p>
<nav>
<a href="/">Analyze Message</a>
<a href="/dashboard">Analytics Dashboard</a>
</nav>
</div>
""" + body + """
<footer>
Student demonstration project. Automated checks may be wrong;
no result guarantees that an email or link is safe.
</footer>
</div>
</body>
</html>"""


def dashboard():
    history = get_history()
    total = len(history)

    spam_count = sum(1 for item in history if item.get("spam"))
    legitimate = total - spam_count

    high_count = sum(
        1 for item in history if item.get("risk_level") == "High"
    )

    phishing_count = sum(
        1 for item in history if item.get("phishing_score", 0) >= 35
    )

    average_risk = (
        round(sum(item.get("risk_score", 0) for item in history) / total)
        if total else 0
    )

    spam_width = round(spam_count * 100 / total) if total else 0
    ham_width = 100 - spam_width if total else 0

    rows = ""

    for item in reversed(history[-10:]):
        verdict = (
            '<span class="spam">Spam</span>'
            if item.get("spam")
            else '<span class="ham">Legitimate</span>'
        )

        level = item.get("risk_level", "Unknown")
        css = level.lower() if level.lower() in (
            "low", "medium", "high"
        ) else "medium"

        rows += (
            "<tr><td>" + esc(item.get("time", "")) + "</td>"
            "<td>" + esc(item.get("preview", "")) + "</td>"
            "<td>" + verdict + "</td>"
            "<td>" + esc(item.get("spam_probability", 0)) + "%</td>"
            '<td><span class="pill ' + css + '">'
            + esc(level) + " (" + esc(item.get("risk_score", 0))
            + "/100)</span></td></tr>"
        )

    if not rows:
        rows = (
            '<tr><td colspan="5">'
            'No analysis history yet. Analyze a message first.'
            '</td></tr>'
        )

    body = f"""
<div class="grid">
<div class="card s4">
<div class="muted">Total messages analyzed</div>
<div class="stat">{total}</div>
</div>

<div class="card s4">
<div class="muted">Spam predictions</div>
<div class="stat">{spam_count}</div>
</div>

<div class="card s4">
<div class="muted">High-risk messages</div>
<div class="stat">{high_count}</div>
</div>

<div class="card s6">
<h2>Spam vs. Legitimate</h2>
<p>Spam — {spam_count}</p>
<div class="bar"><span style="width:{spam_width}%"></span></div>
<p>Legitimate — {legitimate}</p>
<div class="bar"><span style="width:{ham_width}%"></span></div>
<p class="muted">Based on saved analyses, not the training dataset.</p>
</div>

<div class="card s6">
<h2>Security Overview</h2>
<p><b>Messages with phishing indicators:</b> {phishing_count}</p>
<p><b>Average risk score:</b> {average_risk}/100</p>
<p class="muted">Rule-based indicators, not confirmed fraud findings.</p>
</div>

<div class="card s12">
<h2>Recent Analysis History</h2>
<div style="overflow-x:auto">
<table>
<thead>
<tr>
<th>Time</th>
<th>Message preview</th>
<th>Prediction</th>
<th>Spam probability</th>
<th>Risk score</th>
</tr>
</thead>
<tbody>{rows}</tbody>
</table>
</div>
<p class="muted">
History is saved locally in analysis_history.json. The last 100 records are kept.
</p>
</div>
</div>
"""

    return page(body)


class Handler(BaseHTTPRequestHandler):

    def send_html(self, content, status=200):
        data = content.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/dashboard":
            self.send_html(dashboard())
            return

        body = """
<div class="grid">
<div class="card s12">
<h2>Check an Email or Message</h2>
<form method="post" action="/analyze">
<label for="message"><b>Paste your message below:</b></label>
<br><br>
<textarea id="message" name="message" maxlength="10000"
placeholder="Example: Your account is suspended. Verify your password now."
required></textarea>
<br><br>
<button type="submit">Analyze Email Security</button>
</form>
<p class="muted">
Checks the trained model plus rule-based phishing, URL, urgency and risk indicators.
</p>
</div>

<div class="card s4">
<h3>Explainable AI</h3>
<p>Highlights warning phrases and displays explanations.</p>
</div>

<div class="card s4">
<h3>Phishing Detection</h3>
<p>Flags credential-related language and basic URL warning signs.</p>
</div>

<div class="card s4">
<h3>Risk & Analytics</h3>
<p>Displays Low/Medium/High risk and local analysis history.</p>
</div>
</div>
"""
        self.send_html(page(body))

    def do_POST(self):
        try:
            size = min(
                int(self.headers.get("Content-Length", "0")),
                20000
            )

            raw = self.rfile.read(size).decode(
                "utf-8", errors="replace"
            )

            form = parse_qs(raw)
            message = form.get("message", [""])[0][:10000]

            if not message.strip():
                self.send_html(
                    page(
                        '<div class="card"><h2>Please enter a message.</h2>'
                        '<a href="/">Go back</a></div>'
                    ),
                    400
                )
                return

            is_spam, spam_probability, model_label = predict_spam(message)

            data = analyze_message(
                message, is_spam, spam_probability
            )

            if data["phishing_score"] >= 60:
                verdict = (
                    '<span class="spam">WARNING: HIGH PHISHING RISK</span>'
                )
            elif is_spam:
                verdict = (
                    '<span class="spam">WARNING: SPAM MESSAGE</span>'
                )
            else:
                verdict = (
                    '<span class="ham">'
                    'LIKELY LEGITIMATE (HAM) — CHECK OTHER RISK INDICATORS'
                    '</span>'
                )

            suspicious_html = (
                " ".join(
                    '<span class="highlight">' + esc(word) + '</span>'
                    for word in data["suspicious"]
                )
                if data["suspicious"]
                else '<span class="muted">No listed warning phrases found.</span>'
            )

            explanations_html = "".join(
                "<li>" + esc(item) + "</li>"
                for item in data["explanations"]
            )

            advice_html = "".join(
                "<li>" + esc(item) + "</li>"
                for item in data["recommendations"]
            )

            if data["url_findings"]:
                url_html = ""

                for item in data["url_findings"]:
                    url_html += (
                        '<div class="urlbox"><b>'
                        + esc(item["url"])
                        + '</b><ul>'
                        + "".join(
                            "<li>" + esc(flag) + "</li>"
                            for flag in item["flags"]
                        )
                        + "</ul></div>"
                    )
            else:
                url_html = (
                    '<p class="muted">No URLs found in this message.</p>'
                )

            phishing_level = (
                "High" if data["phishing_score"] >= 60
                else "Medium" if data["phishing_score"] >= 25
                else "Low"
            )

            urgency = (
                ", ".join(
                    data["urgency_hits"] + data["threat_hits"]
                )
                or "No listed urgency/threat phrases found"
            )

            result = f"""
<div class="grid">

<div class="card s12">
<h2>Prediction Result</h2>
<div class="result">
<h3>{verdict}</h3>
<p><b>ML estimated spam probability:</b>
{spam_probability * 100:.1f}%</p>
<p><b>Message analyzed:</b><br>
{highlight_message(message, data['suspicious'])}</p>
</div>
</div>

<div class="card s4">
<div class="muted">Intelligent Email Risk Score</div>
<div class="stat">{data['risk_score']}/100</div>
<span class="pill {data['risk_level'].lower()}">
{data['risk_level']} Risk</span>
<div class="meter">
<span style="width:{data['risk_score']}%"></span>
</div>
<p class="muted">
Demonstration score combining model and rule-based signals;
not a calibrated probability.
</p>
</div>

<div class="card s4">
<div class="muted">Phishing Risk Indicator</div>
<div class="stat">{data['phishing_score']}/100</div>
<span class="pill {phishing_level.lower()}">
{phishing_level} Indicator</span>
<p class="muted">Based on wording and basic URL checks.</p>
</div>

<div class="card s4">
<div class="muted">Sentiment & Urgency Analysis</div>
<h3>{esc(data['sentiment'])}</h3>
<p><b>Urgency/threat phrases:</b> {esc(urgency)}</p>
</div>

<div class="card s6">
<h2>Explainable AI: Why this result?</h2>
<ul>{explanations_html}</ul>
<h3>Suspicious Words and Phrases</h3>
<div>{suspicious_html}</div>
</div>

<div class="card s6">
<h2>Suspicious URL Analysis</h2>
{url_html}
</div>

<div class="card s12">
<h2>Smart Email Safety Assistant</h2>
<ul>{advice_html}</ul>
</div>

<div class="card s12">
<a class="button" href="/">Analyze Another Message</a>
<a class="button" href="/dashboard">Open Analytics Dashboard</a>
<p class="muted">
ML model label: {esc(model_label)}. Student demonstration only.
A message or URL that passes these checks may still be malicious.
</p>
</div>

</div>
"""

            history = get_history()

            history.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "preview": re.sub(r"\s+", " ", message)[:100],
                "spam": bool(is_spam),
                "spam_probability": round(spam_probability * 100, 1),
                "risk_score": data["risk_score"],
                "risk_level": data["risk_level"],
                "phishing_score": data["phishing_score"]
            })

            save_history(history)
            self.send_html(page(result))

        except Exception as error:
            traceback.print_exc()

            self.send_html(
                page(
                    '<div class="card"><h2>Prediction Error</h2>'
                    '<p>The message could not be analyzed.</p>'
                    '<p><b>Details:</b> ' + esc(error) + '</p>'
                    '<p><a href="/">Go back</a></p></div>'
                ),
                500
            )

    def log_message(self, format, *args):
        print(
            "%s - %s" %
            (self.address_string(), format % args)
        )


if __name__ == "__main__":
    try:
        server = HTTPServer(("127.0.0.1", 8000), Handler)

        print(
            "AI Email Security Dashboard running at "
            "http://127.0.0.1:8000"
        )
        print(
            "Analytics Dashboard: "
            "http://127.0.0.1:8000/dashboard"
        )
        print("Press Ctrl+C to stop the server.")

        server.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped.")

    except Exception:
        traceback.print_exc()

    finally:
        try:
            server.server_close()
        except NameError:
            pass