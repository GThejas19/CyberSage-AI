
import csv
import io
import os
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    render_template,
    render_template_string,
    send_file,
    abort,
    redirect,
    url_for,
    flash,
    session,
)
from flask_wtf.csrf import CSRFProtect

from analyzer import analyze_input
from auth_db import (
    initialize_auth_database,
    create_user,
    get_user_by_email,
    verify_password,
)
from database import (
    initialize_database,
    save_scan,
    get_recent_scans,
    get_scan,
    get_dashboard_stats,
)

# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    "local-development-only-change-this-secret",
)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("FLASK_HTTPS", "").lower() == "true"
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

csrf = CSRFProtect(app)

initialize_database()
initialize_auth_database()


# --------------------------------------------------
# AUTHENTICATION DECORATOR
# --------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access CyberSage AI.")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


# --------------------------------------------------
# DASHBOARD HTML
# --------------------------------------------------

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>CyberSage AI | Security Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
:root {
    --bg: #080d19;
    --surface: #101827;
    --border: #253349;
    --text: #edf4ff;
    --muted: #94a3b8;
    --cyan: #38bdf8;
    --green: #4ade80;
    --yellow: #fbbf24;
    --red: #fb7185;
}

* { box-sizing: border-box; }

html { scroll-behavior: smooth; }

body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: "Segoe UI", Arial, sans-serif;
}

a { color: #7dd3fc; }

.layout {
    display: flex;
    min-height: 100vh;
}

.sidebar {
    width: 225px;
    flex-shrink: 0;
    padding: 24px 16px;
    background: #0c1321;
    border-right: 1px solid var(--border);
}

.brand {
    display: flex;
    gap: 12px;
    align-items: center;
    margin-bottom: 28px;
}

.brand-icon {
    background: #075985;
    padding: 12px;
    border-radius: 12px;
    font-size: 22px;
    font-weight: bold;
}

.brand h1 { font-size: 19px; margin: 0; }

.brand small {
    color: var(--muted);
    font-size: 10px;
    letter-spacing: 1px;
}

.nav-label {
    color: #64748b;
    font-size: 10px;
    margin: 20px 8px;
}

.nav-link {
    display: block;
    padding: 12px;
    margin: 4px 0;
    border-radius: 8px;
    color: #aab8cc;
    text-decoration: none;
    font-size: 13px;
}

.nav-link:hover, .nav-link.active {
    background: #12283a;
    color: #7dd3fc;
}

.sidebar-note, .notice {
    padding: 13px;
    border: 1px solid var(--border);
    border-radius: 9px;
    color: var(--muted);
    font-size: 12px;
    line-height: 1.7;
}

.sidebar-note { margin-top: 28px; }

.main {
    flex: 1;
    min-width: 0;
    padding: 26px clamp(14px, 3vw, 38px);
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
}

h2 { font-size: 21px; }

.muted, .stat-foot {
    color: var(--muted);
    font-size: 12px;
    line-height: 1.7;
}

.status, .tag {
    font-size: 11px;
    padding: 8px 10px;
    border-radius: 20px;
    border: 1px solid #24543f;
    color: #86efac;
    background: #10251e;
}

.welcome { padding: 24px 0 12px; }

.welcome h1 {
    font-size: clamp(25px, 3vw, 34px);
    margin-bottom: 8px;
}

.welcome h1 span { color: var(--cyan); }

.stats {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 13px;
    margin: 16px 0 22px;
}

.stat, .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 13px;
}

.stat { padding: 17px; min-width: 0; }

.stat-label {
    color: var(--muted);
    font-size: 12px;
}

.stat-value {
    font-size: 28px;
    font-weight: 800;
    margin: 12px 0 7px;
    overflow-wrap: anywhere;
}

.panel {
    padding: 22px;
    margin-bottom: 20px;
    scroll-margin-top: 15px;
}

.panel-heading {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 20px;
}

.panel-heading h2 {
    font-size: 17px;
    margin: 0 0 7px;
}

.panel-heading p {
    font-size: 12px;
    color: var(--muted);
    margin: 0;
    line-height: 1.6;
}

.chart-grid, .result-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 15px;
}

.chart-card, .result-card, .recent-item, .about-item {
    background: #0b1322;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 17px;
    min-width: 0;
    overflow-wrap: anywhere;
}

.chart-card h3, .result-card h3, .about-item h3 {
    font-size: 13px;
}

.chart-wrap {
    height: 230px;
    position: relative;
}

label {
    display: block;
    font-size: 13px;
    font-weight: 700;
    margin-bottom: 10px;
}

textarea {
    width: 100%;
    min-height: 140px;
    padding: 14px;
    color: var(--text);
    background: #080f1d;
    border: 1px solid #34445d;
    border-radius: 9px;
    font: inherit;
    font-size: 13px;
    line-height: 1.7;
    resize: vertical;
}

textarea:focus {
    outline: 2px solid var(--cyan);
}

.input-meta, .recent-item small {
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
    color: var(--muted);
    font-size: 11px;
    margin-top: 8px;
}

.actions {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 16px;
}

.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 11px 15px;
    border: 0;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 700;
    text-decoration: none;
    cursor: pointer;
}

.primary { background: #0284c7; color: white; }

.secondary {
    background: #182438;
    color: #cbd5e1;
    border: 1px solid #334155;
}

.btn:disabled {
    opacity: .65;
    cursor: wait;
}

.notice {
    margin-top: 17px;
    background: #1e293b70;
}

.score-number {
    font-size: 35px;
    font-weight: 800;
}

.progress {
    height: 7px;
    background: #263449;
    border-radius: 8px;
    overflow: hidden;
    margin: 12px 0;
}

.progress-fill {
    height: 100%;
    background: var(--cyan);
    transition: width 1s;
}

.risk-badge {
    display: inline-block;
    padding: 7px 10px;
    border-radius: 7px;
    font-size: 11px;
    font-weight: 800;
}

.high { color: var(--red); background: #f43f5e1f; }
.medium { color: var(--yellow); background: #f59e0b1f; }
.low { color: var(--green); background: #22c55e1f; }

.findings { padding-left: 18px; }

.findings li {
    font-size: 12px;
    line-height: 1.7;
    margin-bottom: 9px;
}

.recent-list { display: grid; gap: 10px; }

.recent-top {
    display: flex;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
}

.recent-item p {
    font-size: 12px;
    line-height: 1.7;
    overflow-wrap: anywhere;
}

.about-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
}

.about-item p {
    font-size: 12px;
    line-height: 1.7;
    color: var(--muted);
}

.terminal {
    background: #060b13;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px;
    font: 12px/1.9 Consolas, monospace;
    min-height: 130px;
    overflow-wrap: anywhere;
}

.terminal-line { color: var(--green); margin: 4px 0; }
.terminal-line.info { color: #7dd3fc; }

footer {
    text-align: center;
    color: #738198;
    font-size: 11px;
    line-height: 1.8;
    padding: 20px;
}

.flash {
    padding: 12px;
    margin: 12px 0;
    background: #3b1d2a;
    border: 1px solid #854052;
    border-radius: 8px;
    color: #fecdd3;
    font-size: 13px;
}

@media(max-width: 1000px) {
    .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .sidebar { width: 190px; }
}

@media(max-width: 720px) {
    .layout { display: block; }
    .sidebar { width: 100%; padding: 14px; }
    .brand { margin-bottom: 12px; }
    .nav-label, .sidebar-note { display: none; }
    nav { display: flex; gap: 4px; overflow-x: auto; }
    .nav-link { flex-shrink: 0; padding: 10px; }
    .main { padding: 16px 12px; }
    .chart-grid, .result-grid, .about-grid {
        grid-template-columns: 1fr;
    }
    .panel { padding: 16px; }
    .panel-heading { flex-direction: column; }
    .status { font-size: 10px; }
}

@media(prefers-reduced-motion: reduce) {
    *, *::before, *::after {
        animation: none !important;
        transition: none !important;
        scroll-behavior: auto !important;
    }
}
</style>
</head>

<body>
<div class="layout">

<aside class="sidebar">
    <div class="brand">
        <div class="brand-icon">CS</div>
        <div>
            <h1>CyberSage AI</h1>
            <small>THREAT INTELLIGENCE</small>
        </div>
    </div>

    <div class="nav-label">WORKSPACE</div>

    <nav>
        <a class="nav-link active" href="#dashboard">Dashboard</a>
        <a class="nav-link" href="#scanner">Threat Scanner</a>
        <a class="nav-link" href="#results">Results</a>
        <a class="nav-link" href="{{ url_for('history') }}">Scan History</a>
        <a class="nav-link" href="#about">About System</a>
    </nav>

    <div class="sidebar-note">
        <strong>Security reminder</strong><br>
        Never submit passwords, OTPs, bank PINs, or private information.
    </div>
</aside>

<main class="main" id="dashboard">

<header class="topbar">
    <div>
        <div class="muted">Workspace / Overview</div>
        <h2>Security Dashboard</h2>
    </div>

    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span class="muted">
            Signed in as {{ session.get("user_name", "User") }}
        </span>

        <form method="POST" action="{{ url_for('logout') }}" style="margin:0">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button class="btn secondary" type="submit">Log out</button>
        </form>

        <div class="status">Application ready</div>
    </div>
</header>

{% with messages = get_flashed_messages() %}
    {% for message in messages %}
        <div class="flash" role="alert">{{ message }}</div>
    {% endfor %}
{% endwith %}

<section class="welcome">
    <h1>Welcome to <span>CyberSage AI</span></h1>
    <p class="muted">
        Analyze suspicious messages, inspect phishing indicators,
        and review saved scan statistics.
    </p>
</section>

<section class="stats">
    <div class="stat">
        <div class="stat-label">Total scans</div>
        <div class="stat-value">{{ stats.total_scans }}</div>
        <div class="stat-foot">All saved scans</div>
    </div>

    <div class="stat">
        <div class="stat-label">Phishing predictions</div>
        <div class="stat-value" style="color:var(--red)">
            {{ stats.phishing_count }}
        </div>
        <div class="stat-foot">Predicted as phishing</div>
    </div>

    <div class="stat">
        <div class="stat-label">Legitimate predictions</div>
        <div class="stat-value" style="color:var(--green)">
            {{ stats.legitimate_count }}
        </div>
        <div class="stat-foot">Predicted as legitimate</div>
    </div>

    <div class="stat">
        <div class="stat-label">High-risk scans</div>
        <div class="stat-value" style="color:var(--yellow)">
            {{ stats.high_risk_count }}
        </div>
        <div class="stat-foot">Rule-based risk levels</div>
    </div>
</section>

<section class="panel" id="soc-terminal">
    <div class="panel-heading">
        <div>
            <h2>Security Operations Center</h2>
            <p>Application activity monitor</p>
        </div>
        <span class="tag">SYSTEM LOG</span>
    </div>

    <div class="terminal">
        <div class="terminal-line info">
            CyberSage AI - Local monitoring console
        </div>
        <div id="terminal-output" aria-live="polite"></div>
        <span>_</span>
    </div>
</section>

<section class="panel" id="analytics">
    <div class="panel-heading">
        <div>
            <h2>Security Analytics</h2>
            <p>Charts calculated from saved scan totals.</p>
        </div>
        <span class="tag">DATABASE TOTALS</span>
    </div>

    <div class="chart-grid">
        <div class="chart-card">
            <h3>Prediction distribution</h3>
            <div class="chart-wrap">
                <canvas id="predictionChart"></canvas>
            </div>
        </div>

        <div class="chart-card">
            <h3>High-risk vs other scans</h3>
            <div class="chart-wrap">
                <canvas id="riskChart"></canvas>
            </div>
        </div>
    </div>

    <p class="muted">
        These charts summarize saved results. They do not prove that
        messages are safe or measure model accuracy.
    </p>
</section>

<section class="panel" id="scanner">
    <div class="panel-heading">
        <div>
            <h2>Threat Analysis Scanner</h2>
            <p>Inspect a suspicious URL or message.</p>
        </div>
        <span class="tag">MANUAL ANALYSIS</span>
    </div>

    <form method="POST" action="{{ url_for('home') }}#results"
          id="scanner-form">

        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <label for="user_input">Message or URL to analyze</label>

        <textarea id="user_input"
                  name="user_input"
                  maxlength="5000"
                  required
                  placeholder="Paste a suspicious message here...">{{ user_input }}</textarea>

        <div class="input-meta">
            <span>Maximum 5,000 characters</span>
            <span id="char-count">0 / 5000</span>
        </div>

        <div class="actions">
            <button class="btn primary" type="submit" id="scan-button">
                <span id="scan-button-text">Analyze threat</span>
            </button>

            <button class="btn secondary" type="button" id="clear-button">
                Clear input
            </button>
        </div>
    </form>

    <div class="notice">
        Educational use only. Submitted links are not opened.
        A low risk score or legitimate prediction does not guarantee safety.
    </div>
</section>

{% if result %}
<section class="panel" id="results">
    <div class="panel-heading">
        <div>
            <h2>Analysis Report | Scan #{{ result.scan_id }}</h2>
            <p>Results for your submitted input.</p>
        </div>

        <span class="risk-badge {{ result.risk|lower if result.risk|lower in ['high', 'medium', 'low'] else 'medium' }}">
            {{ result.risk }} RISK
        </span>
    </div>

    <div class="result-grid">
        <div class="result-card">
            <h3>Heuristic Risk Score</h3>

            <div class="score-number">
                {{ result.score }}<span class="muted"> / 100</span>
            </div>

            <div class="progress">
                <div class="progress-fill"
                     style="width:{{ result.score }}%"></div>
            </div>

            <p class="muted">Rule-based score, not a probability.</p>
        </div>

        <div class="result-card">
            <h3>Machine Learning Prediction</h3>

            {% if result.prediction|lower == 'phishing' %}
                <span class="risk-badge high">PHISHING DETECTED</span>
            {% elif result.prediction|lower == 'legitimate' %}
                <span class="risk-badge low">LEGITIMATE</span>
            {% else %}
                <span class="risk-badge medium">{{ result.prediction }}</span>
            {% endif %}

            {% if result.confidence is not none %}
                <p class="muted">
                    Model confidence estimate:
                    <strong>{{ "%.1f"|format(result.confidence|float) }}%</strong>
                </p>
            {% else %}
                <p class="muted">Confidence estimate unavailable.</p>
            {% endif %}
        </div>

        <div class="result-card">
            <h3>Security Indicators</h3>

            {% if result.findings %}
                <ul class="findings">
                {% for finding in result.findings %}
                    <li>{{ finding }}</li>
                {% endfor %}
                </ul>
            {% else %}
                <p class="muted">No indicators returned.</p>
            {% endif %}
        </div>
    </div>

    <div class="actions">
        <a class="btn primary"
           href="{{ url_for('download_report', scan_id=result.scan_id) }}">
            Download CSV report
        </a>

        <a class="btn secondary" href="{{ url_for('history') }}">
            View scan history
        </a>
    </div>

    <div class="notice">
        Legitimate messages may contain suspicious words, and phishing
        messages can evade simple rules and models.
    </div>
</section>
{% endif %}

<section class="panel" id="recent">
    <div class="panel-heading">
        <div>
            <h2>Recent Scan Activity</h2>
            <p>Your five most recent scans.</p>
        </div>
        <a href="{{ url_for('history') }}">View all &rarr;</a>
    </div>

    {% if recent_scans %}
        <div class="recent-list">
        {% for scan in recent_scans %}
            <div class="recent-item">
                <div class="recent-top">
                    <strong>Scan #{{ scan.id }}</strong>

                    <span class="risk-badge {{ scan.risk|lower if scan.risk|lower in ['high', 'medium', 'low'] else 'medium' }}">
                        {{ scan.risk }}
                    </span>
                </div>

                <p>
                    {{ scan.input_text[:180] }}{% if scan.input_text|length > 180 %}...{% endif %}
                </p>

                <small>
                    {{ scan.scanned_at }} |
                    Score: {{ scan.score }}/100 |
                    ML: {{ scan.prediction }}
                </small>

                <div>
                    <a href="{{ url_for('download_report', scan_id=scan.id) }}">
                        Download report
                    </a>
                </div>
            </div>
        {% endfor %}
        </div>
    {% else %}
        <p class="muted">No saved scans yet.</p>
    {% endif %}
</section>

<section class="panel" id="about">
    <div class="panel-heading">
        <div>
            <h2>Detection Components</h2>
            <p>Core elements of this student cybersecurity project.</p>
        </div>
    </div>

    <div class="about-grid">
        <div class="about-item">
            <h3>Rule-based analysis</h3>
            <p>Checks warning signs, suspicious wording, and URL patterns.</p>
        </div>

        <div class="about-item">
            <h3>Machine learning</h3>
            <p>Uses a trained classifier when one is available.</p>
        </div>

        <div class="about-item">
            <h3>Analytics</h3>
            <p>Displays saved scan counts and prediction distributions.</p>
        </div>
    </div>
</section>

<footer>
    <strong>CyberSage AI</strong> | Student Cybersecurity Project<br>
    For educational use. Independently verify suspicious messages.
</footer>

</main>
</div>

<script>
const input = document.getElementById("user_input");
const count = document.getElementById("char-count");
const clearButton = document.getElementById("clear-button");
const form = document.getElementById("scanner-form");
const terminalOutput = document.getElementById("terminal-output");

function updateCount() {
    count.textContent = input.value.length + " / 5000";
}

input.addEventListener("input", updateCount);

clearButton.addEventListener("click", () => {
    input.value = "";
    updateCount();
    input.focus();
});

updateCount();

const terminalMessages = [
    ["[INFO] Dashboard initialized.", "info"],
    ["[STATUS] Local analyzer ready.", ""],
    ["[DB] Scan history interface loaded.", "info"]
];

terminalMessages.forEach((entry, index) => {
    setTimeout(() => {
        const line = document.createElement("div");
        line.className = "terminal-line " + entry[1];
        line.textContent = entry[0];
        terminalOutput.appendChild(line);
    }, 350 * (index + 1));
});

form.addEventListener("submit", () => {
    if (!input.value.trim()) return;

    document.getElementById("scan-button").disabled = true;
    document.getElementById("scan-button-text").textContent =
        "Analyzing...";
});

const stats = {
    phishing: {{ stats.phishing_count | tojson }},
    legitimate: {{ stats.legitimate_count | tojson }},
    high: {{ stats.high_risk_count | tojson }},
    total: {{ stats.total_scans | tojson }}
};

if (typeof Chart !== "undefined") {
    const common = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: "#cbd5e1" }
            }
        }
    };

    new Chart(document.getElementById("predictionChart"), {
        type: "doughnut",
        data: {
            labels: ["Phishing", "Legitimate"],
            datasets: [{
                data: [stats.phishing, stats.legitimate],
                backgroundColor: ["#fb7185", "#4ade80"],
                borderColor: "#0b1322",
                borderWidth: 3
            }]
        },
        options: { ...common, cutout: "65%" }
    });

    new Chart(document.getElementById("riskChart"), {
        type: "bar",
        data: {
            labels: ["High risk", "Other risk levels"],
            datasets: [{
                label: "Saved scans",
                data: [
                    stats.high,
                    Math.max(0, stats.total - stats.high)
                ],
                backgroundColor: ["#fb7185", "#38bdf8"],
                borderRadius: 7
            }]
        },
        options: {
            ...common,
            scales: {
                x: {
                    ticks: { color: "#94a3b8" },
                    grid: { display: false }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "#94a3b8",
                        precision: 0
                    },
                    grid: { color: "#253349" }
                }
            }
        }
    });
} else {
    document.querySelectorAll(".chart-wrap").forEach(element => {
        element.textContent =
            "Charts require an internet connection.";
    });
}

document.querySelectorAll(".nav-link").forEach(link => {
    link.addEventListener("click", () => {
        document.querySelectorAll(".nav-link").forEach(item => {
            item.classList.remove("active");
        });

        link.classList.add("active");
    });
});
</script>
</body>
</html>
"""


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or len(name) > 80:
            flash("Enter a name between 1 and 80 characters.")
            return render_template("register.html"), 400

        if (
            len(email) > 254
            or "@" not in email
            or "." not in email.rsplit("@", 1)[-1]
        ):
            flash("Enter a valid email address.")
            return render_template("register.html"), 400

        if len(password) < 12 or len(password) > 128:
            flash("Password must be between 12 and 128 characters.")
            return render_template("register.html"), 400

        if password != confirm_password:
            flash("Passwords do not match.")
            return render_template("register.html"), 400

        try:
            create_user(name, email, password)
        except sqlite3.IntegrityError:
            flash("An account with that email already exists.")
            return render_template("register.html"), 409

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_user_by_email(email)

        if user is None or not verify_password(user, password):
            flash("Invalid email or password.")
            return render_template("login.html"), 401

        session.clear()
        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session.permanent = True

        return redirect(url_for("home"))

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))


# --------------------------------------------------
# DASHBOARD AND THREAT SCANNER
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    result = None
    user_input = ""

    if request.method == "POST":
        user_input = request.form.get("user_input", "").strip()

        if not user_input:
            flash("Please enter a message or URL to analyze.")

        elif len(user_input) > 5000:
            flash("Input cannot exceed 5,000 characters.")

        else:
            try:
                result = analyze_input(user_input)

                if not isinstance(result, dict):
                    raise ValueError(
                        "analyze_input() must return a dictionary."
                    )

                result.setdefault("risk", "Unknown")
                result.setdefault("score", 0)
                result.setdefault("prediction", "Unavailable")
                result.setdefault("confidence", None)
                result.setdefault("findings", [])

                result["score"] = max(
                    0,
                    min(100, int(result["score"]))
                )

                if not isinstance(result["findings"], (list, tuple)):
                    result["findings"] = []

                # Expected signature:
                # save_scan(input_text, result, user_id)
                result["scan_id"] = save_scan(
                    user_input,
                    result,
                    session["user_id"],
                )

            except (ValueError, TypeError, sqlite3.Error):
                app.logger.exception("Threat scan failed.")
                result = None
                flash(
                    "The scan failed. Check analyzer.py and "
                    "database.py for errors."
                )

    stats = get_dashboard_stats(session["user_id"])

    recent_scans = get_recent_scans(
        session["user_id"],
        limit=5,
    )

    return render_template_string(
        HTML_PAGE,
        result=result,
        user_input=user_input,
        stats=stats,
        recent_scans=recent_scans,
    )


# --------------------------------------------------
# SCAN HISTORY
# --------------------------------------------------

@app.route("/history")
@login_required
def history():
    scans = get_recent_scans(session["user_id"])

    return render_template_string(
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1">
            <title>CyberSage AI | Scan History</title>

            <style>
                body {
                    margin: 0;
                    padding: 24px;
                    background: #080d19;
                    color: #edf4ff;
                    font-family: "Segoe UI", Arial, sans-serif;
                }

                main {
                    max-width: 950px;
                    margin: auto;
                }

                a { color: #7dd3fc; }

                .scan {
                    margin: 15px 0;
                    padding: 18px;
                    background: #101827;
                    border: 1px solid #253349;
                    border-radius: 12px;
                    overflow-wrap: anywhere;
                }

                .muted {
                    color: #94a3b8;
                    font-size: 12px;
                    line-height: 1.7;
                }

                .btn {
                    display: inline-block;
                    padding: 10px 14px;
                    border-radius: 8px;
                    background: #0284c7;
                    color: white;
                    text-decoration: none;
                    font-size: 13px;
                }
            </style>
        </head>

        <body>
        <main>
            <h1>CyberSage AI - Scan History</h1>

            <p>
                <a href="{{ url_for('home') }}">
                    &larr; Back to dashboard
                </a>
            </p>

            {% for scan in scans %}
                <div class="scan">
                    <h3>Scan #{{ scan.id }}</h3>

                    <p class="muted">{{ scan.scanned_at }}</p>

                    <p>
                        <strong>Input:</strong>
                        {{ scan.input_text }}
                    </p>

                    <p>
                        <strong>Risk:</strong>
                        {{ scan.risk }}
                    </p>

                    <p>
                        <strong>Score:</strong>
                        {{ scan.score }}/100
                    </p>

                    <p>
                        <strong>Prediction:</strong>
                        {{ scan.prediction }}
                    </p>

                    <a class="btn"
                       href="{{ url_for(
                           'download_report',
                           scan_id=scan.id
                       ) }}">
                        Download CSV report
                    </a>
                </div>
            {% else %}
                <p class="muted">No scans saved yet.</p>
            {% endfor %}
        </main>
        </body>
        </html>
        """,
        scans=scans,
    )


# --------------------------------------------------
# CSV REPORT DOWNLOAD
# --------------------------------------------------

@app.route("/report/<int:scan_id>")
@login_required
def download_report(scan_id):
    # The database query must restrict this scan to the current user.
    scan = get_scan(scan_id, session["user_id"])

    if scan is None:
        abort(404)

    def safe_csv_cell(value):
        text = str(value if value is not None else "")

        # Prevent spreadsheet formula injection.
        if text.lstrip().startswith(
            ("=", "+", "-", "@", "\t", "\r")
        ):
            return "'" + text

        return text

    report = io.StringIO()
    writer = csv.writer(report)

    writer.writerow(["CyberSage AI Scan Report"])
    writer.writerow(["Scan ID", scan["id"]])
    writer.writerow(["Date", scan["scanned_at"]])
    writer.writerow(["Input", safe_csv_cell(scan["input_text"])])
    writer.writerow(["Risk", safe_csv_cell(scan["risk"])])
    writer.writerow(["Heuristic score", scan["score"]])
    writer.writerow([
        "ML prediction",
        safe_csv_cell(scan["prediction"]),
    ])
    writer.writerow([
        "Findings",
        safe_csv_cell(scan["findings"]),
    ])
    writer.writerow([])
    writer.writerow([
        "Educational use only; not a guarantee of safety."
    ])

    data = io.BytesIO(report.getvalue().encode("utf-8-sig"))
    data.seek(0)

    return send_file(
        data,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"cybersage_report_{scan_id}.csv",
    )


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
