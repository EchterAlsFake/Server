from flask import Flask, request, jsonify, make_response, send_file, Response, render_template, g
from flask_limiter import Limiter
from werkzeug.serving import WSGIRequestHandler
from flask_limiter.util import get_remote_address
import os
import json
import markdown
from datetime import datetime, timedelta
import threading
import subprocess
import sqlite3
import stripe
import hmac
import hashlib
from io import BytesIO

# Configuration
SAVE_DIR = "/home/asuna/Dokumente/Porn_Fetch/"  # Now mainly used as DB folder
ALLOWED_ENDPOINTS = ["/report", "/feedback", "/ping", "/update", "ci"]
RATE_LIMIT = "10000 per minute"
MAX_REQUEST_SIZE = 200 * 1024  # 200KB
MAX_HOURLY_DATA = 5 * 1024 * 1024 * 1024  # 5GB to prevent DoS attacks
CI_TOKEN = os.environ.get("CI_TOKEN")   # Token used to update the CI stuff from n8n workflows (long story)
KILL_TOKEN = os.environ.get("KILL_TOKEN")  # Token for /killswitch endpoint
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")      # sk_test_... or sk_live_...
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")  # pk_test_... or pk_live_...
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID")          # price_xxx for your Porn Fetch license
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")    # whsec_... from Stripe
APP_DOMAIN = os.environ.get("APP_DOMAIN", "http://localhost:5000") # used in success/cancel URLs
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "dev-secret-change-me")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# Where the SQLite DB lives (override with PF_SERVER_DB if you want)
os.makedirs(SAVE_DIR, exist_ok=True)
DB_PATH = os.environ.get("PF_SERVER_DB", os.path.join(SAVE_DIR, "server.db"))

# Flask setup
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_SIZE

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[RATE_LIMIT]
)

# ---------- DB setup ----------

def init_db():
    """Initialize SQLite database and tables."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            total_requests INTEGER NOT NULL DEFAULT 0,
            total_bytes_in INTEGER NOT NULL DEFAULT 0,
            total_bytes_out INTEGER NOT NULL DEFAULT 0,
            server_started_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ci_status (
            test_name TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            updated_at TEXT,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT NOT NULL,
            message TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS write_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bytes_written INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
            
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            email TEXT,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    # Ensure a single stats row exists
    cur = conn.execute("SELECT COUNT(*) FROM stats WHERE id = 1;")
    count = cur.fetchone()[0]
    if count == 0:
        conn.execute(
            "INSERT INTO stats (id, total_requests, total_bytes_in, total_bytes_out, server_started_at) "
            "VALUES (1, 0, 0, 0, ?);",
            (datetime.utcnow().isoformat(),),
        )

    conn.commit()
    conn.close()


init_db()


def save_license(session_id: str, email: str | None, license_key: str) -> None:
    """Store or update a license record for a given Stripe Checkout session."""
    created_at = datetime.utcnow().isoformat() + "Z"
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO licenses (session_id, email, license_key, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (session_id, email, license_key, created_at),
        )
        conn.commit()


def get_license(session_id: str) -> dict | None:
    """Fetch a license record by checkout session id."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            """
            SELECT session_id, email, license_key, created_at
            FROM licenses
            WHERE session_id = ?
            """,
            (session_id,),
        )
        row = cur.fetchone()

    if not row:
        return None

    return {
        "session_id": row[0],
        "email": row[1],
        "license_key": row[2],
        "created_at": row[3],
    }


def generate_license_key(email: str | None, session_id: str) -> str:
    """Deterministic license key: HMAC(email:session_id, LICENSE_SECRET)."""
    email = email or "anonymous"
    msg = f"{email}:{session_id}".encode("utf-8")
    key = hmac.new(LICENSE_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return key

def get_db():
    """Get a per-request sqlite connection."""
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- Helper functions ----------

def shutdown_server():
    print(">>> KILL SWITCH TRIGGERED: More than 2GB written in the past hour. Shutting down.")
    os._exit(1)


def log_write(file_size: int):
    """Track how much data has been written in the last hour using the DB."""
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=1)
    now_str = now.isoformat()
    cutoff_str = cutoff.isoformat()

    db = get_db()
    with db:
        db.execute(
            "INSERT INTO write_log (bytes_written, created_at) VALUES (?, ?);",
            (file_size, now_str),
        )
        db.execute(
            "DELETE FROM write_log WHERE created_at < ?;",
            (cutoff_str,),
        )
        cur = db.execute(
            "SELECT COALESCE(SUM(bytes_written), 0) FROM write_log WHERE created_at >= ?;",
            (cutoff_str,),
        )
        total_written = cur.fetchone()[0] or 0

    if total_written > MAX_HOURLY_DATA:
        shutdown_server()  # Kill Switch


def validate_payload(data):
    if not isinstance(data, dict):
        return False
    if "message" not in data or not isinstance(data["message"], str):
        return False
    return True


def save_message(data: dict, tag: str):
    """
    Store error/feedback payload into the DB instead of a JSON file.
    Still enforces MAX_REQUEST_SIZE and feeds bytes into the DoS kill switch logic.
    """
    created_at = datetime.utcnow().isoformat()

    # Add timestamp into the stored JSON for convenience
    data_with_ts = dict(data)
    data_with_ts["timestamp"] = created_at + "Z"

    raw_content = json.dumps(data_with_ts, indent=2)
    encoded_content = raw_content.encode("utf-8")

    if len(encoded_content) > MAX_REQUEST_SIZE:
        raise ValueError("File content exceeds 200KB limit")

    # Track how much we've written (DoS prevention)
    log_write(len(encoded_content))

    db = get_db()
    with db:
        db.execute(
            "INSERT INTO reports (tag, message, raw_json, created_at) VALUES (?, ?, ?, ?);",
            (tag, data.get("message", ""), raw_content, created_at),
        )


def get_reports(tag: str, limit: int = 50):
    db = get_db()
    cur = db.execute(
        """
        SELECT id, tag, message, created_at
        FROM reports
        WHERE tag = ?
        ORDER BY created_at DESC
        LIMIT ?;
        """,
        (tag, limit),
    )
    rows = cur.fetchall()
    return [
        {
            "id": row["id"],
            "tag": row["tag"],
            "timestamp": row["created_at"],
            "message": row["message"],
        }
        for row in rows
    ]


def increment_stats(requests_inc: int = 0, bytes_in_inc: int = 0, bytes_out_inc: int = 0):
    """Atomically increment stats counters in the DB."""
    if not (requests_inc or bytes_in_inc or bytes_out_inc):
        return
    db = get_db()
    with db:
        db.execute(
            """
            UPDATE stats
            SET total_requests = total_requests + ?,
                total_bytes_in = total_bytes_in + ?,
                total_bytes_out = total_bytes_out + ?
            WHERE id = 1;
            """,
            (requests_inc, bytes_in_inc, bytes_out_inc),
        )


def get_stats_snapshot():
    db = get_db()
    cur = db.execute(
        "SELECT total_requests, total_bytes_in, total_bytes_out, server_started_at FROM stats WHERE id = 1;"
    )
    row = cur.fetchone()
    if row is None:
        # Should not happen, but recover gracefully
        started_at = datetime.utcnow().isoformat()
        with db:
            db.execute(
                "INSERT OR REPLACE INTO stats (id, total_requests, total_bytes_in, total_bytes_out, server_started_at) "
                "VALUES (1, 0, 0, 0, ?);",
                (started_at,),
            )
        return {
            "total_requests": 0,
            "total_bytes_in": 0,
            "total_bytes_out": 0,
            "server_started_at": started_at,
        }

    return {
        "total_requests": row["total_requests"],
        "total_bytes_in": row["total_bytes_in"],
        "total_bytes_out": row["total_bytes_out"],
        "server_started_at": row["server_started_at"],
    }


def bytes_to_mb(num_bytes: int) -> float:
    return round(num_bytes / (1024 * 1024), 3)


# ---------- CI/CD helper functions (DB-backed) ----------

VALID_CI_STATUSES = {"pass", "fail", "running", "unknown"}


def check_ci_auth():
    """
    Optional simple auth for CI updates.
    If CI_TOKEN is set, require header X-CI-TOKEN or ?token=... to match.
    If CI_TOKEN is not set, allow all (useful for local testing).
    """
    if CI_TOKEN is None:
        return True
    provided = request.headers.get("X-CI-TOKEN") or request.args.get("token")
    return provided == CI_TOKEN


def set_ci_status(test_name, status, details=None):
    """
    Store last known status for a test in the DB.
    status: 'pass', 'fail', 'running', 'unknown'
    """
    norm = str(status).lower()
    if norm not in VALID_CI_STATUSES:
        norm = "unknown"

    updated_at = datetime.utcnow().isoformat()
    entry = {
        "name": test_name,
        "status": norm,
        "updated_at": updated_at + "Z",
    }
    if details is not None:
        entry["details"] = str(details)

    db = get_db()
    with db:
        db.execute(
            """
            INSERT INTO ci_status (test_name, status, updated_at, details)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(test_name) DO UPDATE SET
                status = excluded.status,
                updated_at = excluded.updated_at,
                details = excluded.details;
            """,
            (test_name, norm, updated_at, details),
        )

    return entry


def get_ci_status(test_name):
    db = get_db()
    cur = db.execute(
        "SELECT test_name, status, updated_at, details FROM ci_status WHERE test_name = ?;",
        (test_name,),
    )
    row = cur.fetchone()
    if row:
        return {
            "name": row["test_name"],
            "status": row["status"],
            "updated_at": (row["updated_at"] + "Z") if row["updated_at"] else None,
            "details": row["details"],
        }

    # default if nothing reported yet
    return {
        "name": test_name,
        "status": "unknown",
        "updated_at": None,
        "details": "no result reported yet",
    }


def get_all_ci_status():
    db = get_db()
    cur = db.execute(
        "SELECT test_name, status, updated_at, details FROM ci_status ORDER BY test_name ASC;"
    )
    rows = cur.fetchall()
    tests = []
    for row in rows:
        tests.append(
            {
                "name": row["test_name"],
                "status": row["status"],
                "updated_at": (row["updated_at"] + "Z") if row["updated_at"] else None,
                "details": row["details"],
            }
        )
    return tests


def generate_ci_badge_svg(test_name, status):
    """
    Very simple shields-style SVG badge.
    """
    label = test_name.replace("_", " ")
    value = status.upper()

    # rough width estimation for monospace-like font
    def w(text):
        return 6 * len(text) + 10

    left_width = max(w(label), 40)
    right_width = max(w(value), 40)
    total_width = left_width + right_width
    height = 20

    if status == "pass":
        color = "#4c1"      # green
    elif status == "fail":
        color = "#e05d44"   # red
    elif status == "running":
        color = "#dfb317"   # yellow
    else:
        color = "#9f9f9f"   # grey

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" role="img" aria-label="{label}: {value}">
  <linearGradient id="smooth" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".7"/>
    <stop offset=".1" stop-color="#aaa" stop-opacity=".1"/>
    <stop offset=".9" stop-color="#000" stop-opacity=".3"/>
    <stop offset="1" stop-color="#000" stop-opacity=".5"/>
  </linearGradient>
  <mask id="round">
    <rect width="{total_width}" height="{height}" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#round)">
    <rect width="{left_width}" height="{height}" fill="#555"/>
    <rect x="{left_width}" width="{right_width}" height="{height}" fill="{color}"/>
    <rect width="{total_width}" height="{height}" fill="url(#smooth)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{left_width / 2}" y="14">{label}</text>
    <text x="{left_width + right_width / 2}" y="14">{value}</text>
  </g>
</svg>"""
    return svg


# ---------- Request stats hooks ----------

@app.before_request
def track_request():
    # Count every incoming request and its approximate payload size
    content_length = request.content_length
    if content_length is None:
        content_length = 0
    content_length = max(int(content_length), 0)
    increment_stats(requests_inc=1, bytes_in_inc=content_length)


@app.after_request
def track_response(response):
    # Count response payload size
    try:
        length = response.calculate_content_length()
        if length is None:
            data = response.get_data()
            length = len(data) if data is not None else 0
    except Exception:
        length = 0

    length = max(int(length or 0), 0)
    increment_stats(bytes_out_inc=length)
    return response


# ---------- Kill switch helper ----------

def initiate_poweroff():
    """
    Trigger a system-wide shutdown via 'poweroff'.
    This assumes the server process has the required privileges.
    """
    print(">>> /killswitch triggered: initiating system poweroff.")

    def _poweroff():
        try:
            subprocess.run(["poweroff"])
        except Exception as e:
            print(f"Failed to call poweroff: {e}")

    threading.Thread(target=_poweroff, daemon=True).start()


# ---------- Routes ----------

@app.route("/buy_license", methods=["GET"])
def buy_license():
    # Renders a modern-looking page with a BUY button
    return render_template(
        "buy_license.html",
        stripe_publishable_key=STRIPE_PUBLISHABLE_KEY,
    )

@app.route("/create-checkout-session", methods=["POST"])
@limiter.limit(RATE_LIMIT)
def create_checkout_session():
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        return jsonify({"error": "Stripe is not configured on the server"}), 500

    data = request.get_json(silent=True) or {}
    customer_email = data.get("email")

    try:
        checkout_session = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            line_items=[
                {
                    "price": STRIPE_PRICE_ID,
                    "quantity": 1,
                }
            ],
            success_url=f"{APP_DOMAIN}/buy_success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{APP_DOMAIN}/buy_cancel",
            customer_email=customer_email or None,
        )
        return jsonify({"url": checkout_session.url})
    except Exception as e:
        # In dev, you might want to log(e) as well
        return jsonify({"error": str(e)}), 400

@app.route("/buy_success", methods=["GET"])
def buy_success():
    session_id = request.args.get("session_id")
    # Just render a page that says “thank you” and has a download button
    return render_template("buy_success.html", session_id=session_id)


@app.route("/buy_cancel", methods=["GET"])
def buy_cancel():
    return render_template("buy_cancel.html")

@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    if not STRIPE_WEBHOOK_SECRET:
        # Misconfigured server
        return "Webhook secret not configured", 500

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        # Signature verification failure or JSON parsing error
        return f"Webhook error: {str(e)}", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        handle_successful_checkout(session)

    # Optionally handle other events here

    return "", 200


def handle_successful_checkout(session: dict) -> None:
    """Called when Stripe tells us a Checkout session was successfully completed."""
    session_id = session["id"]
    email = None

    # Stripe can store email in different places depending on configuration
    if session.get("customer_details") and session["customer_details"].get("email"):
        email = session["customer_details"]["email"]
    elif session.get("customer_email"):
        email = session["customer_email"]

    license_key = generate_license_key(email, session_id)
    save_license(session_id, email, license_key)


@app.route("/download_license", methods=["GET"])
@limiter.limit(RATE_LIMIT)
def download_license():
    session_id = request.args.get("session_id")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    record = {
        "email": "test@test.com",
        "session_id": session_id,
        "license_key": "test",
        "created_at": "sometime"
    }
    if not record:
        # Either payment not completed yet, or no such session
        return jsonify({"error": "License not found or payment not completed yet"}), 404

    content = f"""# Porn Fetch License

Email: {record['email']}
Stripe-Session: {record['session_id']}
License-Key: {record['license_key']}
Created-At: {record['created_at']}

Thank you for supporting Porn Fetch ❤️
"""

    file_stream = BytesIO(content.encode("utf-8"))
    return send_file(
        file_stream,
        as_attachment=True,
        download_name="porn_fetch.license",
        mimetype="text/plain",
    )

@app.route("/", methods=["GET"])
def landing_page():
    # templates/index.html contains your landing page HTML
    return render_template("index.html")

@app.route("/ping", methods=["GET"])
def ping():
    return make_response("Success", 200)


@app.route("/update", methods=["GET"])  # Get Porn Fetch changelog
def update():
    version = None
    changelog = None

    with open("porn_fetch_version.txt", "r") as version_file:
        version = version_file.read().strip()

    with open("porn_fetch_changelog.md", "r") as changelog_file:
        changelog_markdown = changelog_file.read().strip()
        changelog = markdown.markdown(changelog_markdown)

    stuff = jsonify({
        "version": version,
        "url": "https://github.com/EchterAlsFake/Porn_Fetch/releases/tag/3.6",
        "anonymous_download": "https://echteralsfake.duckdns.org/download",
        "changelog": changelog,
        "important_info": "Nothing here ;)"
    })
    return stuff, 200


@app.route("/download", methods=["GET"])  # Download Porn Fetch anonymously
def download():
    file_location = "/home/asuna/PycharmProjects/Server/Porn_Fetch.zip"  # Full version

    return send_file(
        path_or_file=file_location,
        as_attachment=True,
        mimetype="application/zip",
        download_name="Porn_Fetch_FULL.zip",
        conditional=True
    )


@app.route("/report", methods=["POST"])
@limiter.limit(RATE_LIMIT)
def report_error():
    if not request.is_json:
        return jsonify({"error": "Expected JSON"}), 400
    data = request.get_json()

    if not validate_payload(data):
        return jsonify({"error": "Invalid payload. Expecting { 'message': 'text' }"}), 400

    try:
        save_message(data, tag="error")
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    return jsonify({"status": "ok", "message": "Error report saved."})


@app.route("/feedback", methods=["POST"])
@limiter.limit(RATE_LIMIT)
def send_feedback():
    if not request.is_json:
        return jsonify({"error": "Expected JSON"}), 400
    data = request.get_json()

    if not validate_payload(data):
        return jsonify({"error": "Invalid payload. Expecting { 'message': 'text' }"}), 400

    try:
        save_message(data, tag="feedback")
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    return jsonify({"status": "ok", "message": "Feedback saved."})


# ---------- Kill switch endpoint ----------

@app.route("/killswitch", methods=["POST"])
@limiter.exempt
def killswitch():
    """
    POST /killswitch
    Auth via:
      - header: X-KILL-TOKEN: <token>
      - or query: ?token=<token>
      - or JSON body: { "token": "<token>" }

    On success, initiates a system poweroff.
    """
    if not KILL_TOKEN:
        return jsonify({"error": "Kill switch token not configured on server."}), 500

    provided = request.headers.get("X-KILL-TOKEN") or request.args.get("token")

    if not provided and request.is_json:
        body = request.get_json(silent=True) or {}
        provided = body.get("token")

    if provided != KILL_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    initiate_poweroff()
    return jsonify({"status": "ok", "message": "Shutdown initiated."}), 200


# ---------- Stats endpoint ----------

@app.route("/stats", methods=["GET"])
def stats_endpoint():
    """
    GET /stats
      - HTML dashboard by default
      - JSON if:
          * Accept: application/json
          * or ?format=json
    """
    stats_row = get_stats_snapshot()

    total_requests = stats_row["total_requests"]
    bytes_in = stats_row["total_bytes_in"]
    bytes_out = stats_row["total_bytes_out"]
    started_at_str = stats_row["server_started_at"]

    try:
        started_at_dt = datetime.fromisoformat(started_at_str)
    except Exception:
        started_at_dt = datetime.utcnow()

    uptime_seconds = int((datetime.utcnow() - started_at_dt).total_seconds())

    ci_list = get_all_ci_status()
    errors = get_reports("error", limit=100)
    feedback = get_reports("feedback", limit=100)

    stats_payload = {
        "server_started_at": started_at_str + "Z",
        "uptime_seconds": uptime_seconds,
        "requests": {
            "total": total_requests,
        },
        "traffic": {
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "mb_in": bytes_to_mb(bytes_in),
            "mb_out": bytes_to_mb(bytes_out),
        },
        "ci": {
            "tests": ci_list,
        },
        "reports": {
            "errors": errors,
            "feedback": feedback,
        },
    }

    want_json = (
        "application/json" in (request.headers.get("Accept") or "")
        or request.args.get("format") == "json"
    )

    if want_json:
        return jsonify(stats_payload), 200

    return render_template("stats.html", stats=stats_payload)


# ---------- CI/CD endpoints ----------

@app.route("/ci/<test_name>", methods=["POST"])
@limiter.limit(RATE_LIMIT)
def ci_update(test_name):
    """
    POST /ci/<test_name>
    JSON body: { "status": "pass" | "fail" | "running", "details": "optional text" }
    Optional auth: header X-CI-TOKEN=<CI_TOKEN> or ?token=<CI_TOKEN>
    """
    if not check_ci_auth():
        return jsonify({"error": "Unauthorized"}), 401

    if not request.is_json:
        return jsonify({"error": "Expected JSON"}), 400

    payload = request.get_json() or {}
    status = payload.get("status")
    if not status:
        return jsonify({"error": "Missing 'status' field"}), 400

    details = payload.get("details")
    entry = set_ci_status(test_name, status, details)
    return jsonify(entry), 200


@app.route("/ci/<test_name>", methods=["GET"])
def ci_plain(test_name):
    """
    GET /ci/<test_name>
    Returns simple plain-text status like "PASS", "FAIL", "RUNNING", "UNKNOWN".
    """
    entry = get_ci_status(test_name)
    text = entry["status"].upper()
    resp = make_response(text, 200)
    resp.mimetype = "text/plain"
    return resp


@app.route("/ci/<test_name>.json", methods=["GET"])
def ci_json(test_name):
    """
    GET /ci/<test_name>.json
    Returns status as JSON for tooling.
    """
    entry = get_ci_status(test_name)
    return jsonify(entry), 200


@app.route("/ci/<test_name>/badge.svg", methods=["GET"])
def ci_badge(test_name):
    """
    GET /ci/<test_name>/badge.svg
    Returns a dynamic SVG badge you can embed in your README.
    """
    entry = get_ci_status(test_name)
    svg = generate_ci_badge_svg(test_name, entry["status"])
    return Response(svg, mimetype="image/svg+xml")


# ---------- Error handlers ----------

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded. Try again later."}), 429


@app.errorhandler(413)
def payload_too_large(e):
    return jsonify({"error": "Payload too large. Max 200KB allowed."}), 413


class NoIPLoggingHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        # Only log method, path, and response code — no IP (For your privacy XD)
        method = self.command
        path = self.path
        print(f'{method} {path} -> {code}')


if __name__ == '__main__':
    app.run(host="::", port=8000)
