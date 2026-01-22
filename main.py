import os
import json
import base64

import httpx
import stripe
import secrets
import sqlite3
import markdown
import threading
import subprocess

from io import BytesIO
from flask_limiter import Limiter
from werkzeug.serving import WSGIRequestHandler
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, request, jsonify, make_response, send_file, Response, render_template, g

# Configuration
SAVE_DIR = "./"  # Now mainly used as DB folder
ALLOWED_ENDPOINTS = ["/report", "/feedback", "/ping", "/update", "ci"]
RATE_LIMIT = "10000 per minute"
MAX_REQUEST_SIZE = 200 * 1024  # 200 KB
MAX_HOURLY_DATA = 5 * 1024 * 1024 * 1024  # 5GB to prevent DoS attacks
CI_TOKEN = os.environ.get("CI_TOKEN")   # Token used to update the CI stuff from n8n workflows (long story)
KILL_TOKEN = os.environ.get("KILL_TOKEN")  # Token for /killswitch endpoint
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")      # sk_test_... or sk_live_...
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")  # pk_test_... or pk_live_...
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID")          # price_xxx for your Porn Fetch license
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")    # whsec_... from Stripe
APP_DOMAIN = os.environ.get("APP_DOMAIN", "http://localhost:5000") # used in success/cancel URLs
LICENSE_PRIVATE_KEY_B64 = os.environ.get("LICENSE_PRIVATE_KEY_B64", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "") # Used for update checking for my repos (long story)

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
        """
    )

    started_at = datetime.utcnow().isoformat()

    # Ensure a single stats row exists, and RESET it on each server start.
    cur = conn.execute("SELECT COUNT(*) FROM stats WHERE id = 1;")
    count = cur.fetchone()[0]

    if count == 0:
        conn.execute(
            "INSERT INTO stats (id, total_requests, total_bytes_in, total_bytes_out, server_started_at) "
            "VALUES (1, 0, 0, 0, ?);",
            (started_at,),
        )
    else:
        conn.execute(
            """
            UPDATE stats
            SET total_requests = 0,
                total_bytes_in = 0,
                total_bytes_out = 0,
                server_started_at = ?
            WHERE id = 1;
            """,
            (started_at,),
        )

    conn.commit()
    conn.close()


init_db()


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
def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def make_license_key(prefix="PF") -> str:
    # human-friendly-ish, not a secret, just an identifier
    raw = secrets.token_hex(16).upper()
    # PF-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
    chunks = [raw[i:i+8] for i in range(0, len(raw), 8)]
    return f"{prefix}-" + "-".join(chunks)


def sign_license(payload: dict) -> str:
    if not LICENSE_PRIVATE_KEY_B64:
        raise RuntimeError("Missing LICENSE_PRIVATE_KEY_B64")

    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(LICENSE_PRIVATE_KEY_B64))
    msg = canonical_json_bytes(payload)
    sig = priv.sign(msg)
    return base64.b64encode(sig).decode("ascii")


def verify_paid_checkout_session(session_id: str) -> stripe.checkout.Session:
    # Retrieve from Stripe and verify it was paid + correct price/product.
    sess = stripe.checkout.Session.retrieve(session_id, expand=["line_items"])
    if sess.get("payment_status") != "paid":
        raise ValueError("Payment not completed.")

    # Optional: ensure the right product/price was purchased
    if STRIPE_PRICE_ID:
        items = sess["line_items"]["data"]
        ok = any((li.get("price") or {}).get("id") == STRIPE_PRICE_ID for li in items)
        if not ok:
            raise ValueError("Wrong product purchased for this session.")
    return sess

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
            "timestamp": row["created_at"],
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
@app.route("/impress", methods=["GET"])
def impress():
    # Renders a modern-looking page with a (hopefully) legal impress (required by german law)
    return render_template(
        "impress.html",
    )


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


@app.route("/download_license", methods=["GET"])
@limiter.limit(RATE_LIMIT)
def download_license():
    session_id = request.args.get("session_id", "")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    try:
        verify_paid_checkout_session(session_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 403

    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    license_payload = {
        "schema": 1,
        "product": "porn-fetch",
        "kid": "v1",
        "alg": "ed25519",
        "license_key": make_license_key(),
        "stripe_session_id": session_id,
        "created_at": created_at,
        "features": ["full_unlock"],
    }

    license_payload["sig"] = sign_license(license_payload)

    file_bytes = (json.dumps(license_payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    return send_file(
        BytesIO(file_bytes),
        as_attachment=True,
        download_name="porn_fetch.license",
        mimetype="application/json",
    )


@app.route("/", methods=["GET"])
def landing_page():
    # templates/index.html contains your landing page HTML
    return render_template("index.html")

@app.route("/ping", methods=["GET"])
def ping():
    return make_response("Success", 200)

@app.route("/datenschutz", methods=["GET"])
def datenschutz():
    return render_template("privacy_policy_de.html")

@app.route("/privacy_policy", methods=["GET"])
def privacy_policy():
    return render_template("privacy_policy_en.html")

@app.route("/update", methods=["GET"])  # Get Porn Fetch changelog
def update():
    version = None
    changelog = None
    """
    curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer <YOUR-TOKEN>" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/OWNER/REPO/releases/latest
    """

    get_information = httpx.get(url="https://api.github.com/repos/EchterAlsFake/Porn_Fetch/releases/latest", headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
    }).json()

    print(get_information)


    with open("porn_fetch_version.txt", "r") as version_file:
        version = version_file.read().strip()

    with open("porn_fetch_changelog.md", "r") as changelog_file:
        changelog_markdown = changelog_file.read().strip()
        changelog = markdown.markdown(changelog_markdown)

    stuff = jsonify({
        "version": version,
        "url": "https://github.com/EchterAlsFake/Porn_Fetch/releases/tag/3.6",
        "anonymous_download": "https://echteralsfake.me/download",
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
