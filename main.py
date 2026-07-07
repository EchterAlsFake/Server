import os
from dotenv import load_dotenv
load_dotenv()
import json
import time
import httpx
import hmac
import hashlib
import base64
import secrets
import sqlite3
import markdown
import threading
import subprocess

from io import BytesIO
from flask_limiter import Limiter
from email.utils import format_datetime
from werkzeug.serving import WSGIRequestHandler
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, request, jsonify, make_response, send_file, Response, render_template, g, redirect
from fpdf import FPDF


# Configuration
SAVE_DIR = "./"  # Now mainly used as DB folder
ALLOWED_ENDPOINTS = ["/report", "/feedback", "/ping", "/update", "ci"]
RATE_LIMIT = "10000 per minute"
MAX_REQUEST_SIZE = 200 * 1024  # 200 KB
MAX_HOURLY_DATA = 5 * 1024 * 1024 * 1024  # 5GB to prevent DoS attacks
CI_TOKEN = os.environ.get("CI_TOKEN")   # Token used to update the CI stuff from n8n workflows (long story)
KILL_TOKEN = os.environ.get("KILL_TOKEN")  # Token for /killswitch endpoint
APP_DOMAIN = os.environ.get("APP_DOMAIN", "http://localhost:5000") # used in success/cancel URLs
LICENSE_PRIVATE_KEY_B64 = os.environ.get("LICENSE_PRIVATE_KEY_B64", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "") # Used for update checking for my repos (long story)
NOWPAYMENTS_API_KEY = os.environ.get("NOWPAYMENTS_API_KEY")
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET")
NOWPAYMENTS_SANDBOX = os.environ.get("NOWPAYMENTS_SANDBOX", "true").lower() in ("true", "1", "yes")
NOWPAYMENTS_API_URL = "https://api-sandbox.nowpayments.io/v1" if NOWPAYMENTS_SANDBOX else "https://api.nowpayments.io/v1"

update_cache = {
    "last_checked": 0,
    "data": None
}

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

        CREATE TABLE IF NOT EXISTS transactions (
            session_id TEXT PRIMARY KEY,
            purchase_id TEXT,
            trans_id TEXT,
            email TEXT,
            status TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS checklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task TEXT NOT NULL,
            is_done INTEGER NOT NULL DEFAULT 0,
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
    # PF-MediaMediaXX-MediaMediaXX-MediaMediaXX-MediaMediaXX
    chunks = [raw[i:i+8] for i in range(0, len(raw), 8)]
    return f"{prefix}-" + "-".join(chunks)


def sign_license(payload: dict) -> str:
    if not LICENSE_PRIVATE_KEY_B64:
        raise RuntimeError("Missing LICENSE_PRIVATE_KEY_B64")

    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(LICENSE_PRIVATE_KEY_B64))
    msg = canonical_json_bytes(payload)
    sig = priv.sign(msg)
    return base64.b64encode(sig).decode("ascii")


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


def get_update_information():
    now = time.monotonic()
    if update_cache.get("last_checked", 0) == 0 or (now - update_cache.get("last_checked", 0)) > 5 * 60:
        # Updating data every 5 minutes for minimal API requests
        update_cache["last_checked"] = now

        get_information = httpx.get(url="https://api.github.com/repos/EchterAlsFake/Porn_Fetch/releases/latest",
                            headers={
                                "Accept": "application/vnd.github+json",
                                "Authorization": f"Bearer {GITHUB_TOKEN}",
                                "X-GitHub-Api-Version": "2022-11-28"
                            }).json()

        update_cache["data"] = get_information
        data = get_information

    else:
        # Using data from cache
        data = update_cache.get("data")

    version = data.get("tag_name", "unavailable")
    assets = data.get("assets", [])
    linux_x64 = next((a for a in assets if a.get("name") == "PornFetch_Linux_GUI_x64.bin"))
    linux_arm64 = next((a for a in assets if a.get("name") == "PornFetch_Linux_GUI_arm64.bin"))
    windows_x64 = next((a for a in assets if a.get("name") == "PornFetch_Windows_GUI_x64.exe"))
    windows_arm64 = next((a for a in assets if a.get("name") == "PornFetch_Windows_GUI_arm64.exe"))
    macos_universal = next((a for a in assets if a.get("name") == "PornFetch_macOS_GUI_Universal.dmg"))
    stuff = {
        "version": version,
        "linux_x64": linux_x64,
        "linux_arm64": linux_arm64,
        "windows_x64": windows_x64,
        "windows_arm64": windows_arm64,
        "macos_universal": macos_universal,
        "url": data.get("html_url")
    }

    return stuff


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
        "buy_license.html"
    )

@app.route("/refund_policy", methods=["GET"])
def refund_policy():
    return render_template("refund_policy.html")


@app.route("/terms", methods=["GET"])
def terms():
    return render_template("terms.html")


@app.route("/content_removal", methods=["GET"])
def content_removal():
    return render_template("content_removal.html")


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

    # Verify that the session_id exists and is approved in the database
    db = get_db()
    cur = db.execute("SELECT status, purchase_id FROM transactions WHERE session_id = ?;", (session_id,))
    row = cur.fetchone()
    if not row or row["status"] not in ("finished", "paid"):
        return jsonify({"error": "Payment not approved or session not found"}), 402

    nowpayments_id = row["purchase_id"] or session_id
    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    license_payload = {
        "schema": 1,
        "product": "porn-fetch",
        "kid": "v1",
        "alg": "ed25519",
        "license_key": make_license_key(),
        "nowpayments_invoice_id": nowpayments_id,
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


@app.route("/check-payment-status", methods=["GET"])
@limiter.limit(RATE_LIMIT)
def check_payment_status():
    session_id = request.args.get("session_id", "")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    db = get_db()
    cur = db.execute("SELECT status FROM transactions WHERE session_id = ?;", (session_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({"status": "unknown"}), 404

    if row["status"] in ("finished", "paid"):
        invoice_num = "N/A"
        invoice_path = os.path.join(SAVE_DIR, "invoices", f"{session_id}.json")
        if os.path.exists(invoice_path):
            with open(invoice_path, "r") as f:
                inv = json.load(f)
                invoice_num = inv.get("Invoice Number", "N/A")
        return jsonify({"status": "finished", "invoice_num": invoice_num}), 200
    else:
        return jsonify({"status": "pending"}), 200

@app.route("/download_invoice", methods=["GET"])
@limiter.limit(RATE_LIMIT)
def download_invoice():
    session_id = request.args.get("session_id", "")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    db = get_db()
    cur = db.execute("SELECT status FROM transactions WHERE session_id = ?;", (session_id,))
    row = cur.fetchone()
    if not row or row["status"] not in ("finished", "paid"):
        return jsonify({"error": "Payment not approved or session not found"}), 402

    invoices_dir = os.path.join(SAVE_DIR, "invoices")
    invoice_path = os.path.join(invoices_dir, f"{session_id}.json")
    if not os.path.exists(invoice_path):
        return jsonify({"error": "Invoice not found for this session"}), 404
        
    with open(invoice_path, "r") as f:
        invoice_data = json.load(f)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    
    # Title
    pdf.set_font("Helvetica", style="B", size=16)
    pdf.cell(0, 10, f"INVOICE {invoice_data.get('Invoice Number', '')}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    
    # Sender info
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 8, "From:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 8, invoice_data.get("Full Name", ""), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, invoice_data.get("Address", ""), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Tax Number: {invoice_data.get('Tax Number', '')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # Dates
    pdf.cell(0, 8, f"Invoice Date: {invoice_data.get('Invoice Date', '')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Delivery Date: {invoice_data.get('Delivery Date', '')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # Item info
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 8, "Items:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 8, f"Description: {invoice_data.get('Description', '')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Quantity: {invoice_data.get('Quantity', 1)}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    pdf.set_font("Helvetica", style="I", size=11)
    pdf.cell(0, 8, invoice_data.get("Tax Info", ""), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    pdf.ln(10)
    
    # Payment info
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 8, "Payment Details:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 8, f"Base Price: {invoice_data.get('Base Price in EUR', '')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Crypto Paid: {invoice_data.get('Crypto Paid', '')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Exchange Rate: {invoice_data.get('Exchange Rate', '')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Transaction Hash / TxID: {invoice_data.get('Transaction Hash / TxID', '')}", new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(15)
    pdf.set_font("Helvetica", style="I", size=12)
    pdf.cell(0, 10, "Thank you for your purchase!", align="C", new_x="LMARGIN", new_y="NEXT")
    
    pdf_bytes = pdf.output()
    return send_file(
        BytesIO(pdf_bytes),
        as_attachment=True,
        download_name=f"invoice_{invoice_data.get('Invoice Number')}.pdf",
        mimetype="application/pdf",
    )


@app.route("/simulate-payment-success", methods=["POST"])
@limiter.limit(RATE_LIMIT)
def simulate_payment_success():
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"error": "Missing session_id"}), 400

    db = get_db()
    with db:
        cur = db.execute("SELECT session_id FROM transactions WHERE session_id = ?;", (session_id,))
        if not cur.fetchone():
            return jsonify({"error": "Session not found"}), 404
        db.execute(
            "UPDATE transactions SET status = 'finished' WHERE session_id = ?;",
            (session_id,)
        )
        
    invoice_num = "INV-" + secrets.token_hex(4).upper()
    invoice_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    invoice_data = {
        "Full Name": "Johannes Habel",
        "Address": "Bahnstr. 21 06886 Lutherstadt Wittenberg",
        "Tax Number": "46208375790",
        "Invoice Date": invoice_date,
        "Delivery Date": invoice_date,
        "Invoice Number": invoice_num,
        "Description": "Porn Fetch License",
        "Quantity": 1,
        "Tax Info": "Hinweis: Gemäß § 19 UStG wird keine Umsatzsteuer berechnet.",
        "Base Price in EUR": "19.99 EUR",
        "Crypto Paid": "0.00016 BTC",
        "Exchange Rate": "1 BTC = 62437.50 EUR",
        "Transaction Hash / TxID": "mock-tx-hash-12345"
    }
    invoices_dir = os.path.join(SAVE_DIR, "invoices")
    os.makedirs(invoices_dir, exist_ok=True)
    with open(os.path.join(invoices_dir, f"{session_id}.json"), "w") as f:
        json.dump(invoice_data, f, indent=4)

    return jsonify({"status": "ok", "message": "Payment simulation successful."}), 200


@app.route("/", methods=["GET"])
def landing_page():
    # templates/index.html contains your landing page HTML
    return render_template("index.html")

@app.route("/porn_fetch", methods=["GET"])
def porn_fetch():
    return render_template("porn_fetch.html")

@app.route("/donation", methods=["GET"])
def donation():
    return render_template("donation.html")


@app.route("/create-crypto-payment", methods=["POST"])
@limiter.limit(RATE_LIMIT)
def create_crypto_payment():
    if not NOWPAYMENTS_API_KEY:
        return jsonify({"error": "NOWPayments API key not configured on server."}), 500

    # Generate a unique order & session ID
    session_id = "NP-" + secrets.token_urlsafe(16)
    created_at = datetime.utcnow().isoformat()

    # Call NOWPayments API to create the invoice
    headers = {
        "x-api-key": NOWPAYMENTS_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "price_amount": 19.99,
        "price_currency": "eur",
        "ipn_callback_url": f"{APP_DOMAIN}/nowpayments_ipn",
        "order_id": session_id,
        "order_description": "Porn Fetch License Key",
        "success_url": f"{APP_DOMAIN}/buy_success?session_id={session_id}",
        "cancel_url": f"{APP_DOMAIN}/buy_cancel"
    }

    try:
        # Create invoice on NOWPayments
        api_url = f"{NOWPAYMENTS_API_URL}/invoice"
        r = httpx.post(api_url, json=payload, headers=headers, timeout=10.0)
        r.raise_for_status()
        invoice_data = r.json()

        # Save order to local database with status "pending"
        db = get_db()
        with db:
            db.execute(
                """
                INSERT INTO transactions (session_id, purchase_id, trans_id, email, status, created_at)
                VALUES (?, ?, ?, 'crypto-buyer@example.com', 'pending', ?);
                """,
                (session_id, str(invoice_data.get("id")), str(invoice_data.get("id")), created_at)
            )

        # Return the redirect invoice URL and the session_id
        return jsonify({
            "session_id": session_id,
            "invoice_url": invoice_data.get("invoice_url")
        }), 200

    except Exception as e:
        app.logger.error(f"NOWPayments Invoice API call failed: {e}")
        if NOWPAYMENTS_SANDBOX:
            app.logger.info("Falling back to local simulation due to API key error or network error.")
            invoice_id = "mock-" + secrets.token_hex(8)
            db = get_db()
            with db:
                db.execute(
                    """
                    INSERT INTO transactions (session_id, purchase_id, trans_id, email, status, created_at)
                    VALUES (?, ?, ?, 'crypto-buyer@example.com', 'pending', ?);
                    """,
                    (session_id, invoice_id, invoice_id, created_at)
                )
            return jsonify({
                "session_id": session_id,
                "invoice_url": f"local-sim:{session_id}"
            }), 200
        else:
            return jsonify({"error": f"Failed to generate crypto payment: {str(e)}"}), 500



@app.route("/nowpayments_ipn", methods=["POST"])
def nowpayments_ipn():
    """
    Webhook handler for NOWPayments IPN callbacks.
    """
    # 1. Verify NOWPayments callback signature
    received_sig = request.headers.get("x-nowpayments-sig")
    if not received_sig or not NOWPAYMENTS_IPN_SECRET:
        return "Missing signature or secret key configuration", 401

    request_data = request.get_data()

    try:
        data_dict = json.loads(request_data)
    except:
        return "Invalid JSON", 400

    # Sort JSON keys to construct signature check payload matching NOWPayments standard
    sorted_data = json.dumps(data_dict, sort_keys=True, separators=(',', ':'))

    calculated_sig = hmac.new(
        NOWPAYMENTS_IPN_SECRET.encode("utf-8"),
        sorted_data.encode("utf-8"),
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(received_sig, calculated_sig):
        return "Invalid signature verification", 403

    # 2. Extract payment status
    payment_status = data_dict.get("payment_status") or data_dict.get("status") or ""
    order_id = data_dict.get("order_id")

    # Important: Prevent automatic approval on Repeated Deposits and Wrong-Asset Deposits
    # as recommended in the NOWPayments documentation to avoid underpayment risks.
    if data_dict.get("parent_payment_id"):
        app.logger.warning(f"Ignored IPN for repeated/wrong-asset deposit for order {order_id}")
        return "Ignored repeated deposit", 200

    # If the transaction is fully finished on-chain, mark it approved
    if payment_status.lower() in ("finished", "paid"):
        db = get_db()
        try:
            with db:
                cur = db.execute("SELECT status FROM transactions WHERE session_id = ?;", (order_id,))
                row = cur.fetchone()
                # Only process if it is pending to prevent duplicate invoice generation
                if row and row["status"] not in ("finished", "paid"):
                    db.execute(
                        "UPDATE transactions SET status = 'finished' WHERE session_id = ?;",
                        (order_id,)
                    )
                    
                    invoice_num = "INV-" + secrets.token_hex(4).upper()
                    invoice_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
                    
                    pay_currency = str(data_dict.get("pay_currency", "")).upper()
                    actually_paid = float(data_dict.get("actually_paid") or data_dict.get("pay_amount", 0))
                    fiat_amount = float(data_dict.get("price_amount", 19.99))
                    
                    if actually_paid > 0:
                        rate = fiat_amount / actually_paid
                    else:
                        rate = 0
                        
                    crypto_paid = f"{actually_paid} {pay_currency}"
                    exchange_rate = f"1 {pay_currency} = {rate:.2f} EUR"
                    tx_hash = str(data_dict.get("payin_hash") or data_dict.get("hash") or "N/A")
                    
                    invoice_data = {
                        "Full Name": "Johannes Habel",
                        "Address": "Bahnstr. 21 06886 Lutherstadt Wittenberg",
                        "Tax Number": "46208375790",
                        "Invoice Date": invoice_date,
                        "Delivery Date": invoice_date,
                        "Invoice Number": invoice_num,
                        "Description": "Porn Fetch License",
                        "Quantity": 1,
                        "Tax Info": "Hinweis: Gemäß § 19 UStG wird keine Umsatzsteuer berechnet.",
                        "Base Price in EUR": f"{fiat_amount:.2f} EUR",
                        "Crypto Paid": crypto_paid,
                        "Exchange Rate": exchange_rate,
                        "Transaction Hash / TxID": tx_hash
                    }
                    
                    invoices_dir = os.path.join(SAVE_DIR, "invoices")
                    os.makedirs(invoices_dir, exist_ok=True)
                    invoice_path = os.path.join(invoices_dir, f"{order_id}.json")
                    with open(invoice_path, "w") as f:
                        json.dump(invoice_data, f, indent=4)
                        
                    app.logger.info(f"NOWPayments order {order_id} marked as approved. Invoice {invoice_num} generated.")
        except Exception as e:
            app.logger.error(f"Failed to update database or generate invoice for order {order_id}: {e}")
            return "Database Error", 500

    return "OK", 200


@app.route("/ping", methods=["GET"])
def ping():
    return make_response("Success", 200)

@app.route("/datenschutz", methods=["GET"])
def datenschutz():
    return render_template("privacy_policy_de.html")

@app.route("/privacy_policy", methods=["GET"])
def privacy_policy():
    return render_template("privacy_policy_en.html")

@app.route("/legal-statement", methods=["GET"])
def legal_compliance():
    return render_template("legal-statement.html")


@app.route("/update", methods=["GET"])  # Get Media Archiver changelog
def update():
    with open("media_archiver_changelog.md", "r") as changelog_file:
        changelog_markdown = changelog_file.read().strip()
        changelog = markdown.markdown(changelog_markdown)

    fortnite = get_update_information()
    stuff = jsonify({
        "version": f"{fortnite.get('version')}",
        "url": fortnite.get("url"),
        "anonymous_download": "https://echteralsfake.me/download",
        "download_linux_x64": fortnite.get("linux_x64")["browser_download_url"],
        "download_linux_arm64": fortnite.get("linux_arm64")["browser_download_url"],
        "download_windows_x64": fortnite.get("windows_x64")["browser_download_url"],
        "download_windows_arm64": fortnite.get("windows_arm64")["browser_download_url"],
        "download_macos_universal": fortnite.get("macos_universal")["browser_download_url"],
        "changelog": changelog,
        "important_info": "Nothing here ;)"
    })
    # "download_linux_arm64": fortnite.get("linux_arm64")["browser_download_url"],
    return stuff, 200

def load_signature_for_version(tag: str) -> str:
    # Needed for Sparkle (macOS auto updating)

    with open(f"signatures/{tag}.txt", "r", encoding="utf-8") as f:
        return f.read().strip()


@app.route("/appcast.xml", methods=["GET"])
def appcast():
    data = get_update_information()
    tag = data.get("version")
    mac_asset = data.get("macos_universal")

    dmg_url = mac_asset["browser_download_url"]
    dmg_size = mac_asset.get("size", 0)

    published_at = data.get("published_at")
    if published_at:
        pub_dt = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    else:
        pub_dt = datetime.now(timezone.utc)

    pub_date_rfc2822 = format_datetime(pub_dt)

    # Your changelog -> HTML
    with open("media_archiver_changelog.md", "r", encoding="utf-8") as f:
        changelog_html = markdown.markdown(f.read().strip())

    ed_sig = load_signature_for_version(tag)

    xml = f"""<?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
      <channel>
        <title>Porn Fetch Updates</title>

        <item>
          <title>Version {tag}</title>
          <pubDate>{pub_date_rfc2822}</pubDate>
          <description><![CDATA[{changelog_html}]]></description>

          <enclosure
            url="{dmg_url}"
            length="{dmg_size}"
            type="application/x-apple-diskimage"
            sparkle:shortVersionString="{tag}"
            sparkle:version="{tag}"
            sparkle:edSignature="{ed_sig}"
          />
        </item>

      </channel>
    </rss>
    """
    return Response(xml, mimetype="application/rss+xml")
# --- Security headers ---

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "connect-src 'self'; "
        "frame-src 'self' https://nowpayments.io; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
    )
    return resp


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
        }
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


# ---------- Checklist routes ----------

def check_checklist_auth():
    auth_env = os.environ.get("CHECKLIST_AUTH")
    if not auth_env:
        return False
    return request.cookies.get("checklist_auth") == auth_env

@app.route('/checklist', methods=['GET', 'POST'])
def checklist():
    auth_env = os.environ.get("CHECKLIST_AUTH")
    if not auth_env:
        return "CHECKLIST_AUTH env variable not set", 500

    if request.method == 'POST':
        password = request.form.get("password", "")
        if password == auth_env:
            resp = make_response(redirect("/checklist"))
            resp.set_cookie("checklist_auth", password)
            return resp
        else:
            return render_template("checklist_login.html", error="Invalid password"), 401

    if not check_checklist_auth():
        return render_template("checklist_login.html")
    
    return render_template("checklist.html")

@app.route('/checklist/api/tasks', methods=['GET'])
def get_tasks():
    if not check_checklist_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    cur = db.execute("SELECT id, task, is_done, created_at FROM checklist ORDER BY created_at ASC;")
    tasks = []
    for row in cur.fetchall():
        tasks.append({
            "id": row["id"],
            "task": row["task"],
            "is_done": bool(row["is_done"]),
            "created_at": row["created_at"]
        })
    return jsonify(tasks)

@app.route('/checklist/api/add', methods=['POST'])
def add_task():
    if not check_checklist_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    task = data.get("task")
    if not task:
        return jsonify({"error": "Task required"}), 400
        
    db = get_db()
    with db:
        db.execute("INSERT INTO checklist (task, is_done, created_at) VALUES (?, ?, ?);",
                   (task, 0, datetime.utcnow().isoformat()))
    return jsonify({"success": True})

@app.route('/checklist/api/toggle/<int:task_id>', methods=['POST'])
def toggle_task(task_id):
    if not check_checklist_auth():
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.json
    is_done = 1 if data.get("is_done") else 0
    db = get_db()
    with db:
        db.execute("UPDATE checklist SET is_done = ? WHERE id = ?;", (is_done, task_id))
    return jsonify({"success": True})

@app.route('/checklist/api/remove/<int:task_id>', methods=['POST'])
def remove_task(task_id):
    if not check_checklist_auth():
        return jsonify({"error": "Unauthorized"}), 401
        
    db = get_db()
    with db:
        db.execute("DELETE FROM checklist WHERE id = ?;", (task_id,))
    return jsonify({"success": True})

@app.route('/checklist/progress.svg', methods=['GET'])
def checklist_progress_svg():
    # Progress SVG doesn't strictly need auth if meant for a public GitHub README
    db = get_db()
    cur = db.execute("SELECT COUNT(*) as total, SUM(is_done) as done FROM checklist;")
    row = cur.fetchone()
    total = row["total"] or 0
    done = row["done"] or 0
    
    percentage = 0
    if total > 0:
        percentage = round((done / total) * 100)
        

    label = "Version 3.9 Development Progress"
    value = f"{percentage}%"
    
    total_width = 400
    height = 36
    radius = 18
    fill_width = int((percentage / 100.0) * total_width)

    if percentage >= 100:
        grad_start, grad_end = "#00b09b", "#96c93d"  # Green
    elif percentage >= 50:
        grad_start, grad_end = "#f7971e", "#ffd200"  # Yellow/Orange
    elif percentage > 0:
        grad_start, grad_end = "#f85032", "#e73827"  # Red
    else:
        grad_start, grad_end = "#444444", "#666666"  # Grey

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" role="img" aria-label="{label}: {value}">
  <defs>
    <linearGradient id="bar-grad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="{grad_start}" />
      <stop offset="100%" stop-color="{grad_end}" />
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#000" flood-opacity="0.4"/>
    </filter>
  </defs>
  
  <rect width="{total_width}" height="{height}" rx="{radius}" fill="#1e1e24" filter="url(#shadow)"/>
  
  <mask id="fill-mask">
    <rect width="{total_width}" height="{height}" rx="{radius}" fill="#fff"/>
  </mask>
  
  <g mask="url(#fill-mask)">
    <rect width="{fill_width}" height="{height}" fill="url(#bar-grad)"/>
    <rect width="{total_width}" height="{height}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="2" rx="{radius}"/>
  </g>
  
  <g font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="14" font-weight="600">
    <text x="20" y="23" fill="#ffffff">{label}</text>
    <text x="{total_width - 20}" y="23" text-anchor="end" fill="#ffffff">{value}</text>
  </g>
</svg>'''

    resp = make_response(svg)
    resp.content_type = 'image/svg+xml'
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = "no-cache"
    resp.headers['Expires'] = "0"
    resp.headers.pop('ETag', None)
    resp.headers.pop('Last-Modified', None)
    return resp


class NoIPLoggingHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        # Only log method, path, and response code — no IP (For your privacy XD)
        method = self.command
        path = self.path
        print(f'{method} {path} -> {code}')


if __name__ == '__main__':
    app.run(host="::", port=8000)
