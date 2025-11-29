from flask import Flask, request, jsonify, make_response, send_file, Response, render_template
from flask_limiter import Limiter
from werkzeug.serving import WSGIRequestHandler
from flask_limiter.util import get_remote_address
import os
import uuid
import json
import markdown
import ssl
from datetime import datetime, timedelta
import threading
import subprocess

# Configuration
SAVE_DIR = "/home/asuna/Dokumente/Porn_Fetch/"  # Logs for Porn Fetch
ALLOWED_ENDPOINTS = ["/report", "/feedback", "/ping", "/update", "ci"]
RATE_LIMIT = "2000 per minute"
MAX_REQUEST_SIZE = 200 * 1024  # 200KB
MAX_HOURLY_DATA = 5 * 1024 * 1024 * 1024  # 5GB to prevent DoS attacks
CI_TOKEN = os.environ.get("CI_TOKEN")  # Token used to update the CI stuff from n8n workflows (long story)
KILL_TOKEN = os.environ.get("KILL_TOKEN")  # Token for /killswitch endpoint

# CI tracking
ci_status = {}
ci_lock = threading.Lock()
VALID_CI_STATUSES = {"pass", "fail", "running", "unknown"}

# Data tracking (This does NOT track YOU, only the requests to prevent DDOS attacks)
written_files_log = []
lock = threading.Lock()

# In-memory stats tracking (public, anonymous)
stats_lock = threading.Lock()
server_start_time = datetime.utcnow()
stats = {
    "total_requests": 0,
    "total_bytes_in": 0,   # client -> server (upload)
    "total_bytes_out": 0,  # server -> client (download)
}

errors_log = []    # summaries of error reports
feedback_log = []  # summaries of feedback reports

# Flask setup
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_SIZE

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[RATE_LIMIT]
)

os.makedirs(SAVE_DIR, exist_ok=True)


def shutdown_server():
    print(">>> KILL SWITCH TRIGGERED: More than 2GB written in the past hour. Shutting down.")
    os._exit(1)


def log_write(file_size: int):
    now = datetime.now()
    with lock:
        written_files_log.append((now, file_size))
        # Remove entries older than 1 hour
        one_hour_ago = now - timedelta(hours=1)
        written_files_log[:] = [(t, s) for t, s in written_files_log if t >= one_hour_ago]

        total_written = sum(s for t, s in written_files_log)
        if total_written > MAX_HOURLY_DATA:
            shutdown_server()  # Kill Switch


def validate_payload(data):
    if not isinstance(data, dict):
        return False
    if "message" not in data or not isinstance(data["message"], str):
        return False
    return True


def save_message(data: dict, tag: str):
    file_id = str(uuid.uuid4())
    filename = f"{tag}_{file_id}.json"
    full_path = os.path.join(SAVE_DIR, filename)
    data["timestamp"] = datetime.utcnow().isoformat() + "Z"

    raw_content = json.dumps(data, indent=2)
    encoded_content = raw_content.encode("utf-8")

    if len(encoded_content) > MAX_REQUEST_SIZE:
        raise ValueError("File content exceeds 200KB limit")

    with open(full_path, 'wb') as f:
        f.write(encoded_content)

    log_write(len(encoded_content))

    # Keep a lightweight in-memory copy for the /stats endpoint
    entry_summary = {
        "id": file_id,
        "tag": tag,
        "timestamp": data["timestamp"],
        "message": data.get("message", "")
    }
    with lock:
        if tag == "error":
            errors_log.append(entry_summary)
        elif tag == "feedback":
            feedback_log.append(entry_summary)


# ---------- CI/CD helper functions ----------

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
    Store last known status for a test.
    status: 'pass', 'fail', 'running', 'unknown'
    """
    norm = str(status).lower()
    if norm not in VALID_CI_STATUSES:
        norm = "unknown"

    entry = {
        "name": test_name,
        "status": norm,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    if details:
        entry["details"] = str(details)

    with ci_lock:
        ci_status[test_name] = entry

    return entry


def get_ci_status(test_name):
    with ci_lock:
        if test_name in ci_status:
            return ci_status[test_name]

    # default if nothing reported yet
    return {
        "name": test_name,
        "status": "unknown",
        "updated_at": None,
        "details": "no result reported yet"
    }


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


# ---------- Stats helper functions & hooks ----------

def bytes_to_mb(num_bytes: int) -> float:
    return round(num_bytes / (1024 * 1024), 3)


@app.before_request
def track_request():
    # Count every incoming request and its approximate payload size
    content_length = request.content_length
    if content_length is None:
        content_length = 0
    with stats_lock:
        stats["total_requests"] += 1
        stats["total_bytes_in"] += max(int(content_length), 0)


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

    with stats_lock:
        stats["total_bytes_out"] += max(int(length or 0), 0)

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
    # snapshot current stats
    with stats_lock:
        total_requests = stats["total_requests"]
        bytes_in = stats["total_bytes_in"]
        bytes_out = stats["total_bytes_out"]

    uptime_seconds = int((datetime.utcnow() - server_start_time).total_seconds())

    with ci_lock:
        ci_list = list(ci_status.values())

    with lock:
        errors = list(errors_log)
        feedback = list(feedback_log)

    stats_payload = {
        "server_started_at": server_start_time.isoformat() + "Z",
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
