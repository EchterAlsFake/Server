from flask import Flask, request, jsonify, make_response, send_file
from flask_limiter import Limiter
from werkzeug.serving import WSGIRequestHandler
from flask_limiter.util import get_remote_address
import os
import uuid
import json
import markdown
from datetime import datetime, timedelta
import threading

# Configuration
SAVE_DIR = "/home/asuna/Dokumente/Porn_Fetch/" # Logs for Porn Fetch
ALLOWED_ENDPOINTS = ["/report", "/feedback", "/ping", "/update"]
RATE_LIMIT = "2000 per minute"
MAX_REQUEST_SIZE = 200 * 1024  # 200KB
MAX_HOURLY_DATA = 5 * 1024 * 1024 * 1024  # 5GB to prevent DoS attacks

# Data tracking
written_files_log = []
lock = threading.Lock()

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
            shutdown_server() # Kill Switch

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

@app.route("/ping", methods=["GET"])
def ping():
    return make_response("Success", 200)

@app.route("/update", methods=["GET"]) # Get Porn Fetch changelog
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

@app.route("/download", methods=["GET"]) # Download Porn Fetch anonymously
def download():
    file_location = "/home/asuna/PycharmProjects/Server/Porn_Fetch.zip" # Full version

    send_file(path_or_file=file_location,
              as_attachment=True,
              mimetype="application/zip",
              download_name="Porn_Fetch_FULL.zip",
              etag="")


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
    app.run(host="0.0.0.0", port=443,  request_handler=NoIPLoggingHandler, ssl_context=(
    "/home/asuna/.acme.sh/echteralsfake.duckdns.org_ecc/fullchain.cer",
    "/home/asuna/.acme.sh/echteralsfake.duckdns.org_ecc/echteralsfake.duckdns.org.key"
))
