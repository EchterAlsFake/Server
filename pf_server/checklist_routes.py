"""Public checklist display and authenticated checklist editing routes."""

import hashlib
import hmac
from datetime import datetime, timezone

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
)

from .extensions import db
from .models import Checklist

checklist_bp = Blueprint("checklist", __name__)


def _checklist_auth_marker(auth_secret: str) -> str:
    signing_key = current_app.secret_key
    if isinstance(signing_key, str):
        signing_key = signing_key.encode("utf-8")
    return hmac.new(signing_key, auth_secret.encode("utf-8"), hashlib.sha256).hexdigest()


def check_checklist_auth() -> bool:
    auth_secret = current_app.config.get("CHECKLIST_AUTH")
    marker = session.get("checklist_auth")
    return (
        isinstance(auth_secret, str)
        and bool(auth_secret)
        and isinstance(marker, str)
        and hmac.compare_digest(marker, _checklist_auth_marker(auth_secret))
    )


@checklist_bp.route("/checklist/login", methods=["GET", "POST"])
def checklist_login():
    auth_secret = current_app.config.get("CHECKLIST_AUTH")
    if not auth_secret:
        return "CHECKLIST_AUTH env variable not set", 500

    if request.method == "POST":
        password = request.form.get("password", "")
        if hmac.compare_digest(password.encode("utf-8"), auth_secret.encode("utf-8")):
            session["checklist_auth"] = _checklist_auth_marker(auth_secret)
            return redirect("/checklist")
        return render_template("checklist_login.html", error="Invalid password"), 401
    return render_template("checklist_login.html")


@checklist_bp.route("/checklist", methods=["GET"])
def checklist():
    if not current_app.config.get("CHECKLIST_AUTH"):
        return "CHECKLIST_AUTH env variable not set", 500
    return render_template("checklist.html", is_auth=check_checklist_auth())


@checklist_bp.route("/checklist/api/tasks", methods=["GET"])
def get_tasks():
    tasks = Checklist.query.order_by(Checklist.created_at.asc()).all()
    return jsonify(
        [
            {
                "id": task.id,
                "task": task.task,
                "is_done": bool(task.is_done),
                "created_at": task.created_at,
            }
            for task in tasks
        ]
    )


@checklist_bp.route("/checklist/api/add", methods=["POST"])
def add_task():
    if not check_checklist_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    task_text = data.get("task") if isinstance(data, dict) else None
    if not isinstance(task_text, str) or not task_text.strip():
        return jsonify({"error": "Task required"}), 400
    task_text = task_text.strip()
    if len(task_text) > 500:
        return jsonify({"error": "Task must be at most 500 characters"}), 400

    db.session.add(
        Checklist(
            task=task_text,
            is_done=0,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    )
    db.session.commit()
    return jsonify({"success": True})


@checklist_bp.route("/checklist/api/toggle/<int:task_id>", methods=["POST"])
def toggle_task(task_id):
    if not check_checklist_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or type(data.get("is_done")) is not bool:
        return jsonify({"error": "is_done must be a boolean"}), 400
    task = db.session.get(Checklist, task_id)
    if task is None:
        return jsonify({"error": "Task not found"}), 404
    task.is_done = int(data["is_done"])
    db.session.commit()
    return jsonify({"success": True})


@checklist_bp.route("/checklist/api/remove/<int:task_id>", methods=["POST"])
def remove_task(task_id):
    if not check_checklist_auth():
        return jsonify({"error": "Unauthorized"}), 401

    deleted = Checklist.query.filter_by(id=task_id).delete()
    if not deleted:
        db.session.rollback()
        return jsonify({"error": "Task not found"}), 404
    db.session.commit()
    return jsonify({"success": True})


@checklist_bp.route("/checklist/progress.svg", methods=["GET"])
def checklist_progress_svg():
    total = db.session.query(db.func.count(Checklist.id)).scalar() or 0
    done = db.session.query(db.func.sum(Checklist.is_done)).scalar() or 0
    percentage = round((done / total) * 100) if total else 0

    label = "Version 3.9 Development Progress"
    value = f"{percentage}%"
    total_width = 400
    bar_height = 36
    badge_height = 22
    height = bar_height + badge_height + 12
    radius = 18
    fill_width = int((percentage / 100.0) * total_width)

    if percentage >= 100:
        gradient = ("#00b09b", "#96c93d")
    elif percentage >= 50:
        gradient = ("#f7971e", "#ffd200")
    elif percentage > 0:
        gradient = ("#f85032", "#e73827")
    else:
        gradient = ("#444444", "#666666")

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="{height}" role="img" aria-label="{label}: {value}">
  <style>
    @keyframes pulse {{
      0% {{ opacity: 0.5; transform: translate(0, 0); }}
      50% {{ opacity: 1; transform: translate(2px, -2px); }}
      100% {{ opacity: 0.5; transform: translate(0, 0); }}
    }}
    .font-base {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
    .arrow {{ animation: pulse 2s infinite; display: inline-block; fill: #58a6ff; }}
    .badge {{ transition: all 0.3s ease; }}
    svg:hover .badge-bg {{ fill: rgba(255, 255, 255, 0.1); stroke: rgba(88, 166, 255, 0.4); }}
    svg:hover .badge-text {{ fill: #ffffff; }}
  </style>
  <defs>
    <linearGradient id="bar-grad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="{gradient[0]}" />
      <stop offset="100%" stop-color="{gradient[1]}" />
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#000" flood-opacity="0.4"/>
    </filter>
  </defs>
  <rect width="{total_width}" height="{bar_height}" rx="{radius}" fill="#1e1e24" filter="url(#shadow)"/>
  <mask id="fill-mask"><rect width="{total_width}" height="{bar_height}" rx="{radius}" fill="#fff"/></mask>
  <g mask="url(#fill-mask)">
    <rect width="{fill_width}" height="{bar_height}" fill="url(#bar-grad)"/>
    <rect width="{total_width}" height="{bar_height}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="2" rx="{radius}"/>
  </g>
  <g class="font-base" font-size="14" font-weight="600">
    <text x="20" y="23" fill="#ffffff">{label}</text>
    <text x="{total_width - 20}" y="23" text-anchor="end" fill="#ffffff">{value}</text>
  </g>
  <g class="badge" transform="translate({total_width / 2 - 75}, {bar_height + 10})">
    <rect class="badge-bg" width="150" height="{badge_height}" rx="11" fill="rgba(255, 255, 255, 0.03)" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
    <text class="badge-text font-base" x="75" y="15" text-anchor="middle" font-size="11" font-weight="500" fill="#a8b2bd">Click for full checklist</text>
    <text class="arrow font-base" x="135" y="15" text-anchor="middle" font-size="12" font-weight="bold">↗</text>
  </g>
</svg>'''

    response = make_response(svg)
    response.content_type = "image/svg+xml"
    response.headers.update(
        {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        }
    )
    response.headers.pop("ETag", None)
    response.headers.pop("Last-Modified", None)
    return response
