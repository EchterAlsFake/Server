"""Database-backed CI status API and SVG badge routes."""

import hmac
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from flask import Blueprint, current_app, jsonify, make_response, request

from .extensions import csrf, db, limiter
from .models import CiStatus
from .time_utils import rfc3339_utc

ci_bp = Blueprint("ci", __name__)
VALID_CI_STATUSES = {"pass", "fail", "running", "unknown"}


def check_ci_auth() -> bool:
    token = current_app.config.get("CI_TOKEN")
    if not token:
        return False
    provided = request.headers.get("X-CI-TOKEN") or request.args.get("token")
    return isinstance(provided, str) and hmac.compare_digest(provided, token)


def set_ci_status(test_name, status, details=None):
    normalized_status = str(status).lower()
    if normalized_status not in VALID_CI_STATUSES:
        normalized_status = "unknown"

    updated_at = datetime.now(timezone.utc).isoformat()
    details_text = str(details) if details is not None else None
    entry = {
        "name": test_name,
        "status": normalized_status,
        "updated_at": rfc3339_utc(updated_at),
    }
    if details_text is not None:
        entry["details"] = details_text

    ci_status = db.session.get(CiStatus, test_name)
    if ci_status is None:
        ci_status = CiStatus(
            test_name=test_name,
            status=normalized_status,
            updated_at=updated_at,
            details=details_text,
        )
        db.session.add(ci_status)
    else:
        ci_status.status = normalized_status
        ci_status.updated_at = updated_at
        ci_status.details = details_text
    db.session.commit()
    return entry


def get_ci_status(test_name):
    ci_status = db.session.get(CiStatus, test_name)
    if ci_status is None:
        return {
            "name": test_name,
            "status": "unknown",
            "updated_at": None,
            "details": "no result reported yet",
        }
    return {
        "name": ci_status.test_name,
        "status": ci_status.status,
        "updated_at": rfc3339_utc(ci_status.updated_at) if ci_status.updated_at else None,
        "details": ci_status.details,
    }


def get_all_ci_status():
    return [
        {
            "name": ci_status.test_name,
            "status": ci_status.status,
            "updated_at": rfc3339_utc(ci_status.updated_at) if ci_status.updated_at else None,
            "details": ci_status.details,
        }
        for ci_status in CiStatus.query.order_by(CiStatus.test_name.asc()).all()
    ]


def generate_ci_badge_svg(test_name, status):
    label_text = test_name.replace("_", " ")
    label = escape(label_text)
    value = status.upper()

    def text_width(text):
        return 6 * len(text) + 10

    left_width = max(text_width(label_text), 40)
    right_width = max(text_width(value), 40)
    total_width = left_width + right_width
    colors = {
        "pass": "#4c1",
        "fail": "#e05d44",
        "running": "#dfb317",
    }
    color = colors.get(status, "#9f9f9f")

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {value}">
  <linearGradient id="smooth" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".7"/>
    <stop offset=".1" stop-color="#aaa" stop-opacity=".1"/>
    <stop offset=".9" stop-color="#000" stop-opacity=".3"/>
    <stop offset="1" stop-color="#000" stop-opacity=".5"/>
  </linearGradient>
  <mask id="round"><rect width="{total_width}" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#round)">
    <rect width="{left_width}" height="20" fill="#555"/>
    <rect x="{left_width}" width="{right_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#smooth)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{left_width / 2}" y="14">{label}</text>
    <text x="{left_width + right_width / 2}" y="14">{value}</text>
  </g>
</svg>"""
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


@ci_bp.route("/ci/<test_name>", methods=["POST"])
@csrf.exempt
@limiter.limit("10000 per minute")
def ci_update(test_name):
    if not current_app.config.get("CI_TOKEN"):
        return jsonify({"error": "CI token is not configured"}), 503
    if not check_ci_auth():
        return jsonify({"error": "Unauthorized"}), 401
    if not request.is_json:
        return jsonify({"error": "Expected JSON"}), 400

    payload = request.get_json() or {}
    status = payload.get("status")
    if not status:
        return jsonify({"error": "Missing 'status' field"}), 400
    return jsonify(set_ci_status(test_name, status, payload.get("details"))), 200


@ci_bp.route("/ci/<test_name>", methods=["GET"])
def ci_plain(test_name):
    response = make_response(get_ci_status(test_name)["status"].upper(), 200)
    response.mimetype = "text/plain"
    return response


@ci_bp.route("/ci/<test_name>.json", methods=["GET"])
def ci_json(test_name):
    return jsonify(get_ci_status(test_name)), 200


@ci_bp.route("/ci/<test_name>/badge.svg", methods=["GET"])
def ci_badge(test_name):
    entry = get_ci_status(test_name)
    return generate_ci_badge_svg(test_name, entry["status"])
