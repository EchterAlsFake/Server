"""Health, statistics, runtime initialization, and administrative routes."""

from datetime import datetime, timezone

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    render_template,
    request,
)

from .ci_routes import get_all_ci_status
from .time_utils import rfc3339_utc

operations_bp = Blueprint("operations", __name__)


def increment_stats(requests_inc=0, bytes_in_inc=0, bytes_out_inc=0):
    current_app.extensions["request_statistics"].increment(
        requests_inc, bytes_in_inc, bytes_out_inc
    )


def get_stats_snapshot():
    return current_app.extensions["request_statistics"].snapshot()


def track_request():
    increment_stats(requests_inc=1, bytes_in_inc=max(request.content_length or 0, 0))


def track_response(response):
    # Never buffer a streamed response just to measure telemetry.
    length = response.content_length if response.is_streamed or response.direct_passthrough else response.calculate_content_length()
    increment_stats(bytes_out_inc=max(length or 0, 0))
    return response


def initialize_runtime_state(application):
    application.extensions["request_statistics"].reset()


def bytes_to_mb(num_bytes: int) -> float:
    return round(num_bytes / (1024 * 1024), 3)


@operations_bp.route("/ping", methods=["GET"])
def ping():
    return make_response("Success", 200)


@operations_bp.route("/stats", methods=["GET"])
def stats_endpoint():
    stats = get_stats_snapshot()
    started_at = stats["server_started_at"]
    try:
        started_at_datetime = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        if started_at_datetime.tzinfo is None:
            started_at_datetime = started_at_datetime.replace(tzinfo=timezone.utc)
    except (AttributeError, TypeError, ValueError):
        current_app.logger.warning(
            "Stored server start timestamp is invalid", exc_info=True
        )
        started_at_datetime = datetime.now(timezone.utc)

    stats_payload = {
        "server_started_at": rfc3339_utc(started_at_datetime),
        "uptime_seconds": int(
            (datetime.now(timezone.utc) - started_at_datetime).total_seconds()
        ),
        "requests": {"total": stats["total_requests"]},
        "traffic": {
            "bytes_in": stats["total_bytes_in"],
            "bytes_out": stats["total_bytes_out"],
            "mb_in": bytes_to_mb(stats["total_bytes_in"]),
            "mb_out": bytes_to_mb(stats["total_bytes_out"]),
        },
        "ci": {"tests": get_all_ci_status()},
    }

    wants_json = (
        "application/json" in (request.headers.get("Accept") or "")
        or request.args.get("format") == "json"
    )
    if wants_json:
        return jsonify(stats_payload), 200
    return render_template("stats.html", stats=stats_payload)
