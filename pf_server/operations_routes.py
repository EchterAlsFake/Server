"""Health, statistics, runtime initialization, and administrative routes."""

import fcntl
import hmac
import os
import subprocess
import threading
from datetime import datetime, timezone

from flask import (
    Blueprint,
    Flask,
    current_app,
    jsonify,
    make_response,
    render_template,
    request,
)
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

from .ci_routes import get_all_ci_status
from .extensions import csrf, db, limiter
from .models import Stats
from .time_utils import rfc3339_utc

operations_bp = Blueprint("operations", __name__)


def increment_stats(
    requests_inc: int = 0,
    bytes_in_inc: int = 0,
    bytes_out_inc: int = 0,
) -> None:
    """Atomically increment counters without breaking the handled request."""
    if not (requests_inc or bytes_in_inc or bytes_out_inc):
        return
    try:
        db.session.execute(
            sqlite_insert(Stats)
            .values(
                id=1,
                total_requests=0,
                total_bytes_in=0,
                total_bytes_out=0,
                server_started_at=datetime.now(timezone.utc).isoformat(),
            )
            .on_conflict_do_nothing(index_elements=[Stats.id])
        )
        statement = (
            db.update(Stats)
            .where(Stats.id == 1)
            .values(
                total_requests=Stats.total_requests + requests_inc,
                total_bytes_in=Stats.total_bytes_in + bytes_in_inc,
                total_bytes_out=Stats.total_bytes_out + bytes_out_inc,
            )
        )
        db.session.execute(statement)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.warning(
            "Could not update aggregate request statistics", exc_info=True
        )


def get_stats_snapshot() -> dict:
    stat = db.session.get(Stats, 1)
    if stat is None:
        started_at = datetime.now(timezone.utc).isoformat()
        stat = Stats(
            id=1,
            total_requests=0,
            total_bytes_in=0,
            total_bytes_out=0,
            server_started_at=started_at,
        )
        db.session.add(stat)
        db.session.commit()
    return {
        "total_requests": stat.total_requests,
        "total_bytes_in": stat.total_bytes_in,
        "total_bytes_out": stat.total_bytes_out,
        "server_started_at": stat.server_started_at,
    }


def track_request() -> None:
    content_length = max(int(request.content_length or 0), 0)
    increment_stats(requests_inc=1, bytes_in_inc=content_length)


def track_response(response):
    try:
        length = response.calculate_content_length()
        if length is None and not response.direct_passthrough:
            data = response.get_data()
            length = len(data) if data is not None else 0
    except Exception:
        current_app.logger.warning(
            "Could not determine response size for aggregate statistics",
            exc_info=True,
        )
        length = 0

    increment_stats(bytes_out_inc=max(int(length or 0), 0))
    return response


def initialize_runtime_state(application: Flask) -> None:
    """Create or reset process-lifetime counters after migrations are available."""
    with application.app_context():
        database_path = db.engine.url.database
        if not database_path or database_path == ":memory:":
            raise RuntimeError("Runtime state initialization requires a file-backed database")
        schema_lock_path = f"{os.path.abspath(database_path)}-schema.lock"
        with open(schema_lock_path, "a+", encoding="utf-8") as schema_lock:
            fcntl.flock(schema_lock.fileno(), fcntl.LOCK_EX)
            started_at = datetime.now(timezone.utc).isoformat()
            stat = db.session.get(Stats, 1)
            if stat is None:
                stat = Stats(
                    id=1,
                    total_requests=0,
                    total_bytes_in=0,
                    total_bytes_out=0,
                    server_started_at=started_at,
                )
                db.session.add(stat)
            else:
                stat.total_requests = 0
                stat.total_bytes_in = 0
                stat.total_bytes_out = 0
                stat.server_started_at = started_at
            db.session.commit()


def initiate_poweroff() -> None:
    """Invoke the host poweroff command asynchronously."""
    logger = current_app.logger
    logger.warning("Kill switch triggered; initiating system poweroff")

    def poweroff():
        try:
            subprocess.run(["poweroff"], check=True)
        except (OSError, subprocess.SubprocessError):
            logger.exception("Could not invoke system poweroff")

    threading.Thread(target=poweroff, daemon=True).start()


def bytes_to_mb(num_bytes: int) -> float:
    return round(num_bytes / (1024 * 1024), 3)


@operations_bp.route("/ping", methods=["GET"])
def ping():
    return make_response("Success", 200)


@operations_bp.route("/killswitch", methods=["POST"])
@csrf.exempt
@limiter.exempt
def killswitch():
    kill_token = current_app.config.get("KILL_TOKEN")
    if not kill_token:
        return jsonify({"error": "Kill switch token not configured on server."}), 500

    provided = request.headers.get("X-KILL-TOKEN") or request.args.get("token")
    if not provided and request.is_json:
        body = request.get_json(silent=True) or {}
        provided = body.get("token")

    if not isinstance(provided, str) or not hmac.compare_digest(provided, kill_token):
        return jsonify({"error": "Unauthorized"}), 401

    initiate_poweroff()
    return jsonify({"status": "ok", "message": "Shutdown initiated."}), 200


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
