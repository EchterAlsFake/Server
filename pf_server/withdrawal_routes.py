"""Public, two-stage withdrawal flow; no login or purchase-secret requirement."""
import json
from io import BytesIO

import click
from cryptography.fernet import InvalidToken
from flask import Blueprint, abort, current_app, render_template, request, send_file
from sqlalchemy.exc import SQLAlchemyError

from .extensions import db
from .models import WithdrawalRequest, WithdrawalDelivery
from . import withdrawal_service as service

withdrawal_bp = Blueprint("withdrawal", __name__)


@withdrawal_bp.after_request
def private_response(response):
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    return response


def form_page(error=None, values=None, status=200):
    return render_template("withdrawal.html", error=error, values=values or {}), status


def decode_submission():
    token = request.form.get("draft", "")
    try:
        return token, service.read_draft(token)
    except (InvalidToken, ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return None, None


@withdrawal_bp.get("/withdrawal")
def start():
    return form_page()


@withdrawal_bp.post("/withdrawal/preview")
def preview():
    try:
        details = service.validate_details(request.form)
    except ValueError as error:
        return form_page(str(error), request.form, 400)
    try:
        token = service.make_draft(details)
    except (ValueError, TypeError, AttributeError):
        current_app.logger.error("Withdrawal encryption is not configured")
        return form_page("The form is unavailable; nothing has been submitted. Email your withdrawal to support@echteralsfake.me.", details, 503)
    return render_template("withdrawal_review.html", values=details, draft=token, statement=service.STATEMENT)


@withdrawal_bp.post("/withdrawal/edit")
def edit():
    _, payload = decode_submission()
    if payload is None:
        return form_page("Please enter your details again.", status=400)
    return form_page(values=payload["details"])


@withdrawal_bp.post("/withdrawal/confirm")
def confirm():
    received_at = service.now()
    token, payload = decode_submission()
    if payload is None or request.form.get("confirm") != "withdraw":
        return form_page("Please review and confirm your details. No withdrawal was submitted.", status=400)
    try:
        row = service.receive(token, payload, received_at)
    except (SQLAlchemyError, ValueError, TypeError, AttributeError):
        db.session.rollback()
        current_app.logger.error("Could not persist withdrawal declaration")
        return render_template("withdrawal_review.html", values=payload["details"], draft=token,
            statement=payload["statement"], error="Receipt could not be confirmed. Retry or email support@echteralsfake.me."), 503
    reference = row.id
    service.deliver_received(reference)
    row = db.session.get(WithdrawalRequest, reference)
    delivery = db.session.get(WithdrawalDelivery, (reference, "consumer"))
    return render_template("withdrawal_received.html", reference=reference, draft=token,
        receipt=service.decrypt_receipt(row), email_sent=delivery.status == "sent")


@withdrawal_bp.post("/withdrawal/receipt")
def download_receipt():
    token = request.form.get("draft", "")
    if not token or len(token) > 16000:
        abort(404)
    row = service.find_received(token)
    if row is None:
        abort(404)
    return send_file(BytesIO(service.decrypt_receipt(row).encode()), as_attachment=True,
                     download_name="withdrawal-receipt.txt", mimetype="text/plain; charset=utf-8")


def register_withdrawal_commands(app):
    @app.cli.command("retry-withdrawal-deliveries")
    def retry_command():
        """Retry consumer receipts and support notifications; never process refunds."""
        click.echo(f"Processed {service.retry_deliveries()} withdrawal deliveries.")

    @app.cli.command("list-withdrawals")
    @click.option("--all-records", is_flag=True, help="Include manually reviewed declarations.")
    def list_command(all_records):
        """Local operator overview without names, emails or contract text."""
        query = db.select(WithdrawalRequest).order_by(WithdrawalRequest.received_at)
        if not all_records:
            query = query.where(WithdrawalRequest.reviewed_at.is_(None))
        for row in db.session.execute(query).scalars():
            deliveries = db.session.execute(db.select(WithdrawalDelivery).where(
                WithdrawalDelivery.request_id == row.id)).scalars().all()
            click.echo(json.dumps(dict(reference=row.id, received_at=row.received_at,
                reviewed_at=row.reviewed_at, deliveries={item.audience: item.status for item in deliveries})))

    @app.cli.command("show-withdrawal")
    @click.option("--reference", required=True)
    def show_command(reference):
        """Display personal declaration details locally for manual processing."""
        row = db.session.get(WithdrawalRequest, reference)
        if row is None:
            raise click.ClickException("Unknown receipt reference")
        click.echo(service.decrypt_receipt(row))

    @app.cli.command("mark-withdrawal-reviewed")
    @click.option("--reference", required=True)
    def reviewed_command(reference):
        """Mark manual review; does not decide validity, refund or revoke licenses."""
        row = db.session.get(WithdrawalRequest, reference)
        if row is None:
            raise click.ClickException("Unknown receipt reference")
        if row.reviewed_at is None:
            row.reviewed_at = service.now().isoformat()
            db.session.commit()
        click.echo("Marked reviewed. No refund or license change was performed.")
