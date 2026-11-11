"""Flask application factory and deployment entry point."""

import json
import logging
import os
import secrets

import click

from dotenv import load_dotenv
from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler

from pf_server.checklist_routes import checklist_bp
from pf_server.ci_routes import ci_bp
from pf_server.config import load_environment_config
from pf_server.http import TrustedHostMiddleware
from pf_server.statistics import RequestStatistics
from pf_server.aggregate_analytics import init_aggregate_analytics
from pf_server.direct_downloads import init_direct_downloads
from pf_server.country_service import CheckoutCountryMiddleware, LocalCountryResolver
from pf_server.docs_routes import docs_bp, handle_docs_subdomain
from pf_server.extensions import csrf, db, limiter, migrate, talisman
from pf_server.logging_config import configure_logging
from pf_server.operations_routes import (
    initialize_runtime_state,
    operations_bp,
    track_request,
    track_response,
)
from pf_server.page_routes import pages_bp
from pf_server.payment_routes import payments_bp
from pf_server.onramp_routes import onramp_bp
from pf_server.withdrawal_routes import withdrawal_bp, register_withdrawal_commands
from pf_server.referral_guard import block_vplan_referrals
from pf_server.seo_routes import seo_bp
from pf_server.guide_routes import guides_bp
from pf_server.tax_service import country_transaction_summary
from pf_server.update_routes import updates_bp
from pf_server.website_releases import releases_bp
from pf_server.download_pages import downloads_bp
from pf_server.onion import init_onion
from pf_server.tor_checkout import init_tor_checkout
from pf_server.android_updates import android_updates_bp

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def ratelimit_handler(_error):
    return jsonify({"error": "Rate limit exceeded. Try again later."}), 429


def payload_too_large(_error):
    return jsonify({"error": "Payload too large. Max 200KB allowed."}), 413


def create_app(
    test_config: dict | None = None, *, initialize_runtime: bool = False
) -> Flask:
    """Build and configure an isolated Flask application instance."""
    application = Flask(__name__)
    application.config.from_mapping(load_environment_config(BASE_DIR))
    if test_config:
        application.config.update(test_config)
    application.extensions["request_statistics"] = RequestStatistics(application)
    init_onion(application)
    init_tor_checkout(application)
    configure_logging(application)
    application.extensions["vplan_referral_key"] = secrets.token_bytes(32)
    application.before_request(block_vplan_referrals)

    application.wsgi_app = TrustedHostMiddleware(application.wsgi_app, application.config["TRUSTED_HOSTS"])
    application.wsgi_app = ProxyFix(
        application.wsgi_app,
        x_for=0,
        x_proto=1,
        x_host=0,
        x_prefix=0,
    )
    country_resolver = LocalCountryResolver(
        application.config["GEOIP_DATABASE_PATH"],
        application.config["GEOIP_DATABASE_LABEL"],
    )
    application.extensions["country_resolver"] = country_resolver
    application.wsgi_app = CheckoutCountryMiddleware(
        application.wsgi_app,
        country_resolver,
        application.config["CHECKOUT_IP_HEADER"],
        application.extensions["tor_resolver"],
    )

    init_direct_downloads(application)
    db.init_app(application)
    csrf.init_app(application)
    limiter.init_app(application)
    init_aggregate_analytics(application)
    migrate.init_app(application, db)
    talisman.init_app(
        application,
        force_https=False,
        content_security_policy_nonce_in=["script-src"],
        content_security_policy={
            "default-src": ["'self'"],
            "img-src": ["'self'", "data:"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "script-src": ["'self'"],
            "connect-src": ["'self'", application.config["DIRECT_DOWNLOAD_ORIGIN"]],
            "frame-src": ["'self'", "https://nowpayments.io"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
            "frame-ancestors": ["'none'"],
        },
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        x_content_type_options=True,
        x_xss_protection=True,
        session_cookie_secure=True,
        session_cookie_http_only=True,
        session_cookie_samesite="Lax",
        referrer_policy="no-referrer",
    )

    for blueprint in (
        pages_bp,
        payments_bp,
        onramp_bp,
        withdrawal_bp,
        seo_bp,
        guides_bp,
        docs_bp,
        updates_bp,
        operations_bp,
        ci_bp,
        checklist_bp,
        releases_bp,
        downloads_bp,
        android_updates_bp,
    ):
        application.register_blueprint(blueprint)

    application.before_request(track_request)
    application.before_request(handle_docs_subdomain)
    application.after_request(track_response)

    @application.after_request
    def private_payment_response(response):
        from flask import request
        if request.path.startswith('/activate') or request.path in {
            "/activate", "/buy_card", "/buy_success", "/download_license", "/download_contract", "/download_invoice",
            "/check-payment-status", "/onramp-acknowledgment", "/create-onramp-payment",
            "/onramp-callback", "/download-recovery", "/create-crypto-payment",
            "/payment-preview/banxa",
        }:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response
    application.register_error_handler(429, ratelimit_handler)
    application.register_error_handler(413, payload_too_large)

    @application.cli.command("init-runtime")
    def init_runtime_command():
        """Reset process-lifetime aggregate counters after migrations run."""
        initialize_runtime_state(application)

    @application.cli.command("tax-country-summary")
    @click.option("--year", type=click.IntRange(2000, 9999), required=True)
    def tax_country_summary_command(year: int):
        """Print country-level completed transaction totals as JSON."""
        click.echo(json.dumps(country_transaction_summary(year), indent=2))

    @application.cli.command("verify-license-policy")
    @click.option("--client-config", type=click.Path(exists=True, dir_okay=False), required=True)
    def verify_license_policy_command(client_config):
        """Read-only check of lifetime entitlement and the shipped client policy ID."""
        from pf_server.keygen_service import KeygenUnavailable, verify_lifetime_policy
        try:
            with open(client_config, encoding="utf-8") as source:
                public_client = json.load(source)
            if public_client["policy_id"] != application.config["KEYGEN_POLICY_ID"]:
                raise click.ClickException("Server and client policy IDs do not match")
            verify_lifetime_policy()
        except (OSError, ValueError, KeyError, TypeError, KeygenUnavailable):
            raise click.ClickException("Could not verify the lifetime policy and client configuration") from None
        click.echo("Verified: non-expiring lifetime Premium, all future releases, ten installations; client policy matches.")

    @application.cli.command("request-sandbox-payment")
    @click.option("--order-id", required=True)
    def request_sandbox_payment_command(order_id):
        """Request provider-side success emulation for an existing sandbox invoice."""
        from pf_server.nowpayments_service import PaymentProviderError, request_sandbox_invoice_payment
        try:
            request_sandbox_invoice_payment(order_id)
        except PaymentProviderError as error:
            raise click.ClickException(str(error)) from None
        click.echo("Sandbox emulation requested. Await NOWPayments' signed webhook on the recovery page. No local payment was approved.")

    @application.cli.command("process-nowpayments-receipts")
    def process_nowpayments_receipts_command():
        """Fulfill durable signed payment receipts outside the webhook request."""
        from pf_server.payment_receipts import process_receipts
        click.echo(f"Processed {process_receipts()} authenticated payment receipts.")

    @application.cli.command("verify-patreon-shop")
    def verify_patreon_shop_command():
        """Read-only complete sales scan; prints counts, never buyer details."""
        from pf_server.patreon_shop import fetch_sales, VerificationUnavailable
        if not application.config.get('PATREON_SHOP_PRODUCT_VARIANT_ID'):
            raise click.ClickException('Configure PATREON_SHOP_PRODUCT_VARIANT_ID first')
        try:
            sales = fetch_sales()
        except VerificationUnavailable as error:
            raise click.ClickException('Verification unavailable: ' + error.reason) from None
        receipts = sum(bool(row[3] and len(row) > 4 and row[4]) for row in sales)
        click.echo(f"Complete scan: {len(sales)} orders; {sum(row[3] for row in sales)} eligible; {receipts} eligible with receipt IDs for browser retrieval.")

    @application.cli.command("update-tor-exits")
    def update_tor_exits_command():
        """Refresh the local payment blocklist from the Tor Project."""
        from pf_server.tor_checkout import update_exit_list
        try:
            count = update_exit_list(application.config["TOR_EXIT_LIST_PATH"])
        except Exception:
            raise click.ClickException("Tor exit refresh failed; the previous list was preserved") from None
        click.echo(f"Updated Tor payment blocklist: {count} addresses.")

    @application.cli.command("process-patreon-shop")
    def process_patreon_shop_command():
        """Verify queued Shop claims and retry durable email delivery."""
        from pf_server.patreon_shop import process_claims
        click.echo(f"Processed {process_claims()} Patreon Shop claims.")

    @application.cli.command("retry-crypto-deliveries")
    def retry_crypto_deliveries_command():
        """Retry crypto delivery and purge expired checkout evidence."""
        from pf_server.crypto_delivery import retry_crypto_deliveries
        from pf_server.contracts import purge_checkout_agreements
        purge_checkout_agreements()
        click.echo(f"Processed {retry_crypto_deliveries()} crypto delivery candidates.")

    @application.cli.command("retry-onramp-deliveries")
    def retry_onramp_deliveries_command():
        """Purge expired checkout PII and retry confirmed card-license emails."""
        from pf_server.onramp_service import retry_deliveries
        click.echo(f"Processed {retry_deliveries()} delivery candidates.")

    register_withdrawal_commands(application)

    if initialize_runtime:
        initialize_runtime_state(application)
    return application


app = create_app()


class NoIPLoggingHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        if self.path.partition("?")[0] == "/_metrics/event":
            return
        method = self.command
        path = self.path.partition("?")[0]
        logging.getLogger("pf_server.access").info("%s %s -> %s", method, path, code)


if __name__ == "__main__":
    initialize_runtime_state(app)
    app.run(host="127.0.0.1", port=8000, request_handler=NoIPLoggingHandler)
