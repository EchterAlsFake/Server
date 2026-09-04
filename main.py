"""Flask application factory and deployment entry point."""

import json
import logging
import os

import click

from dotenv import load_dotenv
from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler

from pf_server.checklist_routes import checklist_bp
from pf_server.ci_routes import ci_bp
from pf_server.config import load_environment_config
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
from pf_server.tax_service import country_transaction_summary
from pf_server.update_routes import updates_bp

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
    configure_logging(application)

    application.wsgi_app = ProxyFix(
        application.wsgi_app,
        x_for=0,
        x_proto=1,
        x_host=1,
        x_prefix=1,
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
    )

    db.init_app(application)
    csrf.init_app(application)
    limiter.init_app(application)
    migrate.init_app(application, db)
    talisman.init_app(
        application,
        force_https=False,
        content_security_policy={
            "default-src": ["'self'"],
            "img-src": ["'self'", "data:"],
            "style-src": ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"],
            "script-src": ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"],
            "connect-src": ["'self'"],
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
    )

    for blueprint in (
        pages_bp,
        payments_bp,
        docs_bp,
        updates_bp,
        operations_bp,
        ci_bp,
        checklist_bp,
    ):
        application.register_blueprint(blueprint)

    application.before_request(track_request)
    application.before_request(handle_docs_subdomain)
    application.after_request(track_response)
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

    if initialize_runtime:
        initialize_runtime_state(application)
    return application


app = create_app()


class NoIPLoggingHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        method = self.command
        path = self.path.partition("?")[0]
        logging.getLogger("pf_server.access").info("%s %s -> %s", method, path, code)


if __name__ == "__main__":
    initialize_runtime_state(app)
    app.run(host="127.0.0.1", port=8000, request_handler=NoIPLoggingHandler)
