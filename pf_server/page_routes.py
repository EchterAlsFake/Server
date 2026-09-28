"""Public HTML pages and the root age-confirmation form."""

from flask import (
    Blueprint,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

pages_bp = Blueprint("pages", __name__)


@pages_bp.route("/", methods=["GET", "POST"])
def landing_page():
    confirmed = request.method == "POST" and request.form.get("adult_confirmed") == "yes"
    if confirmed:
        response = redirect(url_for("pages.porn_fetch"), code=303)
    else:
        error = "Confirm that you are at least 18 years old to continue." if request.method == "POST" else None
        response = make_response(render_template("age_gate.html", error=error), 400 if error else 200)
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response.headers["Cache-Control"] = "private, no-store"
    return response


@pages_bp.route("/access", methods=["GET"])
def site_access():
    response = redirect(url_for("pages.landing_page"), code=302)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@pages_bp.route("/impress", methods=["GET"])
def impress():
    return render_template("impress.html")


@pages_bp.route("/transparency", methods=["GET"])
def transparency():
    return redirect("/docs/transparency/", code=301)


@pages_bp.route("/refund_policy", methods=["GET"])
def refund_policy():
    return render_template("refund_policy.html")


@pages_bp.route("/terms", methods=["GET"])
def terms():
    return render_template("terms.html")


@pages_bp.route("/porn_fetch", methods=["GET"])
def porn_fetch():
    return render_template("porn_fetch.html")


@pages_bp.route("/donation", methods=["GET"])
def donation():
    return render_template("donation.html")


@pages_bp.route("/datenschutz", methods=["GET"])
def datenschutz():
    return render_template("privacy_policy_de.html")


@pages_bp.route("/privacy_policy", methods=["GET"])
def privacy_policy():
    return render_template("privacy_policy_en.html")


@pages_bp.route("/legal-statement", methods=["GET"])
def legal_compliance():
    return render_template("legal-statement.html")
