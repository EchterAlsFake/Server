"""Versioned checkout evidence and immutable contract confirmations."""
import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from flask import abort, current_app, jsonify
from fpdf import FPDF
from sqlalchemy import update

from .extensions import db
from .models import CheckoutAgreement, Transaction
from .website_locale import language, translate, use_language

VERSION = "contract-2026-11-17-v1"
IMMEDIATE_EN = "I expressly consent to immediate digital supply before the 14-day withdrawal period ends. I understand that I lose my withdrawal right when supply starts, provided I receive the required contract confirmation."
REFUND_EN = "I expressly agree to cryptocurrency refunds under the separate refund agreement, at no cost to me."
AGE_TERMS = "I am 18+ and accept the %(terms)s."
TEST_NOTICE = "I understand this is a test checkout. No real purchase."


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
    def handle_data(self, data):
        self.parts.append(data)
    def handle_endtag(self, tag):
        if tag in {"p", "li", "h1", "h2", "h3", "div", "section"}:
            self.parts.append("\n\n")
    def handle_starttag(self, tag, attrs):
        if tag == "br":
            self.parts.append("\n")


def text_template(name, **context):
    from .offer import PREMIUM_PRICE_TEXT
    context.setdefault("premium_price", PREMIUM_PRICE_TEXT)
    parser = PlainText()
    parser.feed(current_app.jinja_env.get_template(name).render(**context))
    return "\n".join(line.strip() for line in "".join(parser.parts).splitlines() if line.strip())


def terms_snapshot():
    with use_language("en"):
        return english_terms_snapshot()


def english_terms_snapshot():
    return {
        "version": VERSION,
        "language": "en",
        "product": text_template("partials/contract_product.html"),
        "terms_de": "",  # Retain the field for older snapshot readers.
        "terms_en": text_template("partials/terms_en.html"),
        "withdrawal": text_template("partials/withdrawal_information.html"),
        "immediate_en": IMMEDIATE_EN,
        "refund_en": REFUND_EN,
        "refund_terms": text_template("partials/refund_agreement.html"),
    }


def dumps(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def offer_digest():
    return hashlib.sha256(dumps(terms_snapshot()).encode()).hexdigest()


def record_agreement(method, country, accepted_at, *, shared_locale=None):
    snapshot = terms_snapshot()
    snapshot.update(payment_method=method, country=country, accepted_at=accepted_at,
                    terms_accepted=True, age_confirmed=True,
                    refund_method_accepted=True,
                    immediate_supply_consent=method != "patreon",
                    withdrawal_acknowledged=method != "patreon")
    shared_locale = shared_locale or language()
    if shared_locale != "en" or (method != "patreon" and language() != "en"):
        snapshot["presentation"] = presentation(method, shared_locale, language())
    row = CheckoutAgreement(id=secrets.token_urlsafe(24), snapshot=dumps(snapshot), created_at=accepted_at)
    db.session.add(row)
    db.session.commit()
    return row.id


def presentation(method, shared_locale, supply_locale):
    with use_language(shared_locale):
        details = {
            "language": shared_locale,
            "age_terms": translate(AGE_TERMS, terms=translate("Terms of Service")),
            "refund": translate(REFUND_EN),
            "product": text_template("partials/contract_product.html"),
            "refund_terms": text_template("partials/refund_agreement.html"),
        }
        if current_app.config["NOWPAYMENTS_SANDBOX"]:
            details["test_notice"] = translate(TEST_NOTICE)
    if method != "patreon":
        with use_language(supply_locale):
            details["supply_language"] = supply_locale
            details["immediate"] = translate(IMMEDIATE_EN)
            details["withdrawal"] = text_template("partials/withdrawal_information.html")
    return details

def checkout_snapshot(method, country):
    from .checkout_consent import current_consent
    consent = current_consent()
    if not consent or consent.get("payment_method") != method or consent.get("country") != country or consent.get("offer_digest") != offer_digest():
        response = jsonify(error=translate("Review and accept the checkout information again before paying."))
        response.status_code = 409
        abort(response)
    row = db.session.get(CheckoutAgreement, consent.get("agreement_id"))
    if row is None:
        response = jsonify(error=translate("Checkout agreement is missing. Start checkout again."))
        response.status_code = 409
        abort(response)
    saved = json.loads(row.snapshot)
    if any(saved.get(key) != value for key, value in terms_snapshot().items()):
        response = jsonify(error=translate("The contract information has changed. Review and accept it again before paying."))
        response.status_code = 409
        abort(response)
    return row.snapshot


def agreement_receipt(agreement):
    """Customer-held evidence; does not assert identity or a completed purchase."""
    data = json.loads(agreement.snapshot)
    if data.get("presentation"):
        return render_pdf(localized_agreement(data, agreement.id))
    if data.get("language") == "en":
        body = (
            "Checkout agreement receipt\n"
            f"Reference: {agreement.id}\n"
            f"Accepted (UTC): {data['accepted_at']}\n"
            f"Terms version: {data['version']}\n"
            f"Payment route: {data['payment_method']}\n"
            "Age 18+ and English terms confirmed. This is not proof of payment.\n"
        )
        if data.get("immediate_supply_consent") and data.get("withdrawal_acknowledged"):
            body += data["immediate_en"] + "\n"
        if data.get("refund_method_accepted"):
            body += "Separately accepted: " + data["refund_en"] + "\n"
        if data["payment_method"] == "patreon":
            body += "Not automatically linked to a Patreon Shop purchase. Keep this receipt as consent evidence.\n"
        return render_pdf(body + english_contract_text(data))
    body = ("Zustimmungsbeleg / Checkout agreement receipt\n"
            f"Referenz / Reference: {agreement.id}\n"
            f"Zeitpunkt / Time (UTC): {data['accepted_at']}\n"
            f"Textfassung / Version: {data['version']}\n"
            f"Zahlungsweg / Payment route: {data['payment_method']}\n"
            "Dieser Beleg dokumentiert die Erklärungen dieser Browsersitzung, keinen Kauf oder Zahlungseingang.\n"
            "This receipt records declarations in this browser session, not a purchase or payment.\n"
            "Volljährigkeit und AGB ausdrücklich bestätigt. / Age and Terms expressly accepted.\n")
    if data.get("immediate_supply_consent") and data.get("withdrawal_acknowledged"):
        body += data["immediate_de"] + "\n" + data["immediate_en"] + "\n"
    if data.get("refund_method_accepted"):
        body += "Gesondert bestätigt / Separately accepted:\n" + data["refund_de"] + "\n" + data["refund_en"] + "\n"
    if data["payment_method"] == "patreon":
        body += ("Keine automatische Zuordnung zu einem Patreon-Shop-Kauf. Bewahren Sie diesen Beleg auf; "
                 "ohne zuordenbaren Nachweis wird die abweichende Erstattung im Einzelfall vereinbart.\n"
                 "Not automatically linked to a Patreon Shop purchase. Keep this receipt; without attributable "
                 "evidence, an alternative refund method must be agreed individually.\n")
    for field in ("product", "terms_de", "terms_en", "withdrawal", "refund_terms"):
        if data.get(field):
            body += "\n" + data[field] + "\n"
    return render_pdf(body)


def english_contract_text(data):
    """Each accepted section appears once; never substitute current website text."""
    return "\n" + "\n\n".join(data[field] for field in (
        "product", "terms_en", "refund_terms", "withdrawal"
    ) if data.get(field))


def localized_agreement(data, reference, transaction=None):
    presented = data["presentation"]
    with use_language(presented["language"]):
        if transaction:
            lines = [
                translate("Contract confirmation"),
                translate("Order: %(order)s", order=reference),
                translate("License price: %(amount)s %(currency)s",
                          amount=transaction.expected_price_amount, currency=transaction.expected_price_currency.upper()),
                translate("Existing license renewal" if transaction.renewal_license_id else "New Premium license"),
            ]
        else:
            lines = [translate("Checkout agreement receipt"), translate("Reference: %(reference)s", reference=reference)]
        lines.extend((
            translate("Accepted (UTC): %(date)s", date=data["accepted_at"]),
            translate("Terms version: %(version)s", version=data["version"]),
            translate("Payment route: %(method)s", method=data["payment_method"]),
        ))
        if not transaction:
            lines.append(translate("This receipt records your declarations and does not confirm payment."))
        elif transaction.environment == "sandbox":
            lines.append(translate("SANDBOX TEST - NO REAL PURCHASE"))
        if data["payment_method"] == "patreon":
            lines.append(translate("Not automatically linked to a Patreon Shop purchase. Keep this receipt as consent evidence."))
        lines.append(presented["age_terms"])
        if presented.get("test_notice"):
            lines.append(presented["test_notice"])
        if data.get("refund_method_accepted"):
            lines.append(presented["refund"])
        if data.get("immediate_supply_consent") and presented.get("immediate"):
            lines.append(presented["immediate"])
        sections = (presented["product"], data["terms_en"], presented["refund_terms"], presented.get("withdrawal"))
        return "\n".join(lines) + "\n\n" + "\n\n".join(section for section in sections if section)


def render_pdf(body):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    fonts = Path(__file__).resolve().parents[1] / "i18n" / "fonts"
    unicode_fonts = []
    if re.search(r"[\u0900-\u097f]", body):
        unicode_fonts.append(("Noto Devanagari", "NotoSansDevanagari.ttf"))
    if re.search(r"[\u2e80-\u9fff\uff00-\uffef]", body):
        unicode_fonts.append(("Noto SC", "NotoSansSC.ttf"))
    for family, filename in unicode_fonts:
        pdf.add_font(family, fname=fonts / filename)
    pdf.add_page()
    body = body.replace("→", "->").replace("↗", "").replace("—", "-")
    if unicode_fonts:
        pdf.set_font(unicode_fonts[0][0], size=10)
        pdf.set_fallback_fonts([family for family, _ in unicode_fonts[1:]])
        pdf.set_text_shaping(True)
    else:
        pdf.core_fonts_encoding = "cp1252"
        pdf.set_font("Helvetica", size=10)
        body = body.encode("cp1252", errors="replace").decode("cp1252")
    for line in body.splitlines():
        pdf.multi_cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())


def confirmation(transaction):
    if not transaction.contract_snapshot:
        return None  # Never invent historical consent.
    if transaction.status != "finished":
        raise ValueError("Contract confirmation requires verified payment")
    if transaction.confirmation_pdf:
        return transaction.confirmation_pdf
    data = json.loads(transaction.contract_snapshot)
    if data.get("presentation"):
        body = localized_agreement(data, transaction.session_id, transaction)
    elif data.get("language") == "en":
        body = (
            "Contract confirmation\n"
            f"Order: {transaction.session_id}\n"
            f"License price: {transaction.expected_price_amount} {transaction.expected_price_currency.upper()}\n"
            f"Supply: {'Existing license renewal' if transaction.renewal_license_id else 'New Premium license'}\n"
            f"Payment route: {data['payment_method']}\n"
            f"Accepted (UTC): {data['accepted_at']}\n"
            f"Terms version: {data['version']}\n"
            "Age 18+ and English terms confirmed.\n"
        )
        if transaction.environment == "sandbox":
            body += "SANDBOX TEST - NO REAL PURCHASE\n"
        if data.get("immediate_supply_consent") and data.get("withdrawal_acknowledged"):
            body += "Express consent and acknowledgment recorded:\n" + data['immediate_en'] + "\n"
        if data.get("refund_method_accepted"):
            body += "Refund method separately accepted: " + data["refund_en"] + "\n"
        body += english_contract_text(data)
    else:
        body = legacy_confirmation_text(transaction, data)
    payload = render_pdf(body)
    db.session.execute(update(Transaction).where(Transaction.session_id == transaction.session_id,
        Transaction.confirmation_pdf.is_(None)).values(confirmation_pdf=payload))
    db.session.commit()
    db.session.refresh(transaction)
    return transaction.confirmation_pdf


def legacy_confirmation_text(transaction, data):
    """Pending older purchases retain their accepted bilingual wording."""
    body = f"Vertragsbestätigung / Contract confirmation\nBestellung / Order: {transaction.session_id}\n"
    body += f"Zahlungsbestätigung verarbeitet / Payment confirmation processed (UTC): {transaction.finished_at}\n"
    body += "Dieser technische Zeitpunkt ersetzt nicht den tatsächlichen Zahlungseingang / This processing timestamp does not replace the actual payment time.\n"
    if transaction.environment == "sandbox":
        body += "SANDBOX TEST - KEIN ECHTER KAUF / NO REAL PURCHASE\n"
    body += f"Lizenzpreis / License price: {transaction.expected_price_amount} {transaction.expected_price_currency.upper()}\n"
    if transaction.renewal_license_id:
        body += "Leistung / Supply: Verlängerung der bestehenden Lizenz / Renewal of the existing license\n"
    else:
        body += "Leistung / Supply: Neue Premium-Lizenz / New Premium license\n"
    body += f"Zahlungsweg / Payment route: {data['payment_method']}\n"
    body += "Bei Banxa sind Kryptokauf und Lizenzkauf getrennte Vorgänge. / Banxa's cryptocurrency purchase is separate from the license purchase.\n"
    body += "Bestätigte Erklärungen / Recorded declarations\n"
    body += f"Zeitpunkt / Time (UTC): {data['accepted_at']}\nTextfassung / Version: {data['version']}\n"
    body += "Volljährigkeit und AGB ausdrücklich bestätigt. / Age and Terms expressly accepted.\n"
    body += data['immediate_de'] + "\n" + data['immediate_en'] + "\n"
    body += "Beide Erklärungen ausdrücklich bestätigt. Die Bestätigung allein behauptet kein bereits eingetretenes Erlöschen. / Both declarations expressly confirmed. This confirmation alone does not assert that the right has already expired.\n"
    if data.get("refund_method_accepted"):
        body += "Erstattungsweg gesondert bestätigt / Refund method separately accepted:\n"
        body += data["refund_de"] + "\n" + data["refund_en"] + "\n" + data["refund_terms"] + "\n"
    for field in ("product", "terms_de", "terms_en", "withdrawal"):
        body += "\n" + data[field] + "\n"
    return body




def purge_checkout_agreements():
    """One-hour browser consent expires; orders retain their own full copy."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    db.session.execute(db.delete(CheckoutAgreement).where(CheckoutAgreement.created_at < cutoff))
    db.session.commit()
