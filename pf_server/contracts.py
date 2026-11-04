"""Versioned checkout evidence and immutable, bilingual delivery documents."""
import hashlib
import json
import secrets
from datetime import datetime, timezone
from html.parser import HTMLParser

from flask import abort, current_app, jsonify
from fpdf import FPDF
from sqlalchemy import update

from .extensions import db
from .models import CheckoutAgreement, Transaction, PatreonLicenseDelivery

VERSION = "contract-2026-11-04-v5"
IMMEDIATE_EN = "I expressly agree to digital delivery before the withdrawal period ends. I understand that my withdrawal right ends when delivery starts, once I receive the contract confirmation."
IMMEDIATE_DE = "Ich stimme ausdrücklich zu, dass vor Ablauf der Widerrufsfrist mit der Bereitstellung der digitalen Inhalte begonnen wird. Mir ist bekannt, dass mein Widerrufsrecht mit Beginn der Vertragsausführung erlischt, sofern mir die gesetzlich erforderliche Vertragsbestätigung zur Verfügung gestellt wurde."
REFUND_EN = "I expressly agree to cryptocurrency refunds under the separate refund agreement, at no cost to me."
REFUND_DE = "Ich vereinbare ausdrücklich Krypto-Erstattungen für die Porn-Fetch-Lizenz nach der gesonderten Erstattungsvereinbarung, auch bei über Banxa finanzierten Zahlungen. Patreon-Zahlungen werden innerhalb von 90 Tagen über Patreon auf das ursprüngliche Zahlungsmittel erstattet; danach gilt die Krypto-Erstattung nach dieser Vereinbarung. Der Anbieter trägt die Erstattungskosten. Meine gesetzlichen Ansprüche und Fristen bleiben unverändert."


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


def text_template(name):
    parser = PlainText()
    parser.feed(current_app.jinja_env.get_template(name).render())
    return "\n".join(line.strip() for line in "".join(parser.parts).splitlines() if line.strip())


def terms_snapshot():
    return {
        "version": VERSION,
        "product": text_template("partials/contract_product.html"),
        "terms_de": text_template("partials/terms_de.html"),
        "terms_en": text_template("partials/terms_en.html"),
        "withdrawal": text_template("partials/withdrawal_information.html"),
        "immediate_en": IMMEDIATE_EN,
        "immediate_de": IMMEDIATE_DE,
        "refund_en": REFUND_EN,
        "refund_de": REFUND_DE,
        "refund_terms": text_template("partials/refund_agreement.html"),
    }


def dumps(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def offer_digest():
    return hashlib.sha256(dumps(terms_snapshot()).encode()).hexdigest()


def record_agreement(method, country, accepted_at):
    snapshot = terms_snapshot()
    snapshot.update(payment_method=method, country=country, accepted_at=accepted_at,
                    terms_accepted=True, age_confirmed=True,
                    refund_method_accepted=True,
                    immediate_supply_consent=method != "patreon",
                    withdrawal_acknowledged=method != "patreon")
    row = CheckoutAgreement(id=secrets.token_urlsafe(24), snapshot=dumps(snapshot), created_at=accepted_at)
    db.session.add(row)
    db.session.commit()
    return row.id


def checkout_snapshot(method, country):
    from .checkout_consent import current_consent
    consent = current_consent()
    if not consent or consent.get("payment_method") != method or consent.get("country") != country:
        response = jsonify(error="Review and accept the checkout information again before paying.")
        response.status_code = 409
        abort(response)
    row = db.session.get(CheckoutAgreement, consent.get("agreement_id"))
    if row is None:
        response = jsonify(error="Checkout agreement is missing. Start checkout again.")
        response.status_code = 409
        abort(response)
    return row.snapshot


def agreement_receipt(agreement):
    """Customer-held evidence; does not assert identity or a completed purchase."""
    data = json.loads(agreement.snapshot)
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
        body += ("Keine automatische Zuordnung zu einer Patreon-Mitgliedschaft. Bewahren Sie diesen Beleg auf; "
                 "ohne zuordenbaren Nachweis wird die abweichende Erstattung im Einzelfall vereinbart.\n"
                 "Not automatically linked to a Patreon membership. Keep this receipt; without attributable "
                 "evidence, an alternative refund method must be agreed individually.\n")
    for field in ("product", "terms_de", "terms_en", "withdrawal", "refund_terms"):
        if data.get(field):
            body += "\n" + data[field] + "\n"
    return render_pdf(body)


def render_pdf(body):
    # The document uses German/English Latin characters; preserve typographic quotes.
    pdf = FPDF()
    pdf.core_fonts_encoding = "cp1252"
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=10)
    body = body.replace("→", "->").replace("↗", "").replace("—", "-")
    for line in body.splitlines():
        pdf.multi_cell(0, 5, line.encode("cp1252", errors="replace").decode("cp1252"), new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())


def confirmation(transaction):
    if not transaction.contract_snapshot:
        return None  # Never invent historical consent.
    if transaction.status != "finished":
        raise ValueError("Contract confirmation requires verified payment")
    if transaction.confirmation_pdf:
        return transaction.confirmation_pdf
    data = json.loads(transaction.contract_snapshot)
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
    payload = render_pdf(body)
    db.session.execute(update(Transaction).where(Transaction.session_id == transaction.session_id,
        Transaction.confirmation_pdf.is_(None)).values(confirmation_pdf=payload))
    db.session.commit()
    db.session.refresh(transaction)
    return transaction.confirmation_pdf


def patreon_confirmation(delivery):
    if delivery.confirmation_pdf:
        return delivery.confirmation_pdf
    # This is a license benefit confirmation, not a fabricated membership contract.
    body = ("Bestätigung der Lizenzleistung / License benefit confirmation\n"
        f"Patreon-Mitgliedsreferenz / Member reference: {delivery.member_id}\n"
        f"Lizenzzuordnung erfasst / License assignment recorded (UTC): {delivery.created_at}\n"
        "Die Berechtigung wurde anhand eines signierten Patreon-Webhooks geprüft.\n"
        "Eligibility was checked using a signed Patreon webhook.\n"
        "Es ist keine Zustimmung zum vorzeitigen Erlöschen des Widerrufsrechts nachgewiesen.\n"
        "No consent to early expiry of withdrawal rights has been established.\n"
        "Diese Bestätigung erklärt keinen Verlust des Widerrufsrechts.\n"
        "This confirmation does not declare loss of withdrawal rights.\n"
        "Eine gesonderte Krypto-Erstattungsvereinbarung ist durch diesen Webhook nicht nachgewiesen.\n"
        "This webhook does not establish a separate cryptocurrency refund agreement.\n"
        "Ohne zuordenbaren Nachweis wird ein abweichender Erstattungsweg im Einzelfall vereinbart.\n"
        "Without attributable evidence, an alternative refund method must be agreed individually.\n"
        "Den Mitgliedschaftsvertrag, Tarifpreis, Währung, Abrechnungsintervall und Zahlungsbeleg bestätigt Patreon.\n"
        "Patreon confirms your membership contract, tier price, currency, billing interval and payment receipt.\n"
        + text_template("partials/contract_product.html") + "\n"
        + text_template("partials/withdrawal_information.html"))
    payload = render_pdf(body)
    db.session.execute(update(PatreonLicenseDelivery).where(PatreonLicenseDelivery.member_id == delivery.member_id,
        PatreonLicenseDelivery.confirmation_pdf.is_(None)).values(confirmation_pdf=payload))
    db.session.commit()
    db.session.refresh(delivery)
    return delivery.confirmation_pdf


def purge_checkout_agreements():
    """One-hour browser consent expires; orders retain their own full copy."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    db.session.execute(db.delete(CheckoutAgreement).where(CheckoutAgreement.created_at < cutoff))
    db.session.commit()
