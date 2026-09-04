"""Invoice persistence, generation, and PDF rendering services."""

import json
import os
import re
import tempfile
from datetime import datetime, timezone

from flask import current_app
from fpdf import FPDF

SESSION_REFERENCE_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,255}")


def _invoice_path(session_id: str) -> str:
    if SESSION_REFERENCE_PATTERN.fullmatch(session_id) is None:
        raise ValueError("Invalid payment session reference")
    return os.path.join(
        current_app.config["DATA_DIR"], "invoices", f"{session_id}.json"
    )


def save_invoice(session_id: str, invoice: dict) -> None:
    """Atomically replace an invoice JSON document."""
    invoice_path = _invoice_path(session_id)
    invoice_directory = os.path.dirname(invoice_path)
    os.makedirs(invoice_directory, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=invoice_directory,
            prefix=".invoice-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(invoice, temporary_file, indent=4, ensure_ascii=False)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, invoice_path)
    except Exception:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
        raise


def load_invoice(session_id: str) -> dict | None:
    invoice_path = _invoice_path(session_id)
    try:
        with open(invoice_path, encoding="utf-8") as invoice_file:
            invoice = json.load(invoice_file)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Stored invoice is unreadable") from error
    if not isinstance(invoice, dict):
        raise ValueError("Stored invoice must be a JSON object")
    return invoice


def build_invoice(
    *,
    fiat_amount: float,
    crypto_amount: float,
    pay_currency: str,
    transaction_hash: str,
) -> dict:
    invoice_number = "INV-" + os.urandom(4).hex().upper()
    invoice_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    exchange_rate = fiat_amount / crypto_amount if crypto_amount > 0 else 0
    return {
        "Full Name": "Johannes Habel",
        "Address": "Bahnstr. 21 06886 Lutherstadt Wittenberg",
        "Tax Number": "46208375790",
        "Invoice Date": invoice_date,
        "Delivery Date": invoice_date,
        "Invoice Number": invoice_number,
        "Description": "Porn Fetch License",
        "Quantity": 1,
        "Tax Info": "Hinweis: Gemäß § 19 UStG wird keine Umsatzsteuer berechnet.",
        "Base Price in EUR": f"{fiat_amount:.2f} EUR",
        "Crypto Paid": f"{crypto_amount} {pay_currency.upper()}",
        "Exchange Rate": f"1 {pay_currency.upper()} = {exchange_rate:.2f} EUR",
        "Transaction Hash / TxID": transaction_hash,
    }


def build_simulated_invoice() -> dict:
    return build_invoice(
        fiat_amount=19.99,
        crypto_amount=0.00016,
        pay_currency="BTC",
        transaction_hash="mock-tx-hash-12345",
    )


def _pdf_text(invoice: dict, field: str, default="") -> str:
    value = str(invoice.get(field, default))
    return value.replace("\r", " ").replace("\n", " ")[:500]


def render_invoice_pdf(invoice: dict) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)

    pdf.set_font("Helvetica", style="B", size=16)
    pdf.cell(
        0,
        10,
        f"INVOICE {_pdf_text(invoice, 'Invoice Number')}",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.set_font("Helvetica", size=12)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 8, "From:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    for value in (
        _pdf_text(invoice, "Full Name"),
        _pdf_text(invoice, "Address"),
        f"Tax Number: {_pdf_text(invoice, 'Tax Number')}",
    ):
        pdf.cell(0, 8, value, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)

    for label, field in (
        ("Invoice Date", "Invoice Date"),
        ("Delivery Date", "Delivery Date"),
    ):
        pdf.cell(
            0,
            8,
            f"{label}: {_pdf_text(invoice, field)}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    pdf.ln(5)

    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 8, "Items:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    for label, field, default in (
        ("Description", "Description", ""),
        ("Quantity", "Quantity", 1),
    ):
        pdf.cell(
            0,
            8,
            f"{label}: {_pdf_text(invoice, field, default)}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    pdf.ln(5)

    pdf.set_font("Helvetica", style="I", size=11)
    pdf.cell(0, 8, _pdf_text(invoice, "Tax Info"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    pdf.ln(10)

    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 8, "Payment Details:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=12)
    for label, field in (
        ("Base Price", "Base Price in EUR"),
        ("Crypto Paid", "Crypto Paid"),
        ("Exchange Rate", "Exchange Rate"),
        ("Transaction Hash / TxID", "Transaction Hash / TxID"),
    ):
        pdf.cell(
            0,
            8,
            f"{label}: {_pdf_text(invoice, field)}",
            new_x="LMARGIN",
            new_y="NEXT",
        )

    pdf.ln(15)
    pdf.set_font("Helvetica", style="I", size=12)
    pdf.cell(
        0,
        10,
        "Thank you for your purchase!",
        align="C",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    return bytes(pdf.output())


def invoice_download_name(invoice: dict) -> str:
    invoice_number = _pdf_text(invoice, "Invoice Number", "invoice")
    safe_number = re.sub(r"[^A-Za-z0-9._-]", "_", invoice_number)[:100] or "invoice"
    return f"invoice_{safe_number}.pdf"
