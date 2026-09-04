"""Country-level transaction summaries for tax record review."""

from decimal import Decimal, InvalidOperation

from .countries import COUNTRIES
from .models import Transaction

EU_COUNTRY_CODES = frozenset(
    {
        "AT",
        "BE",
        "BG",
        "HR",
        "CY",
        "CZ",
        "DK",
        "EE",
        "FI",
        "FR",
        "DE",
        "GR",
        "HU",
        "IE",
        "IT",
        "LV",
        "LT",
        "LU",
        "MT",
        "NL",
        "PL",
        "PT",
        "RO",
        "SK",
        "SI",
        "ES",
        "SE",
    }
)
EU_COUNTRY_NAMES = frozenset(COUNTRIES[code] for code in EU_COUNTRY_CODES)


def country_transaction_summary(year: int) -> dict:
    """Aggregate completed configured prices without exposing transaction IDs."""
    transactions = Transaction.query.filter(
        Transaction.status == "finished",
        Transaction.finished_at.startswith(f"{year:04d}-"),
    ).all()
    totals: dict[tuple[str, str], Decimal] = {}
    counts: dict[tuple[str, str], int] = {}
    for transaction in transactions:
        key = (transaction.customer_country, transaction.expected_price_currency.upper())
        try:
            amount = Decimal(transaction.expected_price_amount)
        except InvalidOperation as error:
            raise ValueError("Stored transaction price is invalid") from error
        totals[key] = totals.get(key, Decimal(0)) + amount
        counts[key] = counts.get(key, 0) + 1

    rows = [
        {
            "country": country,
            "currency": currency,
            "transactions": counts[(country, currency)],
            "configured_price_total": str(amount.quantize(Decimal("0.01"))),
        }
        for (country, currency), amount in sorted(totals.items())
    ]
    eu_cross_border_eur = sum(
        (
            amount
            for (country, currency), amount in totals.items()
            if currency == "EUR"
            and country in EU_COUNTRY_NAMES
            and country != COUNTRIES["DE"]
        ),
        Decimal(0),
    )
    return {
        "year": year,
        "rows": rows,
        "eu_cross_border_configured_price_total_eur": str(
            eu_cross_border_eur.quantize(Decimal("0.01"))
        ),
        "scope_warning": (
            "This total covers only completed transactions in this application; "
            "combine it with every other sales channel and obtain tax advice."
        ),
    }
