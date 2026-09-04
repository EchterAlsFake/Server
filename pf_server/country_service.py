"""Local-only checkout geolocation, tax evidence, and region restrictions."""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .countries import country_name

CHECKOUT_PATHS = frozenset({"/create-crypto-payment", "/create-fiat-payment"})
IP_HEADER_ENVIRONMENT_KEYS = (
    "HTTP_TRUE_CLIENT_IP",
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_REAL_IP",
    "HTTP_FORWARDED",
)
BLOCKED_COUNTRY_CODES = frozenset({"KP", "SY"})
RESTRICTED_UKRAINE_SUBDIVISIONS = frozenset(
    {"crimea", "sevastopol", "donetsk", "luhansk", "kherson", "zaporizhzhia"}
)


@dataclass(frozen=True, slots=True)
class CountryEvidence:
    status: str
    country_code: str | None = None
    subdivision: str | None = None
    database_label: str | None = None


@dataclass(frozen=True, slots=True)
class CheckoutCountryDecision:
    status: str
    country_name: str | None = None
    evidence_source: str | None = None
    database_label: str | None = None
    reason: str | None = None


class LocalCountryResolver:
    """Read country/region evidence from a local MMDB file without network I/O."""

    def __init__(self, database_path: str, database_label: str):
        self.database_path = database_path
        self.database_label = database_label
        self._reader = None

    def _get_reader(self):
        if self._reader is not None:
            return self._reader
        if not os.path.isfile(self.database_path):
            return None
        import maxminddb

        self._reader = maxminddb.open_database(self.database_path)
        if not self.database_label:
            build_epoch = self._reader.metadata().build_epoch
            build_date = datetime.fromtimestamp(build_epoch, timezone.utc)
            self.database_label = f"DB-IP City Lite {build_date:%Y-%m}"
        return self._reader

    def lookup(self, raw_address: object) -> CountryEvidence:
        if not isinstance(raw_address, str) or "," in raw_address:
            return CountryEvidence(status="invalid_address")
        try:
            address = ipaddress.ip_address(raw_address.strip())
        except ValueError:
            return CountryEvidence(status="invalid_address")
        reader = self._get_reader()
        if reader is None:
            return CountryEvidence(status="database_unavailable")
        record = reader.get(str(address))
        if not isinstance(record, dict):
            return CountryEvidence(status="not_found", database_label=self.database_label)
        country = record.get("country")
        country_code = country.get("iso_code") if isinstance(country, dict) else None
        if not isinstance(country_code, str) or country_name(country_code) is None:
            return CountryEvidence(status="not_found", database_label=self.database_label)

        subdivision_name = None
        subdivisions = record.get("subdivisions")
        if isinstance(subdivisions, list) and subdivisions:
            subdivision = subdivisions[0]
            names = subdivision.get("names") if isinstance(subdivision, dict) else None
            if isinstance(names, dict) and isinstance(names.get("en"), str):
                subdivision_name = names["en"][:100]
        return CountryEvidence(
            status="found",
            country_code=country_code.upper(),
            subdivision=subdivision_name,
            database_label=self.database_label,
        )


class CheckoutCountryMiddleware:
    """Resolve checkout IP once, retain only geography, then strip IP headers."""

    def __init__(self, application, resolver: LocalCountryResolver, ip_header: str):
        self.application = application
        self.resolver = resolver
        self.ip_environment_key = (
            "HTTP_" + ip_header.upper().replace("-", "_") if ip_header else None
        )

    def __call__(self, environ, start_response):
        if (
            environ.get("REQUEST_METHOD") == "POST"
            and environ.get("PATH_INFO") in CHECKOUT_PATHS
        ):
            raw_address = (
                environ.get(self.ip_environment_key)
                if self.ip_environment_key
                else environ.get("REMOTE_ADDR")
            )
            try:
                evidence = self.resolver.lookup(raw_address)
            except Exception:
                logging.getLogger("pf_server.country").exception(
                    "Local checkout geolocation failed"
                )
                evidence = CountryEvidence(status="lookup_error")
            environ["PF_COUNTRY_STATUS"] = evidence.status
            if evidence.country_code:
                environ["PF_COUNTRY_CODE"] = evidence.country_code
            if evidence.subdivision:
                environ["PF_COUNTRY_SUBDIVISION"] = evidence.subdivision
            if evidence.database_label:
                environ["PF_COUNTRY_DATABASE"] = evidence.database_label

        for key in IP_HEADER_ENVIRONMENT_KEYS:
            environ.pop(key, None)
        environ.pop("REMOTE_ADDR", None)
        return self.application(environ, start_response)


def checkout_country_decision(
    declared_country_code: object,
    environ: dict,
) -> CheckoutCountryDecision:
    """Compare declared and local-IP countries and apply configured store policy."""
    declared_name = country_name(declared_country_code)
    if declared_name is None:
        return CheckoutCountryDecision(status="invalid_declaration")
    declared_code = str(declared_country_code).strip().upper()
    if declared_code in BLOCKED_COUNTRY_CODES:
        return CheckoutCountryDecision(status="restricted", reason="declared_country")

    evidence_status = environ.get("PF_COUNTRY_STATUS")
    evidence_code = environ.get("PF_COUNTRY_CODE")
    if evidence_status != "found" or not isinstance(evidence_code, str):
        return CheckoutCountryDecision(status="unavailable", reason=str(evidence_status))
    if evidence_code in BLOCKED_COUNTRY_CODES:
        return CheckoutCountryDecision(status="restricted", reason="ip_country")
    if evidence_code != declared_code:
        return CheckoutCountryDecision(status="mismatch", reason="country_mismatch")

    subdivision = environ.get("PF_COUNTRY_SUBDIVISION")
    if evidence_code == "UA":
        if not isinstance(subdivision, str) or not subdivision:
            return CheckoutCountryDecision(
                status="restricted", reason="ukraine_region_unverified"
            )
        normalized_subdivision = re.sub(r"[^a-z]+", " ", subdivision.casefold())
        if any(
            name in normalized_subdivision
            for name in RESTRICTED_UKRAINE_SUBDIVISIONS
        ):
            return CheckoutCountryDecision(
                status="restricted", reason="restricted_ukraine_region"
            )

    database_label = environ.get("PF_COUNTRY_DATABASE")
    if not isinstance(database_label, str) or not database_label:
        return CheckoutCountryDecision(status="unavailable", reason="database_unknown")
    return CheckoutCountryDecision(
        status="verified",
        country_name=declared_name,
        evidence_source="customer_declaration+local_ip_geolocation",
        database_label=database_label[:100],
    )
