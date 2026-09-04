"""Strict, side-effect-free models for third-party webhook payloads.

Keeping payload parsing independent from Flask and the database makes the trust
boundary easy to test and prevents permissive Python coercions (for example,
``True`` being accepted as an integer).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal


def require_json_object(value: object, field_name: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return value


def optional_json_string(data: dict, field_name: str, max_length: int) -> str | None:
    value = data.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > max_length:
        raise ValueError(f"{field_name} must be a string of at most {max_length} characters")
    return value


def required_json_string(
    data: dict,
    field_name: str,
    max_length: int,
    pattern: str | None = None,
) -> str:
    value = optional_json_string(data, field_name, max_length)
    if not value or (pattern is not None and re.fullmatch(pattern, value) is None):
        raise ValueError(f"{field_name} is invalid")
    return value


def optional_json_integer(
    data: dict,
    field_name: str,
    minimum: int | None = None,
) -> int | None:
    value = data.get(field_name)
    if value is None:
        return None
    if type(value) is not int or (minimum is not None and value < minimum):
        raise ValueError(f"{field_name} must be an integer")
    return value


def optional_provider_identifier(data: dict, field_name: str) -> str | None:
    """Accept provider IDs as documented strings or observed JSON integers."""
    value = data.get(field_name)
    if value is None:
        return None
    if type(value) is int:
        if value < 0:
            raise ValueError(f"{field_name} must not be negative")
        return str(value)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or re.fullmatch(r"[A-Za-z0-9._-]+", value) is None
    ):
        raise ValueError(f"{field_name} is invalid")
    return value


def optional_currency(data: dict, field_name: str) -> str | None:
    value = optional_json_string(data, field_name, 20)
    if value is not None and re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError(f"{field_name} is invalid")
    return value


def optional_json_decimal(
    data: dict,
    field_name: str,
    minimum: Decimal | None = None,
) -> Decimal | None:
    value = data.get(field_name)
    if value is None:
        return None
    if type(value) not in (int, float):
        raise ValueError(f"{field_name} must be a number")
    number = Decimal(str(value))
    if not number.is_finite() or (minimum is not None and number < minimum):
        raise ValueError(f"{field_name} must be a finite number")
    return number


def optional_json_boolean(data: dict, field_name: str) -> bool | None:
    value = data.get(field_name)
    if value is None:
        return None
    if type(value) is not bool:
        raise ValueError(f"{field_name} must be a boolean")
    return value


@dataclass(frozen=True, slots=True)
class NowPaymentsWebhook:
    order_id: str
    payment_id: str | None = None
    invoice_id: str | None = None
    payment_status: str | None = None
    parent_payment_id: str | None = None
    pay_currency: str | None = None
    price_currency: str | None = None
    actually_paid: Decimal | None = None
    pay_amount: Decimal | None = None
    price_amount: Decimal | None = None
    payin_hash: str | None = None
    hash: str | None = None

    @classmethod
    def from_mapping(cls, raw_payload: object) -> NowPaymentsWebhook:
        data = require_json_object(raw_payload, "payload")
        return cls(
            order_id=required_json_string(data, "order_id", 255, r"[A-Za-z0-9_-]+"),
            payment_id=optional_provider_identifier(data, "payment_id"),
            invoice_id=optional_provider_identifier(data, "invoice_id"),
            payment_status=optional_json_string(data, "payment_status", 50),
            parent_payment_id=optional_provider_identifier(data, "parent_payment_id"),
            pay_currency=optional_currency(data, "pay_currency"),
            price_currency=optional_currency(data, "price_currency"),
            actually_paid=optional_json_decimal(data, "actually_paid", Decimal(0)),
            pay_amount=optional_json_decimal(data, "pay_amount", Decimal(0)),
            price_amount=optional_json_decimal(data, "price_amount", Decimal(0)),
            payin_hash=optional_json_string(data, "payin_hash", 255),
            hash=optional_json_string(data, "hash", 255),
        )


@dataclass(frozen=True, slots=True)
class PatreonMemberAttributes:
    email: str | None = None
    patron_status: str | None = None
    last_charge_status: str | None = None
    currently_entitled_amount_cents: int | None = None
    campaign_lifetime_support_cents: int | None = None
    lifetime_support_cents: int | None = None
    is_free_trial: bool | None = None
    is_gifted: bool | None = None

    @classmethod
    def from_mapping(cls, raw_attributes: object) -> PatreonMemberAttributes:
        data = require_json_object(raw_attributes, "data.attributes")
        return cls(
            email=optional_json_string(data, "email", 254),
            patron_status=optional_json_string(data, "patron_status", 50),
            last_charge_status=optional_json_string(data, "last_charge_status", 50),
            currently_entitled_amount_cents=optional_json_integer(
                data, "currently_entitled_amount_cents", 0
            ),
            campaign_lifetime_support_cents=optional_json_integer(
                data, "campaign_lifetime_support_cents", 0
            ),
            lifetime_support_cents=optional_json_integer(data, "lifetime_support_cents", 0),
            is_free_trial=optional_json_boolean(data, "is_free_trial"),
            is_gifted=optional_json_boolean(data, "is_gifted"),
        )


@dataclass(frozen=True, slots=True)
class PatreonMember:
    type: str
    id: str
    attributes: PatreonMemberAttributes
    relationships: dict = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw_member: object) -> PatreonMember:
        data = require_json_object(raw_member, "data")
        relationships = require_json_object(data.get("relationships", {}), "data.relationships")
        return cls(
            type=required_json_string(data, "type", 6, r"member"),
            id=required_json_string(data, "id", 128, r"[A-Za-z0-9_-]+"),
            attributes=PatreonMemberAttributes.from_mapping(data.get("attributes")),
            relationships=dict(relationships),
        )


@dataclass(frozen=True, slots=True)
class PatreonWebhook:
    data: PatreonMember
    included: list[dict] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, raw_payload: object) -> PatreonWebhook:
        data = require_json_object(raw_payload, "payload")
        included = data.get("included", [])
        if (
            not isinstance(included, list)
            or len(included) > 100
            or any(not isinstance(resource, dict) for resource in included)
        ):
            raise ValueError("included must be a list of at most 100 objects")
        return cls(
            data=PatreonMember.from_mapping(data.get("data")),
            included=list(included),
        )
