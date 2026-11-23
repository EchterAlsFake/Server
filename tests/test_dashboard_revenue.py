from pf_server.dashboard_revenue import parse_shop_accounting


def test_shop_amounts_use_provider_currency_and_do_not_include_buyer_data():
    customer = "patron@example.invalid"
    payload = {
        "included": [
            {"type": "order_item", "id": "first", "attributes": {"refunded_at": None}},
            {"type": "order_item", "id": "second", "attributes": {"refunded_at": "2026-11-18T12:00:00Z"}},
        ],
        "data": [
            {"id": "sale1", "attributes": {
                "buyer_email": customer, "date_purchased": "2026-11-18T00:30:00+02:00",
                "charge_amount_cents": 1400, "currency_code": "usd", "status": "fulfilled",
            }, "relationships": {"order_items": {"data": [{"id": "first"}, {"id": "second"}]}}},
            {"id": "sale2", "attributes": {
                "buyer_email": customer, "date_purchased": "2026-11-18T09:00:00Z",
                "charge_amount_cents": 1000, "currency_code": "EUR", "status": "refunded",
            }, "relationships": {"order_items": {"data": [{"id": "second"}]}}},
        ],
    }
    first, second = parse_shop_accounting(payload)
    assert (first["gross"], first["currency"], first["day"], first["status"]) == ("14", "USD", "2026-11-17", "partial refund")
    assert first["refunds"] is None
    assert second["refunds"] == "10"
    assert first["net"] is second["net"] is None
    assert customer not in str([first, second])
