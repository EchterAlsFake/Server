# Checkout country evidence and geographic policy

This document explains the country question at checkout, the local IP-country
check, the retained tax evidence, and the geographic block policy. It records
the official sources reviewed in September 2026. It is an engineering record,
not legal or tax advice; the final policy and privacy text should be reviewed by
a German tax adviser and sanctions lawyer before live sales begin.

## What the checkout now does

Every payment-creation request must include a country selected by the customer.
Immediately before Flask handles that request, middleware compares the selected
country with a local DB-IP City Lite lookup of the connecting address.

```text
Customer selects country
        |
        v
Local TLS proxy supplies X-Forwarded-For
        |
        v
Local MMDB lookup (no API request)
        |
        +-- mismatch / missing evidence / restricted location --> no payment
        |
        v
IP and forwarding headers removed from the request environment
        |
        v
Payment created; only country + evidence method + database label are saved
```

The address and, for Ukraine, the subdivision are held only long enough to make
the decision. They are not added to SQLAlchemy models, invoices, application
logs, or provider metadata. `REMOTE_ADDR` and common forwarding headers are
removed before the Flask application and its extensions receive the request.

Stored transaction fields are:

| Field | Example | Reason |
| --- | --- | --- |
| `customer_country` | `Germany` | Customer-location and tax record |
| `country_evidence` | `customer_declaration+local_ip_geolocation` | How the country was checked |
| `geolocation_database` | `DB-IP City Lite 2026-09` | Which evidence snapshot was used |
| `finished_at` | RFC 3339 timestamp | Year-based tax reporting for completed sales |

Not stored: the IP address, subdivision, street address, browser details, or
the raw country-check request.

## Checkout outcomes

| Condition | HTTP result | Effect |
| --- | --- | --- |
| Valid selection matching local evidence | normal provider response | Country evidence is saved with the pending transaction |
| Invalid or missing country | `400` | Customer must select a valid country |
| Country mismatch | `409` | Customer is asked to disable a VPN and retry |
| Restricted location | `451` | Payment creation is blocked |
| Database missing, invalid address, or lookup failure | `503` | Checkout fails closed and asks the customer to retry later |

Checkout intentionally fails closed when the MMDB file has not been installed.
That is the current state of this repository: the large database was not kept,
at the user's request. The deterministic test suite uses a tiny in-memory fake
and does not need or download the real file.

## Why country evidence is retained

For EU telecommunications, broadcasting, and electronically supplied services,
Article 24b of Council Implementing Regulation (EU) No 282/2011 generally calls
for two non-contradictory location-evidence items listed in Article 24f. The
listed evidence includes billing address, IP/geolocation, bank details, SIM
country code, fixed land line, and other commercially relevant information.
The current regulation contains a EUR 100,000 current-and-previous-year
simplification under which one qualifying item from a person involved in the
supply other than the supplier or customer may suffice.

This EUR 100,000 evidence simplification is different from the EUR 10,000
place-of-supply/OSS threshold described by the German Federal Central Tax
Office. Do not treat either threshold as a general tax exemption.

The implementation deliberately records the customer's declaration and a
local IP-geolocation result, but a customer declaration is customer-provided
and may not satisfy every independence requirement. Above the applicable
evidence threshold, obtain another independent item from the payment provider
or bank and have the complete evidence design reviewed professionally.

EU OSS guidance says records must include the information used to determine
where the customer is established/resident, relevant payment information, and
the Member State of consumption. OSS records must generally be retained for ten
years and made electronically available on request. The application therefore
has a privacy-minimizing country summary command:

```bash
uv run flask --app main tax-country-summary --year 2026
```

It reports completed configured-price totals by country and currency without
transaction or provider identifiers. Its EU cross-border EUR figure covers
only this application, so figures from every sales channel must be combined.

Official tax sources:

- [Consolidated Council Implementing Regulation (EU) No 282/2011](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A02011R0282-20250414), especially Articles 24b and 24f
- [European Commission: OSS record keeping and audits](https://vat-one-stop-shop.ec.europa.eu/one-stop-shop/record-keeping-and-audits-oss_en)
- [German Federal Central Tax Office: One-Stop-Shop EU](https://www.bzst.de/DE/Unternehmen/Umsatzsteuer/One-Stop-Shop_EU/one_stop_shop_eu.html?nn=113978)

## Geographic restriction policy

The code implements the requested store policy:

- North Korea (`KP`) is blocked.
- Syria (`SY`) is blocked.
- Crimea, Sevastopol, Donetsk, Luhansk, Kherson, and Zaporizhzhia are blocked
  when the IP database reports Ukraine and one of those subdivision names.
- A Ukrainian lookup without subdivision evidence is blocked because the
  requested regional decision cannot safely be made.

There are important legal and technical limits:

1. EU sanctions are generally targeted measures, not automatic bans on every
   person of a nationality or every resident of a country. A complete country
   block is an operator policy broader than sanctions-list screening.
2. In May 2025 the EU lifted Syria's economic sanctions except measures based
   on security grounds; targeted individual/entity measures remain. The whole-
   country Syria block is therefore explicitly a conservative store policy,
   not a claim that current EU law requires a blanket consumer ban.
3. EU territorial restrictions concern Crimea/Sevastopol and non-government-
   controlled areas of Donetsk, Luhansk, Kherson, and Zaporizhzhia. DB-IP Lite
   exposes administrative subdivisions, not the changing line of control. The
   implementation consequently blocks each named subdivision in full. This is
   knowingly over-inclusive and can reject customers in Ukrainian-controlled
   areas.
4. Country geolocation does not establish identity, citizenship, beneficial
   ownership, or sanctions-list status. It also cannot reliably defeat VPNs,
   proxies, mobile carrier routing, or stale geolocation data. If formal party
   screening is required, it needs a separate legally reviewed process.

Official sanctions sources:

- [Council of the EU: sanctions against North Korea](https://www.consilium.europa.eu/en/policies/sanctions-against-north-korea/)
- [Council of the EU: Syria policy and sanctions changes](https://www.consilium.europa.eu/en/policies/syria/)
- [European Commission: sanctions following Russia's aggression against Ukraine](https://finance.ec.europa.eu/eu-and-world/sanctions-restrictive-measures/sanctions-adopted-following-russias-military-aggression-against-ukraine_en)
- [Commission FAQ on Donetsk, Kherson, Luhansk, and Zaporizhzhia restrictions](https://finance.ec.europa.eu/system/files/2023-10/faqs-sanctions-russia-oblasts_en.pdf)
- [Council of the EU: how EU sanctions work](https://www.consilium.europa.eu/en/topics/sanctions/)

## Local database operation

DB-IP City Lite is a monthly, reduced-accuracy MMDB database offered under CC
BY 4.0. The web checkout includes DB-IP attribution. No runtime request is made
to DB-IP or another geolocation service.

When a normal internet connection is available, review `geoip/README.md` and
install a snapshot explicitly:

```bash
uv run python scripts/update_geoip_database.py --accept-license
```

The updater streams gzip data with a size limit, validates the MMDB metadata
marker, calculates SHA-256, and atomically replaces the old snapshot. The
database and temporary files are ignored by Git. Restart every application
worker after an update because readers are opened lazily and then cached.

Official DB source and format documentation:

- [DB-IP Lite databases](https://db-ip.com/db/lite.php)
- [DB-IP City Lite download](https://db-ip.com/db/download/ip-to-city-lite)
- [DB-IP City Lite MMDB format](https://db-ip.com/db/format/ip-to-city-lite/mmdb.html)

## Deployment checklist

Before enabling checkout:

1. Install the MMDB file over a non-metered connection and restart workers.
2. Keep Gunicorn bound to loopback and allow only the trusted local reverse
   proxy to reach it. A public direct route could forge `X-Forwarded-For`.
3. Confirm the production path is Privex VPS (Sweden), WireGuard, and then the
   Acer Swift 3 or Google Pixel 7 Pro (Germany), with TLS termination only on
   the German endpoint after the tunnel. Preserve the visitor source address
   through the transport, and configure the local reverse proxy to discard any
   inbound `X-Forwarded-For` value and set one value from that source address.
4. Disable IP/query logging on the VPS, WireGuard path, reverse proxy, process
   manager, hosting platform, and operating-system services as applicable.
5. Confirm `/buy_license` explains the check and links to the privacy policy.
6. Run the complete tests and a sandbox checkout from an allowed country.
7. Test mismatch, database-unavailable, and restricted-location responses.
8. Arrange monthly database updates and retain the displayed release/checksum
   in private operational records; do not add the MMDB file to Git.
9. Obtain tax and sanctions advice and decide whether the conservative region
   policy should be replaced by a specialist compliance product or manual
   review before accepting real payments.
