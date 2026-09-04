# Local IP geolocation database

Checkout uses the DB-IP City Lite MMDB database locally. No runtime lookup API
is called and no visitor IP address is written to the database or logs.

The database itself is intentionally ignored by Git because it is large and is
updated monthly. It is currently **not installed** in this working tree, so no
large download is being retained while the development connection is metered.
Checkout consequently fails closed until a snapshot is installed later.

Nothing downloads the database automatically during application startup,
dependency installation, migrations, or tests. On a suitable connection,
install or refresh it explicitly with:

```bash
uv run python scripts/update_geoip_database.py --accept-license
```

To install a specific release:

```bash
uv run python scripts/update_geoip_database.py \
  --release 2026-09 --accept-license
```

The default path is
`$PF_SERVER_DATA_DIR/geoip/dbip-city-lite.mmdb`. Override it with
`GEOIP_DATABASE_PATH` when required. Restart the application after replacing
the file so every worker opens the same new snapshot.

DB-IP City Lite is a reduced-accuracy database updated monthly and licensed
under [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/).
Use requires attribution to [DB-IP.com](https://db-ip.com). The checkout page
contains that attribution. Review the current provider terms before each
deployment or redistribution.

Official source and format documentation:

- <https://db-ip.com/db/lite.php>
- <https://db-ip.com/db/download/ip-to-city-lite>
- <https://db-ip.com/db/format/ip-to-city-lite/mmdb.html>

Country/region geolocation is approximate. VPNs, mobile networks, satellite
connections, stale assignments, and reduced Lite coverage can all produce a
wrong or missing result. It must not be treated as identity or citizenship.
