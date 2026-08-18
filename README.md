# What's this?
This is the official server for Porn Fetch and for my other projects. 

Clearnet: **https://echteralsfake.me**
<br>Tor / Darknet: **http://i3vtbgg6dufszjzbccyzd3wk4v2on3k6ljzjpg2ppzapgqmjmsxlvkid.onion/**

### What does it do? 
- Serves as a test for myself
- Update checking for Porn Fetch
- Error / Feedback reporting for Porn Fetch
- Payment handling (Crypto)
- Creates tax invoices
- Local API Tests for my Porn APIs
- Generates SVGs for my GitHub repositories e.g., the checklist for Porn Fetch
- Landing page

# Hosting / Hardware
- The Server runs on a heavily modified Pixel 7 Pro inside Termux 24/7. 
- Alongside runs a hidden tor service so that the website is available in the Darknet
- Runs on my own internet connection (Vodafone) **50mbit/s up**
- The clearnet site uses Cloudflare as an IPv4 to IPv6 bridge, because my internet is behind CCGNAT
- STRICT zero Log Policy
- No NGINX Remote Address copying
- No debug information

# Subdomains
- docs.echteralsfake.me/ -> Serves the documentation for my projects

### Endpoints
- / → Landing page
- /stats → View real-time server stats
- /update → Fetch update information for Porn Fetch
- /report → Report errors 
- /ci → personal endpoint for API tests
- /buy_license → You can buy a license for Porn Fetch here
- /impress → Impress (legal requirement in Germany)
- /transparency → AI transparency notice
- /refund_policy → Refund Policy
- /terms → Terms of Service of the site (legal requirement)
- /buy_sucess → If the payment succeeds, shows a success page
- /buy_cancel → If user canceled the payments
- /download_license → Downloads the actual license file
- /check-payment-status → IPN Webhook for checking payments
- /download_incoice → Downloads the Invoice for the payment (legal requirement)
- /simulate-payment-success → Simulates the payment locally
- /docs → Documentation for my APIs
- /porn_fetch → Shows the Porn Fetch page
- /donation → Allows you to do a crypto donation
- /create-crypto-payment → creates the actual crypto payment on nowpayments
- /nowpayments_ipn → Webhook for incoming payments
- /ping → You can ping the server :)
- /datenschutz → German translated privacy policy
- /privacy_policy → English Privacy Policy
- /legal-statement → Legal coverage for Porn Fetch
- /appcast.xml → Update for macOS version of Porn Fetch
- /checklist → I can edit the checklist here
- /checklist/progress.svg → Shows the progress for the next Porn Fetch version
- /chat → Private messaging interface! (NOT FOR THE PUBLIC)

# Substitution plan synchronization

The public `/vplan` view is backed by a local `vplan.json`. A background task checks the
school's lightweight modification endpoint every two minutes. Because that endpoint can
return its null timestamp (`0001-01-01 00:00:00`), the complete HTML board is refreshed at
most once per hour as a fallback. A malformed or failed download never replaces the last
valid local plan.

The defaults can be changed through environment variables:

- `VPLAN_SYNC_ENABLED`: set to `false` to disable automatic updates
- `VPLAN_SCHOOL_ID`: required school identifier, loaded from the local `.env` file
- `VPLAN_JSON_PATH`: local output path for the extracted JSON
- `VPLAN_CHECK_INTERVAL_SECONDS`: modification checks, defaults to `120` (minimum `60`)
- `VPLAN_FULL_REFRESH_INTERVAL_SECONDS`: fallback HTML refresh, defaults to `3600`
- `VPLAN_REQUEST_TIMEOUT_SECONDS`: upstream request timeout, defaults to `20`

The JSON file, synchronization state, lock file, and SQLite database are local runtime
files and are excluded from Git.

## VPlan subdomain and proxy privacy

Requests to `https://vplan.echteralsfake.me/` render the plan directly. On that hostname,
the Flask application exposes only the plan, static assets, imprint, and German privacy
policy. The hostname can be changed with `VPLAN_PUBLIC_HOST`.

The application deliberately does not trust `X-Forwarded-For` and removes common visitor-IP
headers before Flask or Flask-Limiter can inspect them. HTTPS and host forwarding remain
enabled. Gunicorn access logging should stay disabled; if it is explicitly enabled elsewhere,
its format must not contain request headers or remote addresses.

Publish `vplan.echteralsfake.me` through the same Cloudflare Tunnel as the main site, mapping it
to `http://localhost:8000`. If the existing main Worker does not already use a wildcard route
covering all subdomains, add `vplan.echteralsfake.me/*` as another route on that same Worker.
No separate Worker is required. The tunnel preserves the public hostname, allowing Flask to
select the VPlan view while serving the same local process and port.

## Main landing-page access gate

The main `/` landing page is protected by a neutral login that reuses the `CHECKLIST_AUTH`
password. If the variable is missing, the page fails closed with HTTP 503. A successful login
creates a separate `site_auth` session and does not grant checklist editing rights. Changing
`CHECKLIST_AUTH` invalidates existing landing-page sessions. The VPlan and documentation
subdomains are unaffected.

# Chat Feature
> [!CAUTION]
> The chat feature is exclusively used for my private purposes for secure communication with my friends. It's not meant to be used
> by the public and is not used in any way by Porn Fetch. 


That's it :) 

> [!WARNING]
> The `/buy_license` endpoint is ONLY a test environment. You won't be charged
> and you won't receive a valid license. Please don't use this endpoint yet.
> It's just for experimenting and testing. I'll tell you when it's ready...


### Why? 
Because I want to have full control all the time about the data being stored,
the device hosting it and I want to learn a little bit by doing it myself.
