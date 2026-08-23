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
- api.echteralsfake.me/ -> Receives authenticated payment and membership webhooks

### Endpoints
- / → Landing page
- /stats → View real-time server stats
- /update → Fetch update information for Porn Fetch
- /report → Report errors 
- /ci → personal endpoint for API tests
- /buy_license → You can buy a license for Porn Fetch here
- /impress → Impress (legal requirement in Germany)
- /transparency → AI transparency notice
- /refund_policy → Ricy
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
- https://api.echteralsfake.me/nowpayments-ipn → Webhook for incoming NOWPayments payments
- https://api.echteralsfake.me/patreon-webhook → Webhook for Patreon member events and license delivery
- /ping → You can ping the server :)
- /datenschutz → German translated privacy policy
- /privacy_policy → English Privacy Policy
- /legal-statement → Legal coverage for Porn Fetch
- /appcast.xml → Update for macOS version of Porn Fetch
- /checklist → I can edit the checklist here
- /checklist/progress.svg → Shows the progress for the next Porn Fetch version
- /chat → Private messaging interface! (NOT FOR THE PUBLIC)

# Independent substitution plan

The substitution plan now lives entirely in [`VPlan/`](VPlan/README.md). It uses a separate
Svelte/FastAPI stack, database and process on `127.0.0.1:8001`; the commercial Flask server on
port 8000 does not expose VPlan routes or data. The Cloudflare route for
`vplan.echteralsfake.me` must therefore target port 8001.

## Main landing-page access gate

The main `/` landing page is protected by a neutral login that reuses the `CHECKLIST_AUTH`
password. If the variable is missing, the page fails closed with HTTP 503. A successful login
creates a separate `site_auth` session and does not grant checklist editing rights. Changing
`CHECKLIST_AUTH` invalidates existing landing-page sessions. The VPlan and documentation
subdomains are unaffected.

## Payment webhook configuration

Both webhook handlers are restricted to the hostname from `API_DOMAIN` (default:
`https://api.echteralsfake.me`). The Cloudflare Tunnel/DNS route for that hostname must point to
the commercial Flask service on `127.0.0.1:8000`. Configure NOWPayments to use
`https://api.echteralsfake.me/nowpayments-ipn` and Patreon to use
`https://api.echteralsfake.me/patreon-webhook`.

Patreon signs the exact request body with the secret in `PATREON_SECRET`. License delivery also
requires an SMTP relay; Patreon does not send the attachment itself. See `.env.example` for the
required mail settings. `PATREON_LICENSE_TIER_IDS` can optionally contain a comma-separated
allow-list of Patreon tier IDs; if it is empty, every paid and currently entitled tier is eligible.
Subscribe the Patreon webhook to `members:create`, `members:pledge:create` and `members:update`.
The update event is needed to deliver after a pending or declined first charge later becomes paid.
Before enabling a third-party SMTP relay, name that provider in both privacy-policy templates and
verify that its handling of Patreon member data satisfies Patreon's Creator Privacy Promise.

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
