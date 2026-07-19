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

That's it :) 

> [!WARNING]
> The `/buy_license` endpoint is ONLY a test environment. You won't be charged
> and you won't receive a valid license. Please don't use this endpoint yet.
> It's just for experimenting and testing. I'll tell you when it's ready...


### Why? 
Because I want to have full control all the time about the data being stored,
the device hosting it and I want to learn a little bit by doing it myself.