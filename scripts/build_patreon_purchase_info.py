"""Build the general purchase-information PDF to attach to the Patreon product."""
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

from main import create_app
from pf_server.contracts import render_pdf, text_template


def build():
    app = create_app({'NOWPAYMENTS_SANDBOX': False, 'APP_DOMAIN': 'https://pornfetch.to'})
    with app.app_context():
        body = (
            'Porn Fetch 3.9 - Lifetime Premium purchase information\n'
            'Version: 8 November 2026\n\n'
            'Read these terms before purchasing. Keep this document with your Patreon receipt.\n'
            'VAT ID: DE463457168\n\n'
            'After purchase: https://pornfetch.to/activate\n'
            'Enter your purchase email and the public Patreon order ID from your receipt to view your key, '
            'or request email delivery. Verification normally takes up to ten minutes; provider outages can delay it.\n'
            'Windows 10+, compatible Linux, macOS 14.4+, Android 9+ or iOS 15+ are supported; '
            'check https://pornfetch.to/download for the package and architecture available for your device.\n'
            'Privacy: https://pornfetch.to/privacy_policy\n'
            'Legal disclosure: https://pornfetch.to/impress\n'
            'Consumers generally have fourteen days to withdraw. Activating a key alone does not end that right; '
            'the statutory early-supply declarations and contract confirmation are also required.\n\n'
        )
        for template in ('partials/contract_product.html', 'partials/terms_en.html',
            'partials/refund_agreement_en.html', 'partials/withdrawal_information.html'):
            body += text_template(template) + '\n\n'
        target = root / 'docs/release/v3.9/patreon-purchase-information.pdf'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(render_pdf(body))
        print(target.relative_to(root))


if __name__ == '__main__':
    build()
