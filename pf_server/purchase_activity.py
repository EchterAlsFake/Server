"""Public worker milestones. Email-only requests never disclose eligibility."""
from datetime import datetime, timezone
import time

from .extensions import db


def record_activity(rows, stage):
    timestamp = time.time()
    for row in rows:
        row.progress_stage, row.progress_updated_at = stage, timestamp
    db.session.commit()


def patreon_progress(row, *, email_only=False):
    stages = [
        ('queued', 'Request saved'),
        ('fetching', 'Read Patreon purchase data'),
        ('verifying', 'Verify purchase details'),
        ('license', 'Prepare signed license'),
        ('delivery', 'Prepare email delivery' if email_only else 'License ready to save'),
    ]
    stage = row.progress_stage or 'queued'
    complete = not row.pending if email_only else row.status != 'pending'
    titles = {
        'queued': ('Request saved. Waiting for the purchase worker.',
                   'The worker checks the queue every minute. Your request is saved; this page will update automatically.'),
        'fetching': ('Reading Patreon purchase data…',
                     'The worker is fetching and validating the Patreon sales pages before checking purchases. This can take a few minutes.'),
        'verifying': ('Checking purchase details…',
                      'The worker is matching the purchase details and checking that the order is fulfilled and eligible.'),
        'license': ('Preparing your license…',
                    'The worker is creating or recovering the signed Premium license for the verified purchase.'),
        'delivery': ('Preparing email delivery…',
                     'The worker is preparing license email delivery for eligible purchases. Check your inbox and Spam folder after processing.'),
        'retry': ('Processing delayed. Waiting to retry.',
                  'The purchase or delivery service is temporarily unavailable. Your request is saved and the worker will retry automatically. You do not need to submit it again.'),
    }
    if email_only:
        # Knowing an address is not proof of ownership. These milestones apply
        # to every email job, including ones with no eligible purchase.
        titles['license'] = ('Checking purchases and preparing licenses…',
                             'The worker is checking the sales data and preparing licenses for eligible purchases. Email delivery follows if your purchase qualifies.')
    title, message = titles.get(stage, titles['queued'])
    if complete:
        title, message = (
            ('Request processed. Check your email.',
             'If an eligible purchase was found, the license was handed to the mail server. Allow up to 10 minutes and check Spam, especially with Gmail. Use your email and order ID above to view a verified license in this browser.')
            if email_only else
            ('Your license is ready.', 'Save your license key and file safely.') if row.status == 'ready' else
            ('Purchase could not be verified.', 'Check the email and order ID on your Patreon receipt, or contact support.')
        )
    index = len(stages) if complete else next((i for i, (key, _) in enumerate(stages) if key == stage), 1)
    if email_only:
        stages[2:4] = [('verifying', 'Check purchases and prepare eligible licenses')]
        index = len(stages) if complete else {'queued': 0, 'fetching': 1, 'verifying': 2, 'license': 2, 'delivery': 3, 'retry': 1}.get(stage, 0)
    attention = not email_only and row.status == 'not_found'
    updated = row.progress_updated_at or (row.requested_at if email_only else row.created_at)
    return dict(stage=stage, title=title, message=message,
                activity='attention' if attention else 'complete' if complete else 'waiting' if stage in {'retry', 'queued'} else 'active',
                steps=[] if attention else [dict(id=key, label=label, state='done' if i < index else 'current' if i == index else 'upcoming') for i, (key, label) in enumerate(stages)],
                updated_at=datetime.fromtimestamp(updated, timezone.utc).isoformat(),
                poll_after_ms=5000)
