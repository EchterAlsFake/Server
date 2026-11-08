"""Wake one background purchase worker per web process after intake commits.

The database remains the durable queue. The shop's file lock serializes this
worker with other web processes and the scheduled retry worker.
"""
from threading import Lock, Thread

from flask import current_app

from .patreon_shop import process_claims, queued_claims_pending


class _ImmediateWorker:
    def __init__(self, app):
        self.app = app
        self.lock = Lock()
        self.requested = False
        self.thread = None

    def wake(self):
        with self.lock:
            self.requested = True
            if self.thread is not None:
                return
            self.thread = Thread(target=self.run, name='patreon-shop', daemon=True)
            try:
                self.thread.start()
            except RuntimeError:
                self.thread = None
                self.app.logger.warning('Immediate Patreon Shop worker unavailable; scheduled retry retained')

    def run(self):
        while True:
            with self.lock:
                self.requested = False
            try:
                # Each batch owns a fresh SQLAlchemy session, independent of
                # the request that submitted it. App-context exit removes it.
                with self.app.app_context():
                    process_claims(wait=True, queued_only=True)
                    more = self.app.config.get('PATREON_SHOP_ENABLED') and queued_claims_pending()
            except Exception:
                # Errors can contain provider secrets. Keep the durable queue
                # for the timer without logging exception payloads.
                self.app.logger.warning('Immediate Patreon Shop processing deferred; scheduled retry retained')
                more = False
            with self.lock:
                if more or self.requested:
                    continue
                self.thread = None
                return


def wake():
    """Start immediately without holding the HTTP request open for scraping."""
    app = current_app._get_current_object()
    if not app.config.get('PATREON_SHOP_ENABLED'):
        return
    worker = app.extensions.setdefault('patreon_shop_worker', _ImmediateWorker(app))
    worker.wake()
