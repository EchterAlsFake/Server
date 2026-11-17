#!/usr/bin/python3
"""Stage PayWarp credentials and site settings for the rootless pfctl rollout.

Run as root on the origin, with JSON containing PAYWARP_API_KEY and
PAYWARP_WEBHOOK_SECRET on stdin. Secrets are sealed with the existing host+TPM2
user-credential scheme; nothing is restarted by this command.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

QUAD = Path('/var/lib/pornfetch/.config/containers/systemd')
SOURCE = Path('/srv/infra/msi/podman/application/quadlet')
STATE = Path('/var/lib/pornfetch-ops/paywarp-config')
CREDENTIALS = {
    'PAYWARP_API_KEY': 'server_paywarp_api_key.cred',
    'PAYWARP_WEBHOOK_SECRET': 'server_paywarp_webhook_secret.cred',
}


def settings(text, site_url):
    lines = [line for line in text.splitlines() if not re.match(
        r'Environment=PAYWARP_(ENABLED|SITE_URL)=|LoadCredentialEncrypted=PAYWARP_(API_KEY|WEBHOOK_SECRET):', line)]
    text = '\n'.join(lines) + '\n'
    if '[Container]\n' not in text or '[Service]\n' not in text:
        raise ValueError('Invalid Quadlet sections')
    text = text.replace('[Container]\n', '[Container]\nEnvironment=PAYWARP_ENABLED=true\nEnvironment=PAYWARP_SITE_URL=' + site_url + '\n', 1)
    declarations = ''.join('LoadCredentialEncrypted=' + name + ':%h/.config/containers/systemd/credentials/' + filename + '\n'
        for name, filename in CREDENTIALS.items())
    return text.replace('[Service]\n', '[Service]\n' + declarations, 1)


def atomic_write(path, content, uid, gid, mode):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        temp = Path(file.name)
        try:
            os.fchmod(file.fileno(), mode)
            os.fchown(file.fileno(), uid, gid)
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
            temp.replace(path)
        finally:
            temp.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site-url', default='https://pornfetch.to')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root on the origin.')
    parsed = urlsplit(args.site_url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
        or parsed.path not in {'', '/'} or parsed.query or parsed.fragment or parsed.port not in {None, 443}):
        parser.error('Use the registered HTTPS site origin.')
    site_url = args.site_url.rstrip('/')
    values = json.load(sys.stdin)
    if not isinstance(values, dict) or any(not isinstance(values.get(k), str) or not values[k].strip() or '\n' in values[k] for k in CREDENTIALS):
        raise ValueError('Both PayWarp secrets are required')
    account = pwd.getpwnam('pornfetch')
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE / 'configure.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        targets = [QUAD / 'credentials' / f for f in CREDENTIALS.values()]
        units = ['pornfetch-web.container', 'pornfetch-migrate.container']
        targets += [root / unit for root in (QUAD, SOURCE) for unit in units]
        originals = {p: (p.read_bytes(), p.stat()) if p.exists() else None for p in targets}
        backup = Path(tempfile.mkdtemp(prefix='settings-', dir=STATE))
        for i, (path, original) in enumerate(originals.items()):
            if original:
                (backup / str(i)).write_bytes(original[0])
                (backup / str(i)).chmod(0o600)
        (backup / 'paths.json').write_text(json.dumps([str(p) for p in targets]))
        # Seal everything before making any configuration changes.
        encrypted = {}
        for name, filename in CREDENTIALS.items():
            process = subprocess.run(['systemd-creds', 'encrypt', '--quiet', '--user',
                '--uid=' + str(account.pw_uid), '--with-key=host+tpm2', '--name=' + name, '-', '-'],
                input=values[name].encode(), capture_output=True, timeout=60, cwd='/')
            if process.returncode:
                raise RuntimeError('Credential sealing failed; output suppressed')
            encrypted[filename] = process.stdout
        try:
            for filename, content in encrypted.items():
                atomic_write(QUAD / 'credentials' / filename, content, account.pw_uid, account.pw_gid, 0o600)
            for unit in units:
                # The installed unit is the authority; preserve all its current settings.
                text = settings((QUAD / unit).read_text(), site_url)
                for root in (QUAD, SOURCE):
                    path = root / unit
                    metadata = path.stat()
                    atomic_write(path, text.encode(), metadata.st_uid, metadata.st_gid, metadata.st_mode & 0o777)
        except Exception:
            for path, original in originals.items():
                if original:
                    content, metadata = original
                    atomic_write(path, content, metadata.st_uid, metadata.st_gid, metadata.st_mode & 0o777)
                else:
                    path.unlink(missing_ok=True)
            raise
    print('PayWarp credentials sealed and configuration staged; no services restarted.')
    print('Configuration rollback copy:', backup)
    print('Deploy the reviewed Server commit using pfctl update web.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('PayWarp staging failed:', type(error).__name__, '(details suppressed to protect secrets)', file=sys.stderr)
        sys.exit(1)
