"""Validate staged site routes with the existing global Caddy configuration."""
import os
from pathlib import Path
import subprocess
import tempfile

from dotenv import dotenv_values

root = Path("/etc/caddy")
configuration = (root / "Caddyfile").read_text()
marker = "import /etc/caddy/conf.d/*.caddy"
if configuration.count(marker) != 1:
    raise SystemExit("Review the changed Caddy import layout before validation")
imports = [str(path) for path in sorted((root / "conf.d").glob("*.caddy"))
           if path.name != "managed-sites.caddy"]
candidate = Path(
    os.environ.get("EAF_CADDY_SITES", Path(__file__).with_name("managed-sites.caddy"))
).resolve(strict=True)
imports.insert(0, str(candidate))
configuration = configuration.replace(marker, "\n".join("import " + path for path in imports))
with tempfile.NamedTemporaryFile(mode="w", suffix=".caddy", prefix="eaf-caddy-") as draft:
    draft.write(configuration)
    draft.flush()
    environment = os.environ | {key: value for key, value in
                               dotenv_values(root / "desec.env").items() if value is not None}
    subprocess.run(["/usr/local/bin/caddy-desec", "validate", "--adapter", "caddyfile",
                    "--config", draft.name], env=environment, check=True)
