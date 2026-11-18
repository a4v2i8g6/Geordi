"""Home Assistant app startup: read optional token, drop privileges permanently."""
from __future__ import annotations

import json
import os
from pathlib import Path
from .ingress import serve


def main() -> None:
    # Only read the app's own options, never HA /config or arbitrary paths.
    options = Path('/data/options.json')
    obj = {}
    if options.is_file():
        try:
            obj = json.loads(options.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            obj = {}
        if isinstance(obj, dict) and isinstance(obj.get('github_token'), str):
            tok = obj['github_token']
            if tok and len(tok) <= 1024:
                os.environ['GITHUB_TOKEN'] = tok
    if os.geteuid() == 0:
        # The Supervisor-owned private data directory may be root-owned at startup.
        # Do not recurse into data contents or grant access to any other path.
        os.chown('/data', 10001, 10001)
        os.chmod('/data', 0o700)
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    if os.geteuid() == 0:
        raise RuntimeError('Refusing to run the scanner as root')
    obj = obj if isinstance(obj, dict) else {}
    # Values must be operator-selected add-on settings, never HTTP parameters.
    def number(name: str, default: int, lo: int, hi: int) -> int:
        value = obj.get(name, default)
        return value if type(value) is int and lo <= value <= hi else default
    serve(monitor_enabled=obj.get('monitor_enabled', True) is not False,
          poll_minutes=number('poll_minutes', 5, 1, 1440),
          daily_limit=number('daily_scan_limit', 12, 1, 24),
          advisory_rechecks=obj.get('advisory_rechecks', False) is True,
          mobile_target=str(obj.get('notify_service', ''))[:100])

if __name__ == '__main__':
    main()
