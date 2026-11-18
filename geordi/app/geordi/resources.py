"""Conservative available-memory guard before unpacking external repositories."""
from __future__ import annotations
from pathlib import Path
from .marketplace import MarketplaceError

MIN_SCAN_AVAILABLE = 1024 * 1024 * 1024  # 1 GiB; guard does not reserve memory


def _int_file(path: str) -> int | None:
    try:
        raw = Path(path).read_text().strip()
    except OSError:
        return None
    return int(raw) if raw.isdecimal() else None


def available_memory() -> int | None:
    host = None
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                host = int(line.split()[1]) * 1024
                break
    except (OSError, ValueError, IndexError):
        pass
    maximum = _int_file('/sys/fs/cgroup/memory.max')
    used = _int_file('/sys/fs/cgroup/memory.current')
    remaining = max(0, maximum - used) if maximum is not None and used is not None else None
    if host is not None and remaining is not None:
        return min(host, remaining)
    return host if remaining is None else remaining


def require_scan_memory() -> None:
    remaining = available_memory()
    if remaining is None:
        raise MarketplaceError('Unable to confirm available memory; manual scan refused')
    if remaining < MIN_SCAN_AVAILABLE:
        raise MarketplaceError('Less than 1 GiB available; manual scan refused to protect Home Assistant')
