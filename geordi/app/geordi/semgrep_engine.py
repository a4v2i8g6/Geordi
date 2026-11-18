"""Optional Semgrep analysis inside an offline Bubblewrap sandbox.

Never executes target code; never launches Semgrep with an untrusted configuration.
Without Bubblewrap's network and filesystem namespaces, analysis is marked incomplete.
Semgrep output snippets and metavariables are discarded to avoid leaking credentials.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .model import Report
from .safeio import UnsafeInput, inventory

RULES = Path(__file__).resolve().parent / 'rules'
LIMIT_OUTPUT = 6 * 1024 * 1024
SEM_TIMEOUT = 90
MAX_CODE_BYTES = 64 * 1024 * 1024
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}


class SemgrepUnavailable(RuntimeError):
    pass


def _stage(root: Path, destination: Path) -> int:
    """Materialize only inspected text files, stripping repository scanner overrides."""
    copied = 0
    bytes_total = 0
    for rel, data, issue in inventory(root):
        if issue:
            # The baseline scan has recorded the problem. Semgrep cannot be complete.
            raise SemgrepUnavailable('source inventory has unreadable paths')
        if Path(rel).suffix.lower() not in EXTENSIONS:
            continue
        if Path(rel).name.startswith('.') or any(p.startswith('.') for p in PurePosixPath(rel).parts):
            raise SemgrepUnavailable('hidden source file needs manual review')
        assert data is not None
        if len(data) > 2_000_000:
            raise SemgrepUnavailable('code file exceeds Semgrep per-target bound')
        bytes_total += len(data)
        if bytes_total > MAX_CODE_BYTES:
            raise SemgrepUnavailable('Semgrep input exceeds bounded code budget')
        if b'\x00' in data:
            raise SemgrepUnavailable('source contains NUL bytes')
        dest = destination / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o400)
        copied += 1
    return copied


def sandbox_command(semgrep_executable: str, bwrap: str, source: Path, rules: Path) -> list[str]:
    """Construct an offline, privilege-free mount namespace; no /data or /config mount."""
    exec_path = Path(semgrep_executable)
    if not exec_path.is_absolute() or not exec_path.is_relative_to(Path('/usr')):
        raise SemgrepUnavailable('Semgrep must be installed in /usr for isolated execution')
    if not Path(bwrap).is_absolute():
        raise SemgrepUnavailable('Bubblewrap path must be absolute')
    cmd = [bwrap, '--die-with-parent', '--new-session', '--unshare-user', '--unshare-net',
           '--unshare-pid', '--unshare-ipc', '--unshare-uts',
           '--ro-bind', '/usr', '/usr',
           '--ro-bind', str(source), '/scan',
           '--ro-bind', str(rules), '/rules',
           '--tmpfs', '/tmp', '--proc', '/proc', '--dev', '/dev',
           '--dir', '/home', '--chdir', '/scan']
    # Debian's /bin, /lib and /lib64 may be usrmerge symlinks. Map only the
    # minimal Python runtime paths, not the host filesystem or scanner secrets.
    for entry in ('/bin', '/lib', '/lib64'):
        if Path(entry).is_symlink():
            cmd += ['--symlink', os.readlink(entry).lstrip('/'), entry]
        elif Path(entry).is_dir():
            cmd += ['--ro-bind', entry, entry]
    cmd += ['--', str(exec_path), 'scan', '--config', '/rules', '--json', '--metrics=off',
            '--no-rewrite-rule-ids',
            '--no-git-ignore', '--jobs', '1', '--timeout', '10',
            '--max-target-bytes', '2000000', '/scan']
    return cmd


def _parse_output(obj: Any, report: Report) -> None:
    if not isinstance(obj, dict) or not isinstance(obj.get('results'), list):
        raise SemgrepUnavailable('Semgrep output has invalid schema')
    if obj.get('errors'):
        raise SemgrepUnavailable('Semgrep reported parse or execution errors')
    for hit in obj['results'][:2000]:
        if not isinstance(hit, dict):
            raise SemgrepUnavailable('invalid Semgrep finding')
        rule = hit.get('check_id')
        if not isinstance(rule, str) or not rule.startswith('geordi.') or len(rule) > 160:
            raise SemgrepUnavailable('unexpected scanner rule identifier')
        path = hit.get('path', '')
        if not isinstance(path, str):
            raise SemgrepUnavailable('Semgrep returned an unexpected path')
        if path.startswith('/scan/'):
            relative = path.removeprefix('/scan/')
        elif path.startswith('scan/'):
            relative = path.removeprefix('scan/')
        elif not path.startswith('/'):
            relative = path
        else:
            raise SemgrepUnavailable('Semgrep returned an unexpected path')
        p = PurePosixPath(relative)
        if (not relative or p.is_absolute() or '..' in p.parts or
                len(p.parts) > 30 or len(relative) > 300):
            raise SemgrepUnavailable('Semgrep finding path unsafe')
        try:
            line = int(hit.get('start', {}).get('line', 1))
        except (TypeError, ValueError, AttributeError) as exc:
            raise SemgrepUnavailable('Semgrep finding line invalid') from exc
        meta = hit.get('extra', {}).get('metadata') or {}
        severity = meta.get('geordi_severity') if isinstance(meta, dict) else None
        if severity not in ('high', 'medium', 'low'):
            severity = 'medium'
        # Rule IDs are owned by Geordi, but messages/evidence and substitutions
        # may contain arbitrary source text, so store fixed descriptions only.
        report.add(rule, severity, relative, max(1, min(line, 2_000_000)),
                   'Semgrep rule matched', 'Review matching code locally; source text is not retained',
                   evidence='semgrep-rule')
    if len(obj['results']) > 2000:
        raise SemgrepUnavailable('Semgrep results truncated')


def run_semgrep(root: Path, report: Report) -> None:
    report.checks['semgrep_dataflow'] = 'unavailable'
    exe = shutil.which('semgrep')
    bwrap = shutil.which('bwrap')
    if not exe or not bwrap or not RULES.is_dir():
        return
    try:
        with tempfile.TemporaryDirectory(prefix='geordi-semgrep-') as folder:
            scratch = Path(folder)
            staged = scratch / 'source'
            staged.mkdir()
            count = _stage(root, staged)
            if not count:
                report.checks['semgrep_dataflow'] = 'not applicable'
                return
            cmd = sandbox_command(exe, bwrap, staged, RULES)
            env = {'HOME': '/tmp', 'PATH': '/usr/local/bin:/usr/bin:/bin',
                   'PYTHONDONTWRITEBYTECODE': '1',
                   'SEMGREP_METRICS': 'off', 'SEMGREP_SEND_METRICS': 'off',
                   'SEMGREP_ENABLE_VERSION_CHECK': '0', 'PYTHONNOUSERSITE': '1',
                   'LANG': 'C.UTF-8'}
            # stdout goes to a regular file to avoid unlimited pipe buffering.
            with (scratch / 'result.json').open('w+b') as output:
                try:
                    finished = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                                              stdout=output, stderr=subprocess.DEVNULL,
                                              env=env, timeout=SEM_TIMEOUT, check=False)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise SemgrepUnavailable('isolated scanner failed or timed out') from exc
                if finished.returncode != 0:
                    raise SemgrepUnavailable('sandbox or Semgrep returned nonzero status')
                if output.tell() > LIMIT_OUTPUT:
                    raise SemgrepUnavailable('Semgrep output exceeded size limit')
                output.seek(0)
                try:
                    data = json.load(output)
                except (ValueError, UnicodeError) as exc:
                    raise SemgrepUnavailable('Semgrep output was not JSON') from exc
            _parse_output(data, report)
            report.checks['semgrep_dataflow'] = 'completed'
    except (SemgrepUnavailable, UnsafeInput, OSError, ValueError):
        # Never allow an unavailable sandbox to be interpreted as a clean result.
        report.checks['semgrep_dataflow'] = 'unavailable or incomplete'
