"""Opt-in OSV advisory lookups, using bounded and HTTPS-only batch requests.

Only package ecosystem, name and exact version are transmitted. No source or HA
secrets are sent; incomplete/bad advisory replies never count as a passing check.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from .model import Report

OSV_URL = "https://api.osv.dev/v1/querybatch"
MAX_REPLY = 1_000_000
BATCH_SIZE = 25
_EXACT_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}\Z")
_NAME = re.compile(r"(?:@?[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]{1,180}\Z")


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("OSV endpoint redirect refused")


def _pinned_runtime(packages: list[dict]) -> list[dict]:
    result: list[dict] = []
    seen = set()
    for item in packages:
        if not isinstance(item, dict) or item.get('scope') != 'runtime':
            continue
        name, version, ecosystem = item.get('name'), item.get('version'), item.get('ecosystem')
        if (not isinstance(name, str) or not isinstance(version, str) or
            ecosystem not in ('PyPI','npm') or not _NAME.fullmatch(name) or
            not _EXACT_VERSION.fullmatch(version)):
            continue
        key = (ecosystem, name, version)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def check_osv(report: Report, limit: int = 150) -> None:
    """Check pinned runtime packages in batches; fail closed on incomplete replies."""
    packages = _pinned_runtime(report.packages)
    if not packages:
        report.checks['advisories'] = 'no resolved runtime packages'
        return
    if len(packages) > limit:
        report.checks['advisories'] = 'truncated'
        return
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirect)
    for offset in range(0, len(packages), BATCH_SIZE):
        batch = packages[offset:offset + BATCH_SIZE]
        queries = [
            {'version': pkg['version'], 'package': {
                'name': pkg['name'], 'ecosystem': pkg['ecosystem']}}
            for pkg in batch
        ]
        payload = json.dumps({'queries': queries}, ensure_ascii=True).encode('utf-8')
        request = urllib.request.Request(OSV_URL, data=payload,
            headers={'Content-Type':'application/json', 'User-Agent':'geordi/0.3'}, method='POST')
        try:
            with opener.open(request, timeout=20) as response:
                raw = response.read(MAX_REPLY + 1)
            if len(raw) > MAX_REPLY:
                raise ValueError('OSV response too large')
            obj = json.loads(raw)
            results = obj.get('results') if isinstance(obj, dict) else None
            if not isinstance(results, list) or len(results) != len(batch):
                raise ValueError('OSV batch results missing or mismatched')
            # The batch endpoint may paginate individual package results.
            # Never conclude complete while results are truncated.
            for pkg, item in zip(batch, results):
                if not isinstance(item, dict) or item.get('next_page_token'):
                    raise ValueError('OSV response incomplete')
                vulns = item.get('vulns', [])
                if not isinstance(vulns, list) or len(vulns) > 500:
                    raise ValueError('OSV vulnerabilities list invalid')
                for vuln in vulns:
                    if not isinstance(vuln, dict) or not isinstance(vuln.get('id'), str):
                        raise ValueError('OSV vulnerability entry invalid')
                    vulnerability_id = vuln['id'][:100]
                    report.add('osv-advisory', 'high', 'dependency:' + pkg['name'], 1,
                               'Published vulnerability: ' + vulnerability_id,
                               'Review advisory and whether this package ships at the exact scanned version',
                               evidence='OSV advisory')
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            report.checks['advisories'] = 'partial: ' + type(exc).__name__
            return
    report.checks['advisories'] = 'completed'


def recheck_report(previous: dict) -> Report:
    """Recheck the stored package inventory without ever fetching source code."""
    from .model import Finding
    report = Report(target=str(previous['target']), source='OSV advisory recheck',
                    commit=previous.get('commit'))
    report.packages = list(previous['packages'])
    report.endpoints = list(previous.get('endpoints', []))
    report.inventory = dict(previous.get('inventory', {}))
    report.inventory['rechecked_from'] = previous.get('generated_at')
    report.skipped = list(previous.get('skipped', []))
    report.checks = dict(previous.get('checks', {}))
    report.checks['advisories'] = 'not requested'
    for raw in previous.get('findings', []):
        if raw.get('rule') == 'osv-advisory':
            continue
        report.findings.append(Finding(
            rule=raw['rule'], severity=raw['severity'], path=raw['path'],
            line=raw['line'], summary=raw['summary'], detail=raw['detail'],
            evidence=raw.get('evidence','heuristic')))
    return report
