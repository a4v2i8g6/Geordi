"""Server-rendered ingress HTML: no JavaScript, fonts, external assets or secrets."""
from __future__ import annotations

import html
from collections import Counter
from typing import Any
from .marketplace import Installed
from .reports import compare


def e(value: Any) -> str:
    return html.escape(str(value), quote=True)


CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'"
STYLE = """
:root {color-scheme:dark} body{margin:0;background:#0e151f;color:#e9f0fa;font:15px system-ui,-apple-system,sans-serif}
main{max-width:1080px;margin:auto;padding:25px 20px 60px}h1{margin:0;font-size:2rem;letter-spacing:-.04em}h2{font-size:1.13rem;margin-top:30px}
header{display:flex;justify-content:space-between;gap:15px;align-items:center;border-bottom:1px solid #29394d;padding-bottom:25px}
.caption{color:#a8b7c8;font-size:13px;line-height:1.5}.label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#a8b7c8}
.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:22px}
.metric,.panel{background:#172334;border:1px solid #2a4056;border-radius:13px;padding:17px}.metric b{display:block;font-size:29px;margin-top:3px}
.notice{padding:15px 16px;border:1px solid #8d7140;background:#24251e;border-radius:9px;margin:20px 0;color:#ffe6bd}
.error{padding:15px;border:1px solid #ab5262;color:#ffd2da;border-radius:9px;margin:20px 0}
.items{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:12px}.item{border:1px solid #2a4056;background:#172334;border-radius:12px;padding:17px;min-width:0}
.item h3{font-size:16px;margin:0 0 7px;overflow-wrap:anywhere}.item p{color:#a8b7c8;font-size:13px;overflow-wrap:anywhere}.tag{display:inline-block;border:1px solid #476078;border-radius:8px;padding:3px 7px;font-size:12px}
.update{border-color:#b3914e;color:#ffdfa3}.status{font-size:13px;color:#a8b7c8;margin:10px 0}
a{color:#a6cfff}button{border:1px solid #6c91b2;background:#284a68;color:white;padding:9px 13px;border-radius:8px;cursor:pointer;font:inherit}button:disabled{opacity:.4;cursor:default}
form{display:inline-block;margin-top:8px}.muted{color:#a8b7c8}.report{line-height:1.5}.report pre{overflow:auto}
@media(max-width:600px){header{display:block}.metrics{grid-template-columns:repeat(3,minmax(0,1fr))}.metric{padding:10px}.metric b{font-size:23px}}
"""


def page(title: str, content: str, *, refresh_seconds: int | None = None) -> str:
    refresh = f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">' if refresh_seconds else ''
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="{e(CSP)}">{refresh}<title>{e(title)} — Geordi</title>'
            f'<style>{STYLE}</style></head><body><main><header><div><h1>Geordi</h1>'
            '<p class="caption">Home Assistant extension security scanner · independent implementation</p></div>'
            '<div class="label">Read-only integration</div></header>' + content + '</main></body></html>')


def home(items: list[Installed], other: dict[str, int], latest: dict[str, dict], csrf: str,
         busy: str, error: str, updated: str, monitor: dict | None = None) -> str:
    scanned = sum(1 for item in items if item.repo in latest)
    updates = sum(item.update for item in items)
    out = '<section class="metrics">'
    for label, value in [('Installed extensions',len(items)), ('Updates available',updates), ('Previously scanned',scanned)]:
        out += f'<div class="metric"><span class="label">{e(label)}</span><b>{value}</b></div>'
    out += '</section><p class="notice">Geordi is a development preview. Published artifacts and optional isolated Semgrep checks are supported, but some checks remain INCOMPLETE. '
    out += 'This dashboard cannot block installations and does not inspect private Home Assistant files.</p>'
    if error:
        out += f'<p class="error">Inventory unavailable: {e(error)}. Cached results, if any, may be stale.</p>'
    if busy:
        out += f'<p class="notice">Scanning {e(busy)}. The page will refresh automatically.</p>'
    out += f'<p class="caption">Inventory checked: {e(updated or "not yet")} · {e(sum(other.values()))} installed items not supported/validated</p>'
    if monitor:
        state_label = "Running" if monitor.get("enabled") else "Monitoring paused"
        out += '<h2>Automatic security monitoring</h2><div class="panel">'
        out += '<p><b>' + e(state_label) + '</b> · Polling every ' + e(monitor.get("poll_minutes")) + ' minutes'
        out += ' · Pending scans: <b>' + e(monitor.get("queued")) + '</b></p>'
        out += '<p class="caption">Last check: ' + e(monitor.get("last_checked")) + ' · Dependency advisory rechecks: ' + ('enabled' if monitor.get("advisories") else 'off') + '</p>'
        if monitor.get("last_event"):
            out += '<p class="caption">Recent activity: ' + e(monitor["last_event"]) + '</p>'
        if monitor.get("error"):
            out += '<p class="error">' + e(monitor["error"]) + '</p>'
        out += '</div>'
    out += '<h2>Installed Marketplace integrations and cards</h2><section class="items">' 
    if not items:
        out += '<div class="panel">No installed integrations were returned. If inventory is unavailable, verify the Marketplace and app permissions.</div>'
    for item in items:
        prev = latest.get(item.repo)
        out += '<article class="item"><h3>' + e(item.name) + '</h3>'
        out += '<div class="tag">' + e(item.kind) + '</div>'
        if item.update:
            out += ' <span class="tag update">Update available</span>'
        out += '<p>' + e(item.repo) + '</p>'
        out += '<p>Installed: <b>' + e(item.installed) + '</b>'
        if item.update:
            out += ' · Offered: ' + e(item.available)
        out += '</p>'
        if prev:
            score = prev.get("score", "?")
            out += f'<p>Last scan ({e(prev.get("version", "unknown ref"))}): <b>{e(score)}/100</b> — {e(prev.get("verdict", ""))} · <a href="report?id={int(prev["id"])}">Details</a></p>'
        else:
            out += '<p class="muted">Not yet scanned</p>'
        if item.update:
            out += '<p><a href="diff?repo=' + e(item.repo) + '">Compare installed vs offered scans</a> (when both available)</p>'
        if not busy:
            out += ('<form method="post" action="scan"><input type="hidden" name="csrf" value="' + e(csrf) + '">'
                    '<input type="hidden" name="repo" value="' + e(item.repo) + '">'
                    '<input type="hidden" name="mode" value="installed">'
                    '<button type="submit">Scan installed version</button></form>')
            if item.update:
                out += (' <form method="post" action="scan"><input type="hidden" name="csrf" value="' + e(csrf) + '">'
                        '<input type="hidden" name="repo" value="' + e(item.repo) + '">'
                        '<input type="hidden" name="mode" value="available">'
                        '<button type="submit">Scan offered update</button></form>')
    out += '</section>'
    out += '<h2>Security model</h2><div class="panel"><p>The list comes from the Home Assistant Marketplace API. '
    out += 'Selecting Scan resolves a pinned GitHub commit, selects the published release asset or source layout, and inspects it in a temporary directory. '
    out += 'This does <b>not</b> execute or install the downloaded integration, and scanning does not require access to /config.</p>'
    out += '<p class="caption">Scores are triage aids, not guarantees. Release asset fingerprints cannot establish what files are already installed locally. Sandbox failures are marked incomplete.</p></div>'
    return page("Dashboard", out, refresh_seconds=12 if busy else None)


def report_page(report: dict, scan_id: int) -> str:
    out = ('<p><a href="./">Back to dashboard</a></p>'
           f'<h2>Scan #{scan_id}: {e(report.get("target","unknown"))}</h2>'
           f'<div class="panel"><b style="font-size:30px">{e(report.get("score","?"))}/100</b>'
           f'<p>{e(report.get("verdict",""))}</p>'
           f'<p class="caption">Incomplete: {e(report.get("incomplete",True))}. Static analysis is not a security certification.</p></div>')
    meta = report.get('inventory', {})
    if isinstance(meta, dict) and meta.get('artifact_selection'):
        digest = str(meta.get('artifact_sha256', ''))
        selection = str(meta.get('artifact_selection', ''))
        out += '<h2>Selected published artifact</h2><div class="panel">'
        out += '<p><b>' + e(selection) + '</b></p>'
        out += '<p class="caption">SHA-256: ' + e(digest[:64]) + '</p>'
        out += '<p class="caption">This fingerprint identifies a fetched upstream payload, not verified local installed bytes.</p></div>'
    out += '<h2>Checks</h2><div class="panel">' 
    for check, status in sorted(report.get("checks", {}).items()):
        out += '<p><b>' + e(check) + '</b>: ' + e(status) + '</p>'
    out += '</div><h2>Findings</h2><section class="items">'
    for finding in report.get("findings", [])[:200]:
        out += ('<article class="item"><span class="tag">' + e(finding.get("severity","")) + '</span>'
                '<h3>' + e(finding.get("rule","")) + '</h3><p>' + e(finding.get("summary","")) + '</p>'
                '<p class="caption">' + e(finding.get("path","")) + ':' + e(finding.get("line",0)) + '</p></article>')
    out += '</section>'
    return page("Scan report", out)


def diff_page(repo: str, old: dict, new: dict) -> str:
    comparison = compare(old, new)
    content = ('<p><a href="./">Back to dashboard</a></p>'
               '<h2>Version comparison: ' + e(repo) + '</h2>'
               '<div class="panel"><p>' + e(old.get('target')) + ' → ' + e(new.get('target')) + '</p>'
               '<p>Score: ' + e(comparison['old_score']) + ' → ' + e(comparison['new_score']) + '</p>'
               '<p>New findings: <b>' + e(len(comparison['new_findings'])) + '</b> · Resolved: <b>' +
               e(len(comparison['resolved_findings'])) + '</b></p>'
               '<p class="caption">Both reports may be incomplete. This comparison does not approve an update.</p></div>')
    for name, key in [('New findings', 'new_findings'), ('Resolved findings', 'resolved_findings')]:
        content += '<h2>' + e(name) + '</h2><section class="items">'
        for finding in comparison[key][:100]:
            content += ('<div class="item"><b>' + e(finding.get('severity','')) + ': ' +
                        e(finding.get('rule','')) + '</b><p>' + e(finding.get('summary','')) +
                        '</p><p class="caption">' + e(finding.get('path','')) + ':' +
                        e(finding.get('line',0)) + '</p></div>')
        if not comparison[key]:
            content += '<p class="muted">None detected</p>'
        content += '</section>'
    return page('Version comparison', content)
