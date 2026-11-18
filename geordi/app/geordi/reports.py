"""Escaped static HTML and append-only SQLite history."""
from __future__ import annotations
import html
import json
import sqlite3
from contextlib import closing
from pathlib import Path


def save_json(report: dict, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def save_html(report: dict, dest: Path) -> None:
    esc = lambda obj: html.escape(str(obj), quote=True)
    rows = "\n".join(
        "<tr><td>" + esc(x["severity"]) + "</td><td>" + esc(x["rule"]) + "</td><td>" +
        esc(x["summary"]) + "</td><td>" + esc(x["path"]) + ":" + esc(x["line"]) + "</td></tr>"
        for x in report["findings"])
    data = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Geordi Report</title>
<style>body{{font:16px system-ui;margin:3rem auto;max-width:1100px;padding:0 1rem;background:#101b28;color:#e4ebf5}}
h1,h2{{color:#fff}}.meta{{opacity:.8}}table{{width:100%;border-collapse:collapse}}th,td{{padding:.65rem;text-align:left;border-bottom:1px solid #42536a;vertical-align:top;word-break:break-word}}
strong{{font-size:2.2rem}}.warning{{padding:.7rem;border:1px solid #d8a657;border-radius:.4rem}}</style></head><body>
<h1>Geordi</h1><p class="meta">{esc(report['target'])}</p><p><strong>{esc(report['score'])}/100</strong> — {esc(report['verdict'])}</p>
<p class="warning">Incomplete: {esc(report['incomplete'])}. Static analysis cannot guarantee safety. Check missing capabilities.</p>
<h2>Checks</h2><table><tr><th>Check</th><th>Status</th></tr>'''
    for k,v in report["checks"].items():
        data += f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
    data += f'''</table><h2>Findings ({len(report['findings'])})</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Summary</th><th>Location</th></tr>{rows}</table>
<p class="meta">Generated {esc(report['generated_at'])}. No external scripts or images loaded.</p></body></html>'''
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(data, encoding="utf-8")


def store_report(db: Path, report: dict) -> int:
    db.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db)) as cx, cx:
        cx.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, target TEXT NOT NULL, "
                   "created TEXT NOT NULL, result TEXT NOT NULL)")
        cur = cx.execute("INSERT INTO scans(target, created, result) VALUES(?,?,?)",
                         (report["target"], report["generated_at"], json.dumps(report)))
        return cur.lastrowid


def history(db: Path) -> list[dict]:
    if not db.exists():
        return []
    with closing(sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)) as cx:
        return [{"id": x[0], "target": x[1], "created": x[2]} for x in cx.execute(
            "SELECT id,target,created FROM scans ORDER BY id DESC LIMIT 50")]


def compare(old: dict, new: dict) -> dict:
    a = {x["id"]: x for x in old["findings"]}
    b = {x["id"]: x for x in new["findings"]}
    return {"old_score": old["score"], "new_score": new["score"],
            "new_findings": [b[x] for x in sorted(b.keys() - a.keys())],
            "resolved_findings": [a[x] for x in sorted(a.keys() - b.keys())],
            "common_findings": len(a.keys() & b.keys()),
            "old_incomplete": old["incomplete"], "new_incomplete": new["incomplete"]}
