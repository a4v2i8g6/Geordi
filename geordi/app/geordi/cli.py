from __future__ import annotations
import argparse
import json
import sys
import tempfile
from pathlib import Path
from .analyze import scan_directory
from .advisories import check_osv, recheck_report
from .github import REPO_RE
from .artifacts import load_installable
from .semgrep_engine import run_semgrep
from .reports import compare, history, save_html, save_json, store_report
from .safeio import UnsafeInput


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="geordi", description="Read-only HA security scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan local dir or GitHub owner/repo")
    scan.add_argument("target")
    scan.add_argument("--ref", help="Git branch, tag or commit (remote only)")
    scan.add_argument("--kind", choices=["integration", "card"], default="integration", help="Marketplace package kind for remote scans")
    scan.add_argument("--no-semgrep", action="store_true", help="Skip isolated Semgrep; mark report incomplete")
    scan.add_argument("--osv", action="store_true", help="Send package names+versions to OSV advisories")
    scan.add_argument("--json", type=Path, help="Write JSON report")
    scan.add_argument("--html", type=Path, help="Write a self-contained HTML report")
    scan.add_argument("--db", type=Path, help="Append report to SQLite")
    recheck = sub.add_parser("recheck", help="Requery advisories using only stored packages")
    recheck.add_argument("report", type=Path)
    recheck.add_argument("--json", type=Path, required=True)
    recheck.add_argument("--db", type=Path)
    cp = sub.add_parser("compare", help="Compare two JSON reports")
    cp.add_argument("old", type=Path)
    cp.add_argument("new", type=Path)
    hist = sub.add_parser("history", help="Show recent scan history")
    hist.add_argument("--db", type=Path, required=True)
    web = sub.add_parser("serve", help="Run Home Assistant ingress dashboard")
    web.add_argument("--port", type=int, default=8099)
    web.add_argument("--dev", action="store_true", help="Loopback-only dashboard preview (no HA access)")
    web.add_argument("--db", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            from .ingress import serve
            serve(args.port, dev=args.dev, db=args.db)
            return 0
        if args.command == "recheck":
            prior = json.loads(args.report.read_text(encoding="utf-8"))
            report = recheck_report(prior)
            check_osv(report)
            new = report.to_dict()
            save_json(new, args.json)
            if args.db:
                store_report(args.db, new)
            print(f"Advisory recheck complete: {new['target']}; incomplete={new['incomplete']}")
            return 0 if new['checks'].get('advisories') == 'completed' else 2
        if args.command == "compare":
            print(json.dumps(compare(json.loads(args.old.read_text()), json.loads(args.new.read_text())), indent=2))
            return 0
        if args.command == "history":
            print(json.dumps(history(args.db), indent=2))
            return 0
        local = Path(args.target).expanduser()
        if local.exists():
            if args.ref:
                raise UnsafeInput("--ref is only supported for GitHub scans")
            report = scan_directory(local, target=str(local), source="local")
            if not args.no_semgrep:
                run_semgrep(local, report)
        else:
            if not REPO_RE.fullmatch(args.target):
                raise UnsafeInput("Local directory not found; remote target must be GitHub owner/repo")
            with tempfile.TemporaryDirectory(prefix="geordi-") as td:
                artifact = load_installable(args.target, args.ref, args.kind, Path(td),
                                            token=__import__("os").getenv("GITHUB_TOKEN"))
                report = scan_directory(artifact.root, target=artifact.label,
                                        source=artifact.selection, commit=artifact.sha)
                report.checks["marketplace_artifact_parity"] = artifact.parity
                report.inventory["artifact_selection"] = artifact.selection
                report.inventory["artifact_sha256"] = artifact.artifact_sha256
                report.inventory["artifact_notes"] = list(artifact.notes)
                if not args.no_semgrep:
                    run_semgrep(artifact.root, report)
        if args.osv:
            check_osv(report)
        obj = report.to_dict()
        if args.json:
            save_json(obj, args.json)
        if args.html:
            save_html(obj, args.html)
        if args.db:
            store_report(args.db, obj)
        print(f"{obj['target']}: {obj['score']}/100 ({obj['verdict']}); "
              f"{len(obj['findings'])} findings; incomplete={obj['incomplete']}")
        for finding in obj["findings"][:20]:
            print(f"  {finding['severity']:8} {finding['path']}:{finding['line']} {finding['rule']}")
        return 0 if obj["score"] >= 90 and not obj["incomplete"] else 2
    except (OSError, UnsafeInput, ValueError, json.JSONDecodeError) as e:
        print("Scan failed: " + str(e), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
