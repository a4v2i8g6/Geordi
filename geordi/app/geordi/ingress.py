"""Ingress-only dashboard, manual scans, and persistent automatic scan monitoring."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from contextlib import closing
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from . import dashboard
from .analyze import scan_directory
from .artifacts import load_installable
from .semgrep_engine import run_semgrep
from .marketplace import Installed, MarketplaceError, get_inventory
from .reports import store_report, compare
from .monitor import read_latest, Monitor
from .notify import Notifier

MAX_POST = 2048
ALLOWED_SOURCE_IP = "172.30.32.2"


def allowed_peer(ip: str, *, dev: bool = False) -> bool:
    return ip in ("127.0.0.1", "::1") if dev else ip == ALLOWED_SOURCE_IP


class AppState:
    def __init__(self, db: Path, inventory_fn: Callable[[], tuple[list[Installed], dict[str, int]]] = get_inventory,
                 scanner: Callable[[str, str], dict] | None = None, *, advisories: bool = False):
        self.db = db
        self.inventory_fn = inventory_fn
        self.scanner = scanner or (lambda repo, ref: self.scan_repo(
            repo, ref, kind=self._kind_for_repo(repo), advisories=advisories))
        self.monitor: Monitor | None = None
        self.csrf = secrets.token_urlsafe(32)
        self.items: list[Installed] = []
        self.other: dict[str, int] = {}
        self.last_check = 0.0
        self.checked_at = ""
        self.error = ""
        self.busy = ""
        self.lock = threading.Lock()

    def _kind_for_repo(self, repo: str) -> str:
        with self.lock:
            item = next((item for item in self.items if item.repo == repo), None)
        return item.kind if item else 'integration'

    @staticmethod
    def scan_repo(repo: str, ref: str, *, kind: str = "integration", advisories: bool = False) -> dict:
        from .resources import require_scan_memory
        require_scan_memory()
        with tempfile.TemporaryDirectory(prefix="geordi-scan-") as scratch:
            artifact = load_installable(repo, ref, kind, Path(scratch),
                                         token=os.getenv('GITHUB_TOKEN'))
            report = scan_directory(artifact.root, target=artifact.label,
                                    source=artifact.selection, commit=artifact.sha)
            report.checks['marketplace_artifact_parity'] = artifact.parity
            report.inventory['artifact_selection'] = artifact.selection
            report.inventory['artifact_sha256'] = artifact.artifact_sha256
            report.inventory['artifact_notes'] = list(artifact.notes)
            run_semgrep(artifact.root, report)
            if advisories:
                from .advisories import check_osv
                check_osv(report)
            return report.to_dict()

    def refresh(self, *, force: bool = False) -> None:
        with self.lock:
            if not force and self.last_check and time.monotonic() - self.last_check < 60:
                return
            # Prevent simultaneous refresh requests from overloading Core.
            self.last_check = time.monotonic()
        try:
            items, other = self.inventory_fn()
        except (MarketplaceError, OSError, ValueError) as exc:
            with self.lock:
                self.error = str(exc)[:180]
            return
        with self.lock:
            self.items, self.other = items, other
            self.checked_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            self.error = ""

    def latest(self) -> dict[str, dict]:
        if not self.db.exists():
            return {}
        with closing(sqlite3.connect(self.db)) as cx:
            cx.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, target TEXT NOT NULL, "
                       "created TEXT NOT NULL, result TEXT NOT NULL)")
            rows = cx.execute("SELECT id,result FROM scans ORDER BY id DESC LIMIT 300").fetchall()
        found: dict[str, dict] = {}
        for i, raw in rows:
            try:
                report = json.loads(raw)
            except (ValueError, TypeError):
                continue
            target = report.get("target", "")
            if not isinstance(target, str) or "@" not in target:
                continue
            repo = target.split("@", 1)[0]
            if repo not in found:
                found[repo] = {"id": i, "score": report.get("score"), "verdict": report.get("verdict"), "version": target.split("@", 1)[1]}
        return found

    def get_report(self, scan_id: int) -> dict | None:
        if scan_id < 1 or scan_id > 1_000_000_000 or not self.db.exists():
            return None
        with closing(sqlite3.connect(self.db)) as cx:
            result = cx.execute("SELECT result FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not result:
            return None
        try:
            return json.loads(result[0])
        except (TypeError, ValueError):
            return None

    def request_scan(self, repo: str, mode: str, *,
                     on_complete: Callable[[dict, int], None] | None = None,
                     on_failure: Callable[[], None] | None = None) -> bool:
        if mode not in ("installed", "available"):
            return False
        with self.lock:
            item = next((it for it in self.items if it.repo == repo), None)
            if self.busy or not item:
                return False
            version = item.installed if mode == "installed" else item.available
            if not version or mode == "available" and not item.update:
                return False
            self.busy = f"{repo}@{version}"
        threading.Thread(target=self._run_scan, args=(repo, version, on_complete, on_failure), daemon=True, name="geordi-scan").start()
        return True

    def _run_scan(self, repo: str, version: str,
                  on_complete: Callable[[dict, int], None] | None = None,
                  on_failure: Callable[[], None] | None = None) -> None:
        try:
            report = self.scanner(repo, version)
            scan_id = store_report(self.db, report)
            with self.lock:
                self.error = ""
        except Exception as exc:
            # Do not surface arbitrary exception text from external code or servers.
            with self.lock:
                self.error = f"Scan failed ({type(exc).__name__}); review the app logs"
            if on_failure:
                try:
                    on_failure()
                except Exception:
                    pass
        else:
            if on_complete:
                try:
                    on_complete(report, scan_id)
                except Exception:
                    with self.lock:
                        self.error = "Scan saved; monitoring follow-up failed"
        finally:
            with self.lock:
                self.busy = ""


class Handler(BaseHTTPRequestHandler):
    server_version = "Geordi/0.4"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # No request URIs, query strings, tokens, or user names in logs.
        return

    def _secure(self) -> bool:
        if not allowed_peer(self.client_address[0], dev=self.server.dev_mode):
            self._respond(HTTPStatus.FORBIDDEN, "Access denied", "text/plain")
            return False
        return True

    def _respond(self, status: HTTPStatus, content: str, typ: str = "text/html; charset=utf-8") -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", typ)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Content-Security-Policy", dashboard.CSP)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if not self._secure():
            return
        if self.path in ("/", ""):
            self.server.state.refresh()
            st = self.server.state
            with st.lock:
                content = dashboard.home(st.items[:], st.other.copy(), st.latest(), st.csrf,
                                         st.busy, st.error, st.checked_at,
                                         monitor=st.monitor.status() if st.monitor else None)
            self._respond(HTTPStatus.OK, content)
            return
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/report":
            try:
                query = urllib.parse.parse_qs(url.query, strict_parsing=True, max_num_fields=2)
                scan_id = int(query["id"][0]) if len(query["id"]) == 1 else 0
            except (ValueError, KeyError):
                scan_id = 0
            report = self.server.state.get_report(scan_id)
            if report is None:
                self._respond(HTTPStatus.NOT_FOUND, "Report unavailable", "text/plain")
            else:
                self._respond(HTTPStatus.OK, dashboard.report_page(report, scan_id))
            return
        if url.path == "/diff":
            try:
                query = urllib.parse.parse_qs(url.query, strict_parsing=True, max_num_fields=2)
                repo = query.get("repo", [""])
                if len(repo) != 1:
                    raise ValueError("Invalid repository")
                from .marketplace import valid_repo
                if not valid_repo(repo[0]):
                    raise ValueError("Invalid repository")
                with self.server.state.lock:
                    item = next((x for x in self.server.state.items if x.repo == repo[0]), None)
                if not item or not item.update:
                    raise ValueError("No offered update")
                old = read_latest(self.server.state.db, f"{item.repo}@{item.installed}")
                new = read_latest(self.server.state.db, f"{item.repo}@{item.available}")
                if not old or not new:
                    raise ValueError("Version not scanned")
            except (ValueError, IndexError):
                self._respond(HTTPStatus.NOT_FOUND, "Comparison unavailable", "text/plain")
            else:
                self._respond(HTTPStatus.OK, dashboard.diff_page(item.repo, old[1], new[1]))
            return
        self._respond(HTTPStatus.NOT_FOUND, "Not found", "text/plain")

    def do_POST(self) -> None:
        if not self._secure():
            return
        if self.path != "/scan" or self.headers.get_content_type() != "application/x-www-form-urlencoded":
            self._respond(HTTPStatus.NOT_FOUND, "Not found", "text/plain")
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if size < 1 or size > MAX_POST:
            self.close_connection = True
            self._respond(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Invalid form length", "text/plain")
            return
        body = self.rfile.read(size)
        try:
            fields = urllib.parse.parse_qs(body.decode("utf-8", "strict"), strict_parsing=True, max_num_fields=4)
        except (ValueError, UnicodeError):
            self._respond(HTTPStatus.BAD_REQUEST, "Malformed request", "text/plain")
            return
        token = fields.get("csrf", [])
        repo = fields.get("repo", [])
        mode = fields.get("mode", [])
        if len(token) != 1 or not secrets.compare_digest(token[0], self.server.state.csrf):
            self._respond(HTTPStatus.FORBIDDEN, "Invalid request token", "text/plain")
            return
        if len(repo) != 1 or len(mode) != 1 or not self.server.state.request_scan(repo[0], mode[0]):
            self._respond(HTTPStatus.CONFLICT, "Unsupported item or a scan is already running", "text/plain")
            return
        # Relative destination: Home Assistant ingress paths change per installation.
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "./")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self) -> None:
        self._respond(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed", "text/plain")


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, host: str, port: int, state: AppState, *, dev_mode: bool = False):
        if dev_mode and host not in ("127.0.0.1", "::1"):
            raise ValueError("Dev mode must bind to loopback")
        self.state = state
        self.dev_mode = dev_mode
        super().__init__((host, port), Handler)


def serve(port: int = 8099, host: str = "0.0.0.0", *, dev: bool = False,
          db: Path | None = None, monitor_enabled: bool = True,
          poll_minutes: int = 5, advisory_rechecks: bool = False,
          mobile_target: str = "", daily_limit: int = 12) -> None:
    if not dev and not os.getenv("SUPERVISOR_TOKEN"):
        raise MarketplaceError("Refusing to expose ingress without Supervisor authentication")
    state = AppState(db or Path("/data/scans.db"),
                     inventory_fn=(lambda: ([], {})) if dev else get_inventory,
                     advisories=advisory_rechecks)
    if dev:
        host = "127.0.0.1"
    if not dev:
        state.monitor = Monitor(state, notifier=Notifier(mobile_target=mobile_target),
                                scan_enabled=monitor_enabled,
                                poll_seconds=poll_minutes * 60,
                                advisory_rechecks=advisory_rechecks,
                                scan_limit_per_day=daily_limit)
    with Server(host, port, state, dev_mode=dev) as server:
        if state.monitor:
            state.monitor.start()
        try:
            print(f"Geordi ingress listening on {host}:{port} (dev={dev})", flush=True)
            server.serve_forever(poll_interval=0.4)
        finally:
            if state.monitor:
                state.monitor.close()
