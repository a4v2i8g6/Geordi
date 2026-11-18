"""Persistent, serial, bounded automatic scan monitor for HA Marketplace changes.

The monitor never sends install commands and never reads Home Assistant /config.
Scan jobs are persisted before the snapshot advances, preventing lost events on
process restart. Incomplete scans remain incomplete; no auto-approval exists.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .advisories import check_osv, recheck_report
from .marketplace import Installed
from .notify import Notifier, NotificationError
from .reports import compare, store_report

PRIORITY = {"offered": 0, "installed_changed": 1, "new_install": 2,
            "baseline_offered": 3, "baseline_installed": 4}
MAX_TASKS = 2000
MAX_PER_DAY = 24


def iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _db(db: Path) -> sqlite3.Connection:
    db.parent.mkdir(parents=True, exist_ok=True)
    cx = sqlite3.connect(db, timeout=10)
    cx.execute("PRAGMA busy_timeout=10000")
    cx.execute("CREATE TABLE IF NOT EXISTS monitor_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    cx.execute("""CREATE TABLE IF NOT EXISTS monitor_queue (
        id INTEGER PRIMARY KEY, repo TEXT NOT NULL, ref TEXT NOT NULL,
        trigger TEXT NOT NULL, prior_ref TEXT NOT NULL DEFAULT '',
        queued_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
        next_try REAL NOT NULL DEFAULT 0,
        UNIQUE(repo,ref))""")
    cx.execute("""CREATE TABLE IF NOT EXISTS monitor_advisories (
        target TEXT PRIMARY KEY, attempted_at REAL NOT NULL)""")
    cx.execute("CREATE INDEX IF NOT EXISTS idx_monitor_try ON monitor_queue(next_try)")
    return cx


def read_latest(db: Path, target: str) -> tuple[int, dict] | None:
    if not db.exists():
        return None
    with closing(sqlite3.connect(db, timeout=10)) as cx:
        # Missing table is legitimate for a fresh install.
        try:
            rows = cx.execute("SELECT id,result FROM scans WHERE target=? ORDER BY id DESC LIMIT 1", (target,)).fetchall()
        except sqlite3.OperationalError:
            return None
    if not rows:
        return None
    try:
        obj = json.loads(rows[0][1])
        return (int(rows[0][0]), obj) if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        return None


def _snapshot(items: list[Installed]) -> dict[str, dict[str, str]]:
    return {i.repo: {"installed": i.installed, "available": i.available} for i in items}


@dataclass(frozen=True)
class Work:
    id: int
    repo: str
    ref: str
    trigger: str
    prior_ref: str
    attempts: int


class Monitor:
    def __init__(self, state: Any, *, notifier: Notifier | Any | None = None,
                 scan_enabled: bool = True, poll_seconds: int = 300,
                 advisory_rechecks: bool = False, advisory_hours: int = 24,
                 scan_limit_per_day: int = 12, now_fn: Callable[[], float] = time.time):
        if not 60 <= poll_seconds <= 86400 or not 1 <= advisory_hours <= 168 or not 1 <= scan_limit_per_day <= MAX_PER_DAY:
            raise ValueError("monitor limits outside safe range")
        self.state = state
        self.db = state.db
        self.notifier = notifier
        self.scan_enabled = scan_enabled
        self.poll_seconds = poll_seconds
        self.advisory_rechecks = advisory_rechecks
        self.advisory_hours = advisory_hours
        self.scan_limit_per_day = scan_limit_per_day
        self.now_fn = now_fn
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self._tick_lock = threading.Lock()
        self.last_error = ""
        self.last_event = ""
        self.last_tick = 0.0
        self.last_notify_error = ""
        with closing(_db(self.db)) as cx:
            cx.commit()

    def start(self) -> None:
        if self.thread is not None:
            return
        self.thread = threading.Thread(target=self.run_forever, name="geordi-monitor", daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=2)

    def run_forever(self) -> None:
        while not self.stop.is_set():
            try:
                self.tick()
            except Exception as exc:
                # Never include exception messages: network errors can contain URIs.
                self.last_error = f"Monitor error ({type(exc).__name__}); consult app logs"
            self.stop.wait(self.poll_seconds)

    def _enqueue(self, cx: sqlite3.Connection, repo: str, ref: str, trigger: str,
                 prior_ref: str = "") -> None:
        if read_latest(self.db, f"{repo}@{ref}") is not None:
            return
        if cx.execute("SELECT COUNT(*) FROM monitor_queue").fetchone()[0] >= MAX_TASKS:
            self.last_error = "Scan queue reached its size limit"
            return
        cx.execute("""INSERT INTO monitor_queue(repo,ref,trigger,prior_ref,queued_at)
                      VALUES (?,?,?,?,?) ON CONFLICT(repo,ref) DO UPDATE SET
                        trigger=CASE WHEN ? < (CASE monitor_queue.trigger
                            WHEN 'offered' THEN 0 WHEN 'installed_changed' THEN 1
                            WHEN 'new_install' THEN 2 WHEN 'baseline_offered' THEN 3 ELSE 4 END)
                            THEN excluded.trigger ELSE monitor_queue.trigger END,
                        prior_ref=CASE WHEN excluded.prior_ref!='' THEN excluded.prior_ref
                            ELSE monitor_queue.prior_ref END""",
                   (repo, ref, trigger, prior_ref, iso(), PRIORITY[trigger]))

    def _record_inventory(self, items: list[Installed]) -> None:
        new = _snapshot(items)
        with closing(_db(self.db)) as cx, cx:
            old_row = cx.execute("SELECT value FROM monitor_settings WHERE key='snapshot'").fetchone()
            try:
                old = json.loads(old_row[0]) if old_row else None
            except ValueError:
                old = None
            if old is not None and not isinstance(old, dict):
                old = None
            for item in items:
                prev = old.get(item.repo) if isinstance(old, dict) else None
                if not isinstance(prev, dict):
                    trig = "baseline_installed" if old is None else "new_install"
                    self._enqueue(cx, item.repo, item.installed, trig)
                elif prev.get("installed") != item.installed:
                    prior = str(prev.get("installed") or "")[:128]
                    self._enqueue(cx, item.repo, item.installed, "installed_changed", prior)
                elif not read_latest(self.db, f"{item.repo}@{item.installed}"):
                    self._enqueue(cx, item.repo, item.installed, "baseline_installed")
                if item.update:
                    offered_changed = not isinstance(prev, dict) or prev.get("available") != item.available
                    trig = ("baseline_offered" if old is None else "offered") if offered_changed else "baseline_offered"
                    self._enqueue(cx, item.repo, item.available, trig, item.installed)
            # Obsolete jobs are not scanned even if a version is changed/uninstalled.
            live = {f"{i.repo}@{v}" for i in items for v in [i.installed, i.available] if v}
            for job_id, repo, ref in cx.execute("SELECT id,repo,ref FROM monitor_queue").fetchall():
                if f"{repo}@{ref}" not in live:
                    cx.execute("DELETE FROM monitor_queue WHERE id=?", (job_id,))
            cx.execute("INSERT INTO monitor_settings(key,value) VALUES('snapshot',?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(new),))

    def _next_work(self, items: list[Installed]) -> Work | None:
        allowed = {i.repo: (i.installed, i.available if i.update else "") for i in items}
        with closing(_db(self.db)) as cx, cx:
            candidates = cx.execute("""SELECT id,repo,ref,trigger,prior_ref,attempts
                         FROM monitor_queue WHERE next_try<=? ORDER BY
                         CASE trigger WHEN 'offered' THEN 0 WHEN 'installed_changed' THEN 1
                         WHEN 'new_install' THEN 2 WHEN 'baseline_offered' THEN 3 ELSE 4 END,
                         id LIMIT 100""", (self.now_fn(),)).fetchall()
            for row in candidates:
                job = Work(*row)
                if job.ref not in allowed.get(job.repo, ()) or read_latest(self.db, f"{job.repo}@{job.ref}"):
                    cx.execute("DELETE FROM monitor_queue WHERE id=?", (job.id,))
                    continue
                return job
        return None

    def _quota(self) -> bool:
        # Daily quota resets on UTC day changes; timestamps are never user supplied.
        day = datetime.fromtimestamp(self.now_fn(), timezone.utc).strftime('%Y-%m-%d')
        with closing(_db(self.db)) as cx, cx:
            row = cx.execute("SELECT value FROM monitor_settings WHERE key='daily_count'").fetchone()
            try:
                old = json.loads(row[0]) if row else {}
            except (ValueError, TypeError):
                old = {}
            count = int(old.get('count', 0)) if old.get('day') == day else 0
            if count >= self.scan_limit_per_day:
                return False
            cx.execute("INSERT INTO monitor_settings(key,value) VALUES('daily_count',?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (json.dumps({'day': day, 'count': count + 1}),))
            return True

    def tick(self) -> None:
        if not self._tick_lock.acquire(blocking=False):
            return
        try:
            self.state.refresh(force=True)
            with self.state.lock:
                failed = bool(self.state.error) and not self.state.checked_at
                # On refresh errors, never ingest a possibly stale snapshot.
                failed = bool(self.state.error)
                items = list(self.state.items)
            self.last_tick = self.now_fn()
            if failed:
                self.last_error = "Inventory refresh failed; monitoring paused until retry"
                return
            self.last_error = ""
            self._record_inventory(items)
            if not self.scan_enabled:
                return
            with self.state.lock:
                busy = bool(self.state.busy)
            if busy:
                return
            job = self._next_work(items)
            if job is not None:
                if not self._quota():
                    return
                mode = "installed" if any(i.repo == job.repo and i.installed == job.ref for i in items) else "available"
                accepted = self.state.request_scan(job.repo, mode,
                    on_complete=lambda report, scan_id: self._completed(job, report, scan_id),
                    on_failure=lambda: self._failed(job))
                if accepted:
                    self.last_event = f"Queued {job.repo}@{job.ref} ({job.trigger})"
                else:
                    # Refund quota if scan failed to enter queue.
                    self._refund()
                return
            if self.advisory_rechecks:
                self._recheck_one()
        finally:
            self._tick_lock.release()

    def _refund(self) -> None:
        with closing(_db(self.db)) as cx, cx:
            row = cx.execute("SELECT value FROM monitor_settings WHERE key='daily_count'").fetchone()
            if row:
                val = json.loads(row[0]); val['count'] = max(0, val['count'] - 1)
                cx.execute("UPDATE monitor_settings SET value=? WHERE key='daily_count'", (json.dumps(val),))

    def _failed(self, work: Work) -> None:
        with closing(_db(self.db)) as cx, cx:
            attempts = work.attempts + 1
            cx.execute("UPDATE monitor_queue SET attempts=?,next_try=? WHERE id=?",
                       (attempts, self.now_fn() + min(3600 * (2 ** min(attempts - 1, 4)), 86400), work.id))
        self.last_event = f"Scan failed: {work.repo}@{work.ref}; retry scheduled"

    def _completed(self, work: Work, report: dict, scan_id: int) -> None:
        with closing(_db(self.db)) as cx, cx:
            cx.execute("DELETE FROM monitor_queue WHERE id=?", (work.id,))
        self.last_event = f"Scanned {work.repo}@{work.ref} (report #{scan_id})"
        # Warn about an update compared with the currently installed (or previous) ref.
        prior = read_latest(self.db, f"{work.repo}@{work.prior_ref}") if work.prior_ref else None
        new_findings = len(compare(prior[1], report)['new_findings']) if prior else 0
        risky = any(f.get('severity') in ('critical','high') for f in report.get('findings', []))
        # Initial inventory: notify only for high/critical findings, not every incomplete scan.
        relevant = risky or (work.trigger in ('offered','installed_changed','new_install'))
        if not relevant:
            return
        score = int(report.get('score', 0))
        total = len(report.get('findings', []))
        kind = "Update offered" if work.trigger.endswith('offered') or work.trigger == 'offered' else "Installed version"
        msg = (f"{kind}: {work.repo}@{work.ref}. Score: {score}/100. "
               f"Findings: {total}. New compared with baseline: {new_findings if prior else 'not available'}. "
               f"{'INCOMPLETE scan; manual review required.' if report.get('incomplete') else 'Review scan before installing.'} "
               f"Open Geordi in the Home Assistant sidebar and view report #{scan_id}.")
        key = hashlib.sha256(f"{work.repo}@{work.ref}".encode()).hexdigest()[:24]
        self._notify("Geordi: extension security report", msg, "geordi_" + key)

    def _notify(self, title: str, message: str, notification_id: str) -> None:
        if self.notifier is None:
            return
        try:
            self.notifier.send(title, message, notification_id)
            self.last_notify_error = ""
        except (NotificationError, OSError, ValueError) as exc:
            self.last_notify_error = f"Notification delivery failed ({type(exc).__name__})"

    def _recheck_one(self) -> None:
        # Recheck only a previous report with an exact pinned runtime package list.
        # Advisory lookup is a network operation; it never reads source code.
        if not self.db.exists():
            return
        now = self.now_fn()
        with closing(_db(self.db)) as cx, cx:
            try:
                rows = cx.execute("SELECT target,result FROM scans ORDER BY id DESC LIMIT 500").fetchall()
            except sqlite3.OperationalError:
                return
            seen = set()
            for target, raw in rows:
                if target in seen:
                    continue
                seen.add(target)
                try:
                    previous = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(previous, dict):
                    continue
                packages = previous.get('packages', [])
                valid = [p for p in packages if isinstance(p, dict) and p.get('scope') == 'runtime'
                         and p.get('name') and p.get('version') and p.get('version') not in ('*', '?')]
                if not valid:
                    continue
                prior = cx.execute("SELECT attempted_at FROM monitor_advisories WHERE target=?", (target,)).fetchone()
                if prior and now - prior[0] < self.advisory_hours * 3600:
                    continue
                # Mark attempted before network request, so failures cannot hot-loop.
                cx.execute("INSERT INTO monitor_advisories(target,attempted_at) VALUES (?,?) "
                           "ON CONFLICT(target) DO UPDATE SET attempted_at=excluded.attempted_at", (target, now))
                break
            else:
                return
        report = recheck_report(previous)
        check_osv(report)
        if report.checks.get('advisories') != 'completed':
            self.last_event = f"Advisory recheck unavailable: {target}"
            return
        new = report.to_dict()
        old_advisories = {f['id'] for f in previous.get('findings', []) if f.get('rule') == 'osv-advisory'}
        new_advisories = {f['id'] for f in new.get('findings', []) if f.get('rule') == 'osv-advisory'}
        scan_id = store_report(self.db, new)
        self.last_event = f"Advisories checked: {target} (report #{scan_id})"
        if new_advisories - old_advisories:
            key = hashlib.sha256(target.encode()).hexdigest()[:24]
            self._notify("Geordi: new dependency advisory",
                         f"New advisories for {target}: {len(new_advisories-old_advisories)}. "
                         f"Open Geordi and review report #{scan_id}. This recheck did not analyze source code.",
                         "geordi_" + key)

    def status(self) -> dict[str, Any]:
        with closing(_db(self.db)) as cx:
            queue = cx.execute("SELECT COUNT(*) FROM monitor_queue").fetchone()[0]
        return {
            "enabled": self.scan_enabled, "poll_minutes": self.poll_seconds // 60,
            "queued": queue, "last_checked": datetime.fromtimestamp(self.last_tick, timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if self.last_tick else "Not yet",
            "last_event": self.last_event, "error": self.last_error or self.last_notify_error,
            "advisories": self.advisory_rechecks,
        }
