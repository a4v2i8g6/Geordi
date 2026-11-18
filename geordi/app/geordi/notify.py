"""Strict, fixed-destination Home Assistant notification client.

Only persistent_notification.create and, if explicitly configured and present in the
HA service registry, notify.<service> are used. No scanned string is submitted as
an endpoint, a template, an arbitrary service, or HTML.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

HOST = "http://supervisor"
MAX_RESPONSE = 128 * 1024
_TARGET = re.compile(r"[a-z0-9_]{1,100}\Z")
_ID = re.compile(r"geordi_[a-z0-9_]{1,70}\Z")


class NotificationError(Exception):
    """Intentionally excludes response bodies and authentication credentials."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise NotificationError("Supervisor redirect refused")


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _call(path: str, token: str, body: dict | None = None) -> Any:
    # The HTTP destination is constant; the sole dynamic suffix is validated below.
    if path not in ("/core/api/services", "/core/api/services/persistent_notification/create") and not (
        path.startswith("/core/api/services/notify/") and
        _TARGET.fullmatch(path.removeprefix("/core/api/services/notify/"))
    ):
        raise NotificationError("Disallowed Home Assistant API path")
    if not token:
        raise NotificationError("Supervisor token unavailable")
    method = "POST" if body is not None else "GET"
    raw = json.dumps(body, ensure_ascii=True).encode() if body is not None else None
    request = urllib.request.Request(HOST + path, data=raw, method=method, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "User-Agent": "geordi/0.4",
    })
    try:
        with OPENER.open(request, timeout=10) as resp:
            data = resp.read(MAX_RESPONSE + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NotificationError("Supervisor notification request failed") from exc
    if len(data) > MAX_RESPONSE:
        raise NotificationError("Supervisor reply exceeds limit")
    if not data.strip():
        return None
    try:
        return json.loads(data)
    except ValueError as exc:
        raise NotificationError("Invalid Supervisor JSON response") from exc


class Notifier:
    def __init__(self, *, token: str | None = None, mobile_target: str = ""):
        self.token = token if token is not None else os.environ.get("SUPERVISOR_TOKEN", "")
        self.mobile_target = mobile_target
        if mobile_target and not _TARGET.fullmatch(mobile_target):
            raise NotificationError("Invalid optional notify service name")
        self._verified_target: bool | None = None

    def _target_available(self) -> bool:
        if not self.mobile_target:
            return False
        if self._verified_target is None:
            services = _call("/core/api/services", self.token)
            if not isinstance(services, list):
                raise NotificationError("Could not verify notify service")
            self._verified_target = any(
                isinstance(group, dict) and group.get("domain") == "notify" and
                isinstance(group.get("services"), dict) and self.mobile_target in group["services"]
                for group in services
            )
        return self._verified_target

    def send(self, title: str, message: str, notification_id: str) -> None:
        if not _ID.fullmatch(notification_id):
            raise NotificationError("Invalid notification identifier")
        title = title[:100]
        message = message[:1200]
        if not title or not message:
            raise NotificationError("Empty notification")
        _call("/core/api/services/persistent_notification/create", self.token, {
            "title": title, "message": message, "notification_id": notification_id,
        })
        if self._target_available():
            _call("/core/api/services/notify/" + self.mobile_target, self.token, {
                "title": title, "message": message,
            })
