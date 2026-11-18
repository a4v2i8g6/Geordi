"""Minimal read-only Home Assistant Marketplace inventory client.

Home Assistant Core's WebSocket protocol is accessed only through the app's
Supervisor proxy. No installation, configuration or service-write commands exist.
The WebSocket wire implementation is intentionally small and bounded.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import struct
from dataclasses import dataclass
from typing import Any

SUPERVISOR_HOST = "supervisor"
SUPERVISOR_PORT = 80
WEBSOCKET_PATH = "/core/websocket"
MAX_MESSAGE = 8 * 1024 * 1024
MAX_HANDSHAKE = 8192
MAX_ITEMS = 20_000
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+/-]{0,127}\Z")
_ALLOWED_COMMANDS = ("marketplace/repositories/list", "hacs/repositories/list")


class MarketplaceError(Exception):
    """A bounded error; never includes credentials or response bodies."""


@dataclass(frozen=True, slots=True)
class Installed:
    repo: str
    name: str
    kind: str
    installed: str
    available: str
    custom: bool

    @property
    def update(self) -> bool:
        return bool(self.available and self.available != self.installed)


def valid_repo(value: str) -> bool:
    if not _REPO.fullmatch(value):
        return False
    owner, name = value.split("/", 1)
    return all(p not in (".", "..") and ".." not in p for p in (owner, name))


def valid_ref(value: str) -> bool:
    return bool(_REF.fullmatch(value)) and ".." not in value and not value.endswith(".lock")


def parse_inventory(raw: Any) -> tuple[list[Installed], dict[str, int]]:
    """Turn third-party repository metadata into allowlisted scan targets."""
    if not isinstance(raw, list) or len(raw) > MAX_ITEMS:
        raise MarketplaceError("Marketplace inventory was not a bounded list")
    entries: list[Installed] = []
    other: dict[str, int] = {}
    seen: set[str] = set()
    kinds = {"integration": "integration", "plugin": "card"}
    for obj in raw:
        if not isinstance(obj, dict) or obj.get("installed") is not True:
            continue
        category = obj.get("category")
        if category not in kinds:
            key = category if isinstance(category, str) and category.isascii() else "other"
            key = key[:32] or "other"
            other[key] = other.get(key, 0) + 1
            continue
        repo, installed, available = obj.get("full_name"), obj.get("installed_version"), obj.get("available_version")
        if not isinstance(repo, str) or not valid_repo(repo) or not isinstance(installed, str) or not valid_ref(installed):
            other["invalid"] = other.get("invalid", 0) + 1
            continue
        if repo.lower() in seen:
            other["duplicate"] = other.get("duplicate", 0) + 1
            continue
        seen.add(repo.lower())
        entries.append(Installed(
            repo=repo,
            name=str(obj.get("name") or repo)[:100],
            kind=kinds[category],
            installed=installed,
            available=available if isinstance(available, str) and valid_ref(available) else "",
            custom=obj.get("custom") is True,
        ))
    return sorted(entries, key=lambda item: item.repo.lower()), other


class _Socket:
    """RFC6455 uncompressed client, with bounded messages and verified upgrade."""

    def __init__(self, host: str = SUPERVISOR_HOST, port: int = SUPERVISOR_PORT,
                 path: str = WEBSOCKET_PATH, timeout: float = 12):
        self.conn = socket.create_connection((host, port), timeout=timeout)
        self.conn.settimeout(timeout)
        self.buffer = bytearray()
        try:
            nonce = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
            request = (
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {nonce}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            )
            self.conn.sendall(request.encode("ascii"))
            head = self._until(b"\r\n\r\n", MAX_HANDSHAKE)
            lines = head.decode("latin1").split("\r\n")
            if not lines[0].startswith("HTTP/1.1 101 ") and lines[0] != "HTTP/1.1 101":
                raise MarketplaceError("Supervisor rejected the WebSocket upgrade")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, val = line.split(":", 1)
                    headers[name.strip().lower()] = val.strip()
            expected = base64.b64encode(hashlib.sha1((nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            if (headers.get("sec-websocket-accept") != expected or
                headers.get("upgrade", "").lower() != "websocket" or
                "upgrade" not in headers.get("connection", "").lower().replace(" ", "").split(",")):
                raise MarketplaceError("Invalid WebSocket handshake")
        except BaseException:
            self.conn.close()
            raise

    def _fill(self, size: int) -> None:
        while len(self.buffer) < size:
            packet = self.conn.recv(min(65536, size - len(self.buffer)))
            if not packet:
                raise MarketplaceError("Supervisor closed the connection")
            self.buffer.extend(packet)

    def _read(self, n: int) -> bytes:
        self._fill(n)
        result = bytes(self.buffer[:n])
        del self.buffer[:n]
        return result

    def _until(self, separator: bytes, max_bytes: int) -> bytes:
        while separator not in self.buffer:
            if len(self.buffer) >= max_bytes:
                raise MarketplaceError("WebSocket handshake exceeds size limit")
            packet = self.conn.recv(min(1024, max_bytes - len(self.buffer)))
            if not packet:
                raise MarketplaceError("WebSocket handshake closed")
            self.buffer.extend(packet)
        loc = self.buffer.index(separator)
        result = bytes(self.buffer[:loc])
        del self.buffer[:loc + len(separator)]
        return result

    def _send(self, opcode: int, content: bytes) -> None:
        if len(content) > MAX_MESSAGE:
            raise MarketplaceError("Message too large to send")
        mask = secrets.token_bytes(4)
        n = len(content)
        header = (struct.pack("!BB", 0x80 | opcode, 0x80 | n) if n < 126 else
                  struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n) if n < 65536 else
                  struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n))
        self.conn.sendall(header + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(content)))

    def send_json(self, data: dict[str, Any]) -> None:
        self._send(1, json.dumps(data, separators=(",", ":")).encode("utf-8"))

    def recv_json(self) -> Any:
        parts: list[bytes] = []
        total = 0
        opcode_first = None
        while True:
            a, b = self._read(2)
            if a & 0x70 or b & 0x80:  # RSV bits or illegal masked server frame
                raise MarketplaceError("Invalid WebSocket frame")
            opcode, fin, size = a & 0x0F, bool(a & 0x80), b & 0x7F
            if size == 126:
                size = struct.unpack("!H", self._read(2))[0]
            elif size == 127:
                size = struct.unpack("!Q", self._read(8))[0]
            if size > MAX_MESSAGE or total + size > MAX_MESSAGE:
                raise MarketplaceError("WebSocket response exceeds size limit")
            if opcode >= 8 and (not fin or size > 125):
                raise MarketplaceError("Invalid control frame")
            content = self._read(size)
            if opcode == 8:
                raise MarketplaceError("WebSocket closed")
            if opcode == 9:
                self._send(10, content)
                continue
            if opcode == 10:
                continue
            if opcode not in (0, 1) or (opcode == 0 and opcode_first is None) or (opcode == 1 and opcode_first is not None):
                raise MarketplaceError("Unexpected WebSocket opcode")
            if opcode == 1:
                opcode_first = 1
            total += size
            parts.append(content)
            if fin:
                try:
                    return json.loads(b"".join(parts).decode("utf-8"))
                except (UnicodeDecodeError, ValueError) as exc:
                    raise MarketplaceError("Invalid Core WebSocket JSON") from exc

    def close(self) -> None:
        try:
            self._send(8, b"")
        except (OSError, MarketplaceError):
            pass
        self.conn.close()


def get_inventory(token: str | None = None) -> tuple[list[Installed], dict[str, int]]:
    """Fetch inventory with exactly two allowlisted read commands, using Supervisor auth."""
    tok = token if token is not None else os.getenv("SUPERVISOR_TOKEN", "")
    if not tok:
        raise MarketplaceError("Supervisor app token missing; run inside Home Assistant")
    for command in _ALLOWED_COMMANDS:
        ws = None
        try:
            ws = _Socket()
            hello = ws.recv_json()
            if not isinstance(hello, dict) or hello.get("type") != "auth_required":
                raise MarketplaceError("Unexpected Home Assistant authentication greeting")
            ws.send_json({"type": "auth", "access_token": tok})
            auth = ws.recv_json()
            if not isinstance(auth, dict) or auth.get("type") != "auth_ok":
                raise MarketplaceError("Supervisor rejected app authentication")
            ws.send_json({"id": 1, "type": command})
            for _ in range(10):
                msg = ws.recv_json()
                if not isinstance(msg, dict) or msg.get("id") != 1 or msg.get("type") != "result":
                    continue
                if not msg.get("success"):
                    error = msg.get("error") if isinstance(msg.get("error"), dict) else {}
                    code = str(error.get("code", ""))
                    if code == "unknown_command":
                        break
                    raise MarketplaceError("Marketplace inventory request failed: " + code[:40])
                return parse_inventory(msg.get("result"))
            else:
                raise MarketplaceError("No Marketplace result received")
        except (OSError, TimeoutError) as exc:
            raise MarketplaceError("Supervisor WebSocket unavailable") from exc
        finally:
            if ws is not None:
                ws.close()
    raise MarketplaceError("Neither Marketplace nor legacy HACS inventory is available")
