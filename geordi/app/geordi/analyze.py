"""Conservative rule engine. Suspicious patterns are leads, not malware verdicts."""
from __future__ import annotations

import ast
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from .model import Report
from .safeio import inventory

CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yaml", ".yml"}
URL_RE = re.compile(r"https?://[^\s\"'`<>)}\\]+", re.I)
ENDPOINT_LINE_LIMIT = 250
SENSITIVE_RE = re.compile(
    r"(?:\.storage/(?:auth|core\.config_entries)|secrets\.yaml|hass\.auth|auth\.data|refresh_token|access_token|"
    r"(?:os\.environ(?:\.get)?|getenv)\s*\(|(?:localStorage|sessionStorage)\.|"
    r"(?:process\.env|config_entries\.async_entries))", re.I)
TRANSMIT_RE = re.compile(r"\b(?:requests\.(?:post|put|patch)|httpx\.(?:post|put|patch)|"
                         r"(?:session|client)\.(?:post|put|patch)|fetch\s*\(|XMLHttpRequest|"
                         r"sendBeacon\s*\(|websocket|aiohttp)\b", re.I)
RISK_PATTERNS = [
    ("runtime-execution", "high", re.compile(r"\b(?:eval|exec)\s*\(|\bnew\s+Function\s*\(", re.I),
     "Runtime evaluation or execution", "Review why source text is evaluated as code"),
    ("shell-invocation", "high", re.compile(r"\b(?:os\.system\s*\(|subprocess\.(?:Popen|run|call)\s*\(|child_process\.)"),
     "Shell or process execution", "Inspect arguments, input sources, and whether shell=True is used"),
    ("dynamic-loader", "medium", re.compile(r"\b(?:importlib\.import_module\s*\(|__import__\s*\(|marshal\.loads\s*\()"),
     "Dynamic loading", "Determine whether dynamic imports or payload decoding are required"),
    ("auth-internals", "high", re.compile(r"(?:hass\.auth|\.storage/auth|refresh_token)"),
     "Authentication data access", "Check whether the integration legitimately needs authentication internals"),
    ("js-evasion", "medium", re.compile(r"<!--|-->"),
     "Legacy HTML-comment token in JavaScript", "Check whether this token can alter parsing by security tools"),
    ("external-code", "high", re.compile(r"(?:curl|wget)\s+[^\n]{0,130}(?:\||&&).*?(?:sh|bash|python)|"
                                               r"(?:https?:)?//[^\s\"']+\.(?:py|sh)\b", re.I),
     "Possible code retrieval/execution", "Inspect remote code retrieval and execution sequence"),
]


def _parse_json(data: bytes, label: str, report: Report) -> dict:
    try:
        obj = json.loads(data)
        if not isinstance(obj, dict):
            raise ValueError("top-level JSON must be an object")
        return obj
    except (ValueError, UnicodeError) as e:
        report.add("invalid-json", "low", label, 1, "Invalid metadata JSON", str(e))
        return {}


def _classify_host(host: str) -> str:
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "local IP"
        return "public IP"
    except ValueError:
        pass
    if host.endswith((".local", ".internal", ".home.arpa", ".lan")) or host in {"localhost"}:
        return "local host"
    if host.endswith((".github.com", ".githubusercontent.com")) or host in {"github.com", "pypi.org"}:
        return "infrastructure"
    return "external host"


def _is_url_risky(url: str) -> bool:
    # Match known destination *classes*, not full URLs that might contain credentials.
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    suspicious = ("webhook.site", "requestbin.com", "pastebin.com", "ngrok.io", "ngrok-free.app")
    return any(host == domain or host.endswith("." + domain) for domain in suspicious)


def _safe_host(url: str) -> tuple[str, str, bool]:
    try:
        u = urlsplit(url.rstrip(".,;"))
        host = (u.hostname or "").lower()
        if not host or len(host) > 253:
            return "", "", False
        # Never retain credentials, URL paths, query strings, or fragments.
        return host, _classify_host(host), bool(u.username or u.password)
    except ValueError:
        return "", "", False


def _requirements(data: dict, report: Report, path: str) -> None:
    requirements = data.get("requirements", [])
    if not isinstance(requirements, list):
        report.add("invalid-requirements", "high", path, 1, "Invalid manifest requirements", "Expected a list")
        return
    for item in requirements[:500]:
        if not isinstance(item, str):
            report.add("invalid-requirement", "medium", path, 1, "Non-string dependency", "Review manifest requirements")
            continue
        if len(item) > 250 or item.startswith("-") or any(x in item for x in ("\n", "\r", ";--")):
            report.add("installer-argument", "high", path, 1, "Unsafe dependency declaration", "A dependency must not inject installer flags")
            continue
        # This first version parses exact pins only. Inexact versions are explicitly flagged incomplete.
        m = re.fullmatch(r"([a-zA-Z0-9_.-]+)==([a-zA-Z0-9_.+!-]+)", item)
        if m:
            name, version = m.groups()
            report.packages.append({"ecosystem": "PyPI", "name": name, "version": version, "scope": "runtime"})
        elif re.match(r"^\s*(?:git\+|https?://|file:|\.\.?/)", item, re.I):
            report.add("external-dependency", "high", path, 1, "Non-index dependency", "Review dependency URL/VCS pin and publisher")
        else:
            report.add("unpinned-dependency", "low", path, 1, "Dependency not resolved by baseline scanner", "Supply-chain review requires constraint resolution")
            report.checks["dependency_resolution"] = "not implemented"


def _npm_lock(raw: bytes, report: Report, path: str) -> None:
    data = _parse_json(raw, path, report)
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        report.checks["npm_lock"] = "invalid"
        return
    count = 0
    for key, obj in packages.items():
        if not key or not isinstance(obj, dict):
            continue
        if count >= 4000:
            report.checks["npm_lock"] = "truncated"
            break
        ver = obj.get("version")
        name = key.split("node_modules/")[-1]
        if not isinstance(ver, str) or not isinstance(name, str):
            continue
        count += 1
        report.packages.append({"ecosystem": "npm", "name": name, "version": ver, "scope": "dev" if obj.get("dev") else "runtime"})
        resolved = obj.get("resolved", "")
        if isinstance(resolved, str) and resolved and not resolved.startswith("https://registry.npmjs.org/"):
            report.add("nonregistry-npm", "medium", path, 1, "Dependency downloaded outside npm registry", "Verify package source integrity")


def _python_ast(text: str, path: str, report: Report) -> None:
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError) as e:
        report.add("unparsable-code", "medium", path, getattr(e, "lineno", 1) or 1,
                   "Python source could not be parsed", "Additional review needed for unsupported syntax")
        report.checks["syntax"] = "partial"
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.Call, ast.Attribute)):
            continue
        # AST currently used as a syntax gate; expanded dataflow support is scheduled.


def scan_directory(root: Path, target: str | None = None, source: str = "local", commit: str | None = None) -> Report:
    report = Report(target=target or str(root), source=source, commit=commit)
    report.checks.update({"static_rules": "completed", "syntax": "completed", "archive_safety": "completed",
                          "dependency_resolution": "not implemented", "advisories": "not requested",
                          "publisher_history": "not implemented", "semgrep_dataflow": "not implemented"})
    seen = 0
    read_bytes = 0
    sensitive = []
    sends = []
    endpoint_seen = set()
    for path, data, issue in inventory(root):
        if issue:
            report.skipped.append(f"{path}: {issue}")
            report.add("uninspected-file", "medium", path, 1, "File could not be inspected", issue)
            continue
        assert data is not None
        if read_bytes + len(data) > 128 * 1024 * 1024:
            report.checks["file_budget"] = "truncated"
            report.skipped.append("total scanned-byte limit exceeded")
            break
        seen += 1
        read_bytes += len(data)
        ext = Path(path).suffix.lower()
        lowpath = path.lower()
        if ext in (".pyc", ".pyo", ".so", ".pyd", ".dll"):
            report.add("binary-extension", "high", path, 1, "Executable or compiled module present",
                       "Review binary provenance; static source scan cannot inspect it")
        if Path(path).name == "manifest.json":
            meta = _parse_json(data, path, report)
            _requirements(meta, report, path)
            domain = meta.get("domain")
            if isinstance(domain, str):
                report.inventory.setdefault("domains", []).append(domain[:100])
            if meta.get("iot_class"):
                report.inventory.setdefault("iot_classes", []).append(str(meta["iot_class"])[:100])
        if Path(path).name in ("package-lock.json", "npm-shrinkwrap.json"):
            _npm_lock(data, report, path)
        if ext not in CODE_EXT:
            continue
        if b"\x00" in data:
            report.skipped.append(path + ": binary/null bytes")
            report.add("opaque-source", "medium", path, 1, "Uninspectable source text", "Embedded null bytes")
            continue
        text = data.decode("utf-8", "replace")
        if "\ufffd" in text:
            report.add("encoding-error", "low", path, 1, "Non-UTF8 source", "Some bytes could not be decoded")
            report.checks["syntax"] = "partial"
        if ext == ".py":
            _python_ast(text, path, report)
        # Keep stored results free of matching text: scanned code may include credentials.
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 20000:
                report.add("minified-line", "low", path, lineno, "Very long source line", "Review obfuscated or minified code")
                continue
            if SENSITIVE_RE.search(line):
                if len(sensitive) < 250:
                    sensitive.append((path, lineno))
            if TRANSMIT_RE.search(line):
                if len(sends) < 250:
                    sends.append((path, lineno))
            if ext in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
                for rule, sev, rx, summary, detail in RISK_PATTERNS:
                    if rule == "js-evasion" and ext == ".py":
                        continue
                    if rx.search(line):
                        report.add(rule, sev, path, lineno, summary, detail)
            for match in list(URL_RE.finditer(line))[:5]:
                url = match.group()
                host, group, creds = _safe_host(url)
                if not host:
                    continue
                if host not in endpoint_seen and len(endpoint_seen) < ENDPOINT_LINE_LIMIT:
                    endpoint_seen.add(host)
                    report.endpoints.append({"host": host, "classification": group, "evidence": path})
                if creds or _is_url_risky(url):
                    report.add("suspicious-endpoint", "high", path, lineno,
                               "Potential credential-bearing or collection endpoint", "Inspect full URL privately; URL is not stored in report")
                elif group == "public IP":
                    report.add("hardcoded-public-ip", "low", path, lineno, "Hardcoded public IP", "Check whether the IP is expected")
    if sensitive and sends:
        same_file = any(a[0] == b[0] for a in sensitive for b in sends)
        report.add("sensitive-source-and-network", "high" if same_file else "medium",
                   sensitive[0][0], sensitive[0][1], "Sensitive data access coexists with network transmission",
                   "Heuristic only; no proven dataflow. Review both read and network destinations.")
    report.inventory.update({"files_inspected": seen, "bytes_inspected": read_bytes,
                             "sensitive_read_locations": len(sensitive), "network_call_locations": len(sends),
                             "supply_chain_scope": "runtime exact pins and npm lockfiles, no transitive Python resolution"})
    report.checks["static_rules"] = "completed"
    return report
