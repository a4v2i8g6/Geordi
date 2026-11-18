from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

SEVERITIES = {"critical": 36, "high": 19, "medium": 8, "low": 3, "info": 0}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    summary: str
    detail: str
    evidence: str = "heuristic"

    def key(self) -> str:
        # A stable identity useful for version comparisons, with no secret-bearing snippets.
        return sha256(f"{self.rule}\0{self.path}\0{self.summary}".encode()).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["id"] = self.key()
        return result


@dataclass
class Report:
    target: str
    source: str
    commit: str | None = None
    findings: list[Finding] = field(default_factory=list)
    packages: list[dict] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    inventory: dict = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    checks: dict[str, str] = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: int = 1

    def add(self, rule: str, severity: str, path: str, line: int, summary: str, detail: str,
            evidence: str = "heuristic") -> None:
        assert severity in SEVERITIES
        if len(self.findings) >= 2000:
            self.checks["findings"] = "truncated"
            return
        self.findings.append(Finding(rule, severity, path, line, summary, detail, evidence))

    def to_dict(self) -> dict[str, Any]:
        f = sorted(self.findings, key=lambda x: (-SEVERITIES[x.severity], x.path, x.line, x.rule))
        points = sum(SEVERITIES[x.severity] for x in f)
        score = max(0, 100 - points)
        if any(x.severity == "critical" for x in f):
            score = min(score, 39)
        if any(x.severity == "high" for x in f):
            score = min(score, 89)
        incomplete = bool(self.skipped) or any(v != "completed" for v in self.checks.values())
        if incomplete:
            score = min(score, 89)
        verdict = "review required" if incomplete else ("low observed risk" if score >= 90 else
                 "review recommended" if score >= 70 else "high risk" if score >= 40 else "do not install")
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "source": self.source,
            "commit": self.commit,
            "generated_at": self.generated_at,
            "score": score,
            "verdict": verdict,
            "incomplete": incomplete,
            "counts": {s: sum(x.severity == s for x in f) for s in SEVERITIES},
            "findings": [x.to_dict() for x in f],
            "packages": self.packages,
            "endpoints": self.endpoints,
            "inventory": self.inventory,
            "skipped": self.skipped[:100],
            "checks": self.checks,
            "disclaimer": "Static checks do not establish that code is safe. Never execute untrusted code to scan it.",
        }
