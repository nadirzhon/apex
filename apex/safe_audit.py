"""Authorized, non-destructive production audit runner for APEX.

Only bounded GET requests are emitted. No brute force, form submission, mutation,
credential guessing, payload injection, or cross-origin traversal is implemented.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from .scope import Scope

MAX_BODY_BYTES = 1_000_000
PASSIVE_PATHS = ("/", "/robots.txt", "/.well-known/security.txt")
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


@dataclass(frozen=True)
class ResponseSnapshot:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes = b""
    elapsed_ms: float = 0.0

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


@dataclass(frozen=True)
class AuditFinding:
    key: str
    severity: str
    title: str
    evidence: str
    remediation: str


@dataclass
class AuditReport:
    target: str
    host: str
    started_at: float
    completed_at: float = 0.0
    observations: list[dict] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)
    discovered_same_origin_urls: list[str] = field(default_factory=list)
    external_origins: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "host": self.host,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "observations": self.observations,
            "findings": [asdict(f) for f in self.findings],
            "discovered_same_origin_urls": self.discovered_same_origin_urls,
            "external_origins": self.external_origins,
        }


Transport = Callable[[str, str], ResponseSnapshot]


def _is_authorized_https_url(host: str, url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and (parsed.hostname or "").lower() == host.lower()


class SameHostHttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_host: str) -> None:
        super().__init__()
        self.allowed_host = allowed_host.lower()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_authorized_https_url(self.allowed_host, newurl):
            raise urllib.error.HTTPError(
                newurl, code, "redirect blocked by same-host HTTPS-only policy", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrllibTransport:
    def __init__(self, host: str, timeout: float = 10.0) -> None:
        self.host = host
        self.timeout = timeout
        self.opener = urllib.request.build_opener(SameHostHttpsRedirectHandler(host))

    def __call__(self, method: str, url: str) -> ResponseSnapshot:
        if method not in {"GET", "HEAD"}:
            raise ValueError("safe audit transport permits only GET/HEAD")
        if not _is_authorized_https_url(self.host, url):
            raise PermissionError("transport target violates same-host HTTPS-only policy")
        req = urllib.request.Request(
            url,
            method=method,
            headers={"User-Agent": "APEX-Safe-Audit/1.0 (+authorized security review)"},
        )
        started = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                body = b"" if method == "HEAD" else resp.read(MAX_BODY_BYTES)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status = int(getattr(resp, "status", 200))
                final_url = resp.geturl()
        except urllib.error.HTTPError as exc:
            body = b"" if method == "HEAD" else exc.read(MAX_BODY_BYTES)
            headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            status = int(exc.code)
            final_url = exc.geturl()
        elapsed = (time.perf_counter() - started) * 1000.0
        return ResponseSnapshot(final_url, status, headers, body, elapsed)


def _extract_urls(base_url: str, body: bytes) -> tuple[list[str], list[str]]:
    text = body.decode("utf-8", "replace")
    raw = re.findall(r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''', text, re.I)
    same: set[str] = set()
    external: set[str] = set()
    base_host = (urllib.parse.urlparse(base_url).hostname or "").lower()
    for item in raw:
        if item.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        absolute = urllib.parse.urljoin(base_url, item)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if (parsed.hostname or "").lower() == base_host:
            same.add(absolute.split("#", 1)[0])
        else:
            external.add(f"{parsed.scheme}://{parsed.netloc}")
    return sorted(same), sorted(external)


def _cookie_findings(headers: dict[str, str]) -> list[AuditFinding]:
    raw = headers.get("set-cookie", "")
    if not raw:
        return []
    lower = raw.lower()
    checks = (
        ("secure", "cookie-secure", "medium", "Cookie without Secure attribute",
         "Set Secure on cookies that carry session or sensitive state."),
        ("httponly", "cookie-httponly", "low", "Cookie without HttpOnly attribute",
         "Use HttpOnly for cookies that do not need JavaScript access."),
        ("samesite=", "cookie-samesite", "low", "Cookie without explicit SameSite policy",
         "Set an explicit SameSite policy appropriate for the application flow."),
    )
    return [
        AuditFinding(key, severity, title, f"Set-Cookie lacks {token}.", remediation)
        for token, key, severity, title, remediation in checks if token not in lower
    ]


def _header_findings(snapshot: ResponseSnapshot) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for header in SECURITY_HEADERS:
        if header not in snapshot.headers:
            severity = "medium" if header in {"strict-transport-security", "content-security-policy"} else "low"
            findings.append(AuditFinding(
                f"missing-{header}", severity, f"Missing security header: {header}",
                f"HTTP {snapshot.status} from {snapshot.url} did not include {header}.",
                f"Add and test an appropriate {header} policy.",
            ))
    value = snapshot.headers.get("x-content-type-options", "").lower()
    if value and value != "nosniff":
        findings.append(AuditFinding(
            "bad-x-content-type-options", "low", "Unexpected X-Content-Type-Options value",
            f"Observed value: {value}", "Use X-Content-Type-Options: nosniff.",
        ))
    return findings + _cookie_findings(snapshot.headers)


def audit(scope: Scope, target: str, authorized: bool, *, transport: Transport | None = None) -> AuditReport:
    scope.assert_ready(authorized)
    scope.guard(target)
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme != "https":
        raise ValueError("production-safe audit requires an https:// target")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("target must include a hostname")

    base = f"https://{parsed.netloc}"
    run_transport = transport or UrllibTransport(host)
    report = AuditReport(target=target, host=host, started_at=time.time())
    finding_keys: set[str] = set()

    for path in PASSIVE_PATHS:
        url = urllib.parse.urljoin(base, path)
        scope.guard(url)
        snapshot = run_transport("GET", url)
        if not _is_authorized_https_url(host, snapshot.url):
            raise PermissionError("transport returned a response outside same-host HTTPS policy")
        report.observations.append({
            "method": "GET", "url": snapshot.url, "status": snapshot.status,
            "elapsed_ms": round(snapshot.elapsed_ms, 2), "body_bytes": len(snapshot.body),
            "body_sha256": snapshot.body_sha256, "headers": snapshot.headers,
        })
        if path == "/":
            for finding in _header_findings(snapshot):
                if finding.key not in finding_keys:
                    report.findings.append(finding)
                    finding_keys.add(finding.key)
            report.discovered_same_origin_urls, report.external_origins = _extract_urls(snapshot.url, snapshot.body)
        elif path == "/.well-known/security.txt" and snapshot.status == 404:
            report.findings.append(AuditFinding(
                "security-txt-missing", "info", "No security.txt published",
                "GET /.well-known/security.txt returned 404.",
                "Consider publishing security.txt with a security contact and disclosure policy.",
            ))

    report.completed_at = time.time()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="APEX authorized passive production audit")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", default="apex-safe-audit.json")
    parser.add_argument("--i-am-authorized", action="store_true")
    args = parser.parse_args(argv)
    report = audit(Scope.load(args.scope), args.target, args.i_am_authorized)
    payload = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    Path(args.out).write_text(payload, encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
