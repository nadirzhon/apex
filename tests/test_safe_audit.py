from apex.safe_audit import ResponseSnapshot, audit
from apex.scope import Scope


def _scope():
    return Scope(program="Autonoma", authorized=True, in_scope=["autonoma.uk"])


def test_audit_is_scope_and_authorization_gated():
    scope = _scope()
    try:
        audit(scope, "https://example.com", True, transport=lambda m, u: None)
        assert False, "out-of-scope target must be rejected"
    except PermissionError:
        pass
    try:
        audit(scope, "https://autonoma.uk", False, transport=lambda m, u: None)
        assert False, "explicit authorization flag is required"
    except PermissionError:
        pass


def test_audit_requires_https():
    try:
        audit(_scope(), "http://autonoma.uk", True, transport=lambda m, u: None)
        assert False, "plain HTTP must be rejected"
    except ValueError:
        pass


def test_audit_only_reads_three_passive_paths_and_reports_missing_headers():
    calls = []

    def transport(method, url):
        calls.append((method, url))
        if url.endswith("/.well-known/security.txt"):
            return ResponseSnapshot(url, 404, {"content-type": "text/plain"}, b"not found", 1.0)
        if url.endswith("/robots.txt"):
            return ResponseSnapshot(url, 200, {"content-type": "text/plain"}, b"User-agent: *", 1.0)
        html = b'<html><a href="/en/">English</a><script src="https://cdn.example.net/a.js"></script></html>'
        return ResponseSnapshot(url, 200, {
            "content-type": "text/html",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
        }, html, 2.0)

    report = audit(_scope(), "https://autonoma.uk", True, transport=transport)
    assert calls == [
        ("GET", "https://autonoma.uk/"),
        ("GET", "https://autonoma.uk/robots.txt"),
        ("GET", "https://autonoma.uk/.well-known/security.txt"),
    ]
    keys = {f.key for f in report.findings}
    assert "missing-strict-transport-security" in keys
    assert "missing-content-security-policy" in keys
    assert "security-txt-missing" in keys
    assert "https://autonoma.uk/en/" in report.discovered_same_origin_urls
    assert "https://cdn.example.net" in report.external_origins


def test_audit_never_follows_cross_host_transport_result():
    def transport(method, url):
        return ResponseSnapshot("https://evil.example/", 200, {}, b"")

    try:
        audit(_scope(), "https://autonoma.uk", True, transport=transport)
        assert False, "cross-host response must be rejected"
    except PermissionError:
        pass


def test_cookie_policy_findings_are_conservative():
    def transport(method, url):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
        }
        if url.endswith("/"):
            headers["set-cookie"] = "session=abc; Path=/"
        return ResponseSnapshot(url, 200, headers, b"ok")

    report = audit(_scope(), "https://autonoma.uk", True, transport=transport)
    keys = {f.key for f in report.findings}
    assert {"cookie-secure", "cookie-httponly", "cookie-samesite"} <= keys
