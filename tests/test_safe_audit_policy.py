from apex.safe_audit import UrllibTransport, _is_authorized_https_url


def test_authorized_url_policy_requires_https_and_exact_host():
    assert _is_authorized_https_url("autonoma.uk", "https://autonoma.uk/")
    assert not _is_authorized_https_url("autonoma.uk", "http://autonoma.uk/")
    assert not _is_authorized_https_url("autonoma.uk", "https://sub.autonoma.uk/")
    assert not _is_authorized_https_url("autonoma.uk", "https://example.com/")


def test_transport_rejects_non_get_head_before_network():
    transport = UrllibTransport("autonoma.uk")
    try:
        transport("POST", "https://autonoma.uk/")
        assert False, "POST must never be allowed by passive audit transport"
    except ValueError:
        pass


def test_transport_rejects_http_before_network():
    transport = UrllibTransport("autonoma.uk")
    try:
        transport("GET", "http://autonoma.uk/")
        assert False, "HTTP downgrade must be rejected before network"
    except PermissionError:
        pass
