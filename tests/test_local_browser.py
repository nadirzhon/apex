import pytest

from apex.local_browser import BrowserRequestFact, LocalBrowserInventory, LocalBrowserSnapshot, LocalPlaywrightExplorer


def test_local_browser_refuses_non_loopback():
    with pytest.raises(PermissionError):
        LocalPlaywrightExplorer('https://example.com/')


def test_endpoint_hints_keep_blocked_mutation_metadata():
    inv = LocalBrowserInventory('http://127.0.0.1:9000/')
    inv.snapshots.append(LocalBrowserSnapshot(
        url='http://127.0.0.1:9000/',
        title='T',
        dom_sha256='a' * 64,
        links=(),
        controls=(),
        requests=(
            BrowserRequestFact('GET', 'http://127.0.0.1:9000/api/me', 'fetch', False, 200),
            BrowserRequestFact('POST', 'http://127.0.0.1:9000/api/login', 'fetch', True, 0),
            BrowserRequestFact('GET', 'https://example.org/x', 'script', True, 0),
        ),
    ))
    hints = inv.endpoint_hints()
    assert len(hints) == 2
    assert any(x['url'].endswith('/api/login') and x['blocked_mutation'] for x in hints)
    assert any(x['url'].endswith('/api/me') and not x['blocked_mutation'] for x in hints)


def test_safe_fill_values_are_inert():
    assert LocalPlaywrightExplorer._safe_fill_value('email', 'email').endswith('.invalid')
    assert LocalPlaywrightExplorer._safe_fill_value('password', 'password') == 'APEX_DISCOVERY'
    assert LocalPlaywrightExplorer._safe_fill_value('file', 'upload') == ''
