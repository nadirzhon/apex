import pytest

from apex.ascend.pipeline import AscendPipeline
from apex.js_intel import JavaScriptAnalyzer
from apex.scope import Scope
from apex.store import Store


SOURCE = r'''
fetch('/api/profile');
fetch('/api/lead', {method: 'POST', body: data});
axios.get('/api/orders?id=7');
axios.post('/api/contact', payload);
const endpoint = '/graphql';
const ignored = 'https://evil.test/api/x';
const secret = 'api_key: ABCDEFGHIJKLMNOPQRST';
'''


def test_extracts_methods_and_routes_without_execution():
    analyzer = JavaScriptAnalyzer('https://app.test/')
    result = analyzer.analyze('https://app.test/assets/app.js', SOURCE)
    pairs = {(r.method, r.url) for r in result.routes}
    assert ('POST', 'https://app.test/api/lead') in pairs
    assert ('GET', 'https://app.test/api/orders?id=7') in pairs
    assert ('POST', 'https://app.test/api/contact') in pairs
    assert any(r.url == 'https://app.test/api/profile' for r in result.routes)
    assert not any('evil.test' in r.url for r in result.routes)


def test_unknown_method_is_not_silently_promoted_to_get():
    analyzer = JavaScriptAnalyzer('https://app.test/')
    result = analyzer.analyze('https://app.test/a.js', "const endpoint='/api/mystery';")
    row = analyzer.endpoint_records([result])[0]
    assert row['method'] == 'UNKNOWN'
    assert row['attrs']['method_confirmed'] is False


def test_secret_like_literals_are_redacted():
    analyzer = JavaScriptAnalyzer('https://app.test/')
    result = analyzer.analyze('https://app.test/a.js', SOURCE)
    assert result.secret_hints
    hint = result.secret_hints[0]
    assert hint.length > 10
    assert 'ABCDEFGHIJKLMNOP' not in hint.fingerprint
    assert len(hint.fingerprint) == 16


def test_cross_host_script_is_rejected():
    analyzer = JavaScriptAnalyzer('https://app.test/')
    with pytest.raises(PermissionError):
        analyzer.analyze('https://cdn.test/a.js', SOURCE)


def test_pipeline_ingests_js_route_hints_with_scope_gate(tmp_path):
    analyzer = JavaScriptAnalyzer('https://app.test/')
    result = analyzer.analyze('https://app.test/a.js', SOURCE)
    pl = AscendPipeline(
        Scope(program='owned', authorized=True, in_scope=['app.test']),
        Store(tmp_path / 'state.json'), authorized=True,
    )
    pl.ingest_js_analyses(analyzer, [result])
    assert 'POST /api/lead' in pl.awm.nodes
    assert pl.twin.endpoints['POST /api/lead'].mutates_state is True
    assert 'UNKNOWN /graphql' in pl.awm.nodes
