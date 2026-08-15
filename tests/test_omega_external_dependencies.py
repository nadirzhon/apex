from apex.js_intel import JavaScriptAnalyzer


def test_cross_origin_request_hint_is_retained_but_not_targetable():
    analyzer = JavaScriptAnalyzer('https://app.test/')
    result = analyzer.analyze(
        'https://app.test/a.js',
        "fetch('https://worker.example.net/api/lead',{method:'POST'}); fetch('/api/me');",
    )
    assert any(x.origin == 'https://worker.example.net' for x in result.external_routes)
    deps = analyzer.external_dependencies([result])
    assert deps[0]['in_scope'] is False
    assert deps[0]['targetable'] is False
    assert deps[0]['mutating'] is True
    records = analyzer.endpoint_records([result])
    assert all('worker.example.net' not in r['url'] for r in records)
    assert any(r['url'] == 'https://app.test/api/me' for r in records)


def test_plain_external_literal_without_endpoint_semantics_is_ignored():
    analyzer = JavaScriptAnalyzer('https://app.test/')
    result = analyzer.analyze('https://app.test/a.js', "const x='https://cdn.test/logo.png';")
    assert result.external_routes == []
