from apex.local_html_intel import extract_same_origin_hints


def test_extracts_dynamic_fetch_route_with_observed_id():
    body = """
    <script>
      function viewOrder(orderId) { return fetch('/orders/details/' + orderId); }
    </script>
    <button onclick="viewOrder(300123)">View</button>
    """
    hints = extract_same_origin_hints(
        'http://127.0.0.1:8000/',
        'http://127.0.0.1:8000/orders',
        body,
        numeric_ids=('300123',),
    )
    assert 'http://127.0.0.1:8000/orders/details/300123' in hints


def test_keeps_same_origin_and_drops_external():
    body = """
    <a data-endpoint='/api/orders/10'>ok</a>
    <a data-endpoint='https://evil.example/api/orders/10'>external</a>
    """
    hints = extract_same_origin_hints(
        'http://localhost:9000/',
        'http://localhost:9000/orders',
        body,
    )
    assert hints == ('http://localhost:9000/api/orders/10',)
