from concurrent.futures import ThreadPoolExecutor


def test_yandex_request_starts_are_spaced_across_threads(monkeypatch, no_rate_wait_in_mocked_search_tests):
    from osint_mcp.tools import web_search_source as search

    limiter = no_rate_wait_in_mocked_search_tests
    clock = [0.0]
    starts = []
    monkeypatch.setattr(search, "_YANDEX_NEXT_REQUEST", 0.0)
    monkeypatch.setattr(search.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(search.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(search, "reserve_yandex_attempt", lambda: starts.append(clock[0]))
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: limiter(), range(8)))
    assert len(starts) == 8
    assert all(b - a >= 1.049 for a, b in zip(starts, starts[1:]))
