# Python
"""
Resilience tests for PassiveReconAdapter:
- HTTP 429/5xx retry with backoff/Retry-After
- Per-service rate limiting (requests per minute)
"""

import pytest
from pathlib import Path
import sys
import importlib

# Ensure project root is importable (so 'src' package is found)
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.adapters.passive_recon import PassiveReconAdapter, create_passive_recon_adapter  # noqa: E402
import src.adapters.passive_recon as pr_mod  # noqa: E402


class _FakeHeaders:
    def get_content_charset(self):
        return None


class _FakeResp:
    def __init__(self, body: str):
        self._body = body
        self.headers = _FakeHeaders()

    def read(self):
        return self._body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_retry_on_429_with_retry_after(monkeypatch: pytest.MonkeyPatch):
    """
    Verify that _http_get retries on 429 with Retry-After and eventually succeeds.
    """
    state = {"crt": 0, "wb": 0}

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        if "crt.sh" in url:
            if state["crt"] == 0:
                state["crt"] += 1
                hdrs = {"Retry-After": "0"}  # avoid sleeping long in test
                raise pr_mod.error.HTTPError(url, 429, "Too Many Requests", hdrs, None)
            state["crt"] += 1
            return _FakeResp("[]")
        if "web.archive.org" in url:
            if state["wb"] == 0:
                state["wb"] += 1
                hdrs = {"Retry-After": "0"}  # avoid sleeping long in test
                raise pr_mod.error.HTTPError(url, 429, "Too Many Requests", hdrs, None)
            state["wb"] += 1
            return _FakeResp("[]")
        return _FakeResp("[]")

    # Patch networking and sleep
    monkeypatch.setattr(pr_mod.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(pr_mod.time, "sleep", lambda s: None)

    adapter = create_passive_recon_adapter({
        "retries": 1,
        "respect_retry_after": True
    })

    result = adapter.execute({"domain": "example.com"})
    # Should not raise; both endpoints retried then succeeded with empty lists
    assert result.status.value in ("success", "partial", "failure")
    assert state["crt"] == 2  # one 429 + one success
    assert state["wb"] == 2   # one 429 + one success


def test_rate_limit_enforced_with_sleep(monkeypatch: pytest.MonkeyPatch):
    """
    Verify that per-base-url rate limiting calls time.sleep when last call was recent.
    """
    sleeps = []

    def fake_sleep(s):
        sleeps.append(s)

    def fake_urlopen(req, timeout=None):
        # Always succeed with empty JSON quickly
        return _FakeResp("[]")

    monkeypatch.setattr(pr_mod.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(pr_mod.time, "sleep", fake_sleep)

    # Prepare last-call timestamps to "now" so limiter must sleep
    # Keys must match exactly what adapter uses:
    #  - crt: base_url stripped of trailing slash: "https://crt.sh"
    #  - wayback: base_url as-is: "https://web.archive.org/cdx/search/cdx"
    now_ts = pr_mod.time.time()
    backup = dict(PassiveReconAdapter._last_call_times)
    try:
        PassiveReconAdapter._last_call_times["https://crt.sh"] = now_ts
        PassiveReconAdapter._last_call_times["https://web.archive.org/cdx/search/cdx"] = now_ts

        adapter = create_passive_recon_adapter({
            "crt_sh": {"rate_limit_rpm": 120},       # 0.5s min interval
            "wayback": {"rate_limit_rpm": 120}
        })

        result = adapter.execute({"domain": "example.com"})
        assert result is not None
        # At least one sleep should have been requested (likely two: one per service)
        assert len(sleeps) >= 1
        assert any(s > 0 for s in sleeps)
    finally:
        PassiveReconAdapter._last_call_times = backup
