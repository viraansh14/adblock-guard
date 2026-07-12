"""Integration tests for the runtime wiring (probe) with dig/scutil mocked.

Proves classify() is fed correctly by probe() and the end-to-end verdict is
right for each scenario — without touching the network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import adblock_guard as ag  # noqa: E402


def make_dig(mapping):
    """Return a fake dig() that looks up domain -> ips in `mapping`."""
    def _dig(domain, resolver="127.0.0.1", timeout=3):
        return mapping.get(domain, [])
    return _dig


def test_probe_reports_healthy(monkeypatch):
    monkeypatch.setattr(ag, "dig", make_dig({
        "doubleclick.net": ["0.0.0.0"], "ad.doubleclick.net": ["0.0.0.0"],
        "googleadservices.com": ["0.0.0.0"], "ads.youtube.com": [],
        "apple.com": ["17.253.144.10"], "cloudflare.com": ["104.16.132.229"],
    }))
    monkeypatch.setattr(ag, "active_resolver", lambda: "127.0.0.1")
    v = ag.probe(ag.DEFAULT_AD_DOMAINS, ag.DEFAULT_CONTROL_DOMAINS)
    assert v["state"] == "HEALTHY"
    assert v["probes"]["resolver"] == "127.0.0.1"


def test_probe_detects_silent_leak(monkeypatch):
    # every ad domain suddenly resolves to a real IP (free-tier fallback)
    monkeypatch.setattr(ag, "dig", make_dig({
        "doubleclick.net": ["142.250.1.1"], "ad.doubleclick.net": ["142.250.1.2"],
        "googleadservices.com": ["142.250.1.3"], "ads.youtube.com": ["142.250.1.4"],
        "apple.com": ["17.253.144.10"], "cloudflare.com": ["104.16.132.229"],
    }))
    monkeypatch.setattr(ag, "active_resolver", lambda: "127.0.0.1")
    v = ag.probe(ag.DEFAULT_AD_DOMAINS, ag.DEFAULT_CONTROL_DOMAINS)
    assert v["state"] == "BLOCKING_DOWN"


def test_probe_detects_cellular_bypass(monkeypatch):
    monkeypatch.setattr(ag, "dig", make_dig({
        "doubleclick.net": ["142.250.1.1"],
        "apple.com": ["17.253.144.10"], "cloudflare.com": ["104.16.132.229"],
    }))
    monkeypatch.setattr(ag, "active_resolver", lambda: "10.0.0.1")  # carrier DNS
    v = ag.probe(["doubleclick.net"], ag.DEFAULT_CONTROL_DOMAINS)
    assert v["state"] == "RESOLVER_BYPASS"
