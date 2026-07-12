"""Unit tests for the pure classification core of adblock-guard.

These test the failure-mode detection logic without any network I/O, by feeding
classify() the exact shapes `dig` would produce in each real-world scenario.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from adblock_guard import (  # noqa: E402
    classify, is_blocked, should_alert, UNHEALTHY,
)

REAL = ["17.253.144.10"]        # a real, resolving A record
SINK = ["0.0.0.0"]              # NextDNS/AdGuard sinkhole
NONE: list[str] = []           # NXDOMAIN / no records


# ---- is_blocked -------------------------------------------------------------

def test_is_blocked_sinkhole():
    assert is_blocked(["0.0.0.0"]) is True
    assert is_blocked(["::"]) is True
    assert is_blocked([]) is True          # NXDOMAIN counts as blocked

def test_is_blocked_real_ip():
    assert is_blocked(["17.253.144.10"]) is False

def test_is_blocked_mixed_counts_as_leaking():
    # if ANY real IP comes back, the ad is reachable => not blocked
    assert is_blocked(["0.0.0.0", "17.253.144.10"]) is False


# ---- classify: the four states ---------------------------------------------

def test_healthy():
    v = classify("127.0.0.1",
                 {"doubleclick.net": SINK, "ads.youtube.com": NONE},
                 {"apple.com": REAL})
    assert v["state"] == "HEALTHY"

def test_blocking_down_is_the_silent_freetier_failure():
    # ads suddenly resolve to real IPs, control still works, resolver still ours.
    # This is exactly the NextDNS 300k-cap silent fallback.
    v = classify("127.0.0.1",
                 {"doubleclick.net": REAL, "ads.youtube.com": REAL},
                 {"apple.com": REAL})
    assert v["state"] == "BLOCKING_DOWN"
    assert "filtering off" in " ".join(v["reasons"])

def test_resolver_bypass_on_cellular_carrier_dns():
    # profile dropped: system resolver is now a carrier IP, ads leak.
    v = classify("192.168.1.1",
                 {"doubleclick.net": REAL},
                 {"apple.com": REAL})
    assert v["state"] == "RESOLVER_BYPASS"

def test_resolver_bypass_even_when_ads_happen_to_be_blocked():
    # resolver isn't ours, but the upstream happens to block ads too.
    # Still a warning: filtering is no longer under our control.
    v = classify("8.8.8.8",
                 {"doubleclick.net": SINK},
                 {"apple.com": REAL})
    assert v["state"] == "RESOLVER_BYPASS"

def test_dns_down_takes_precedence():
    # nothing resolves — must NOT be misreported as BLOCKING_DOWN.
    v = classify("127.0.0.1",
                 {"doubleclick.net": NONE},
                 {"apple.com": NONE, "cloudflare.com": NONE})
    assert v["state"] == "DNS_DOWN"

def test_no_resolver_info_still_classifies_blocking():
    # scutil failed (resolver None) but we can still judge filtering.
    v = classify(None,
                 {"doubleclick.net": REAL},
                 {"apple.com": REAL})
    assert v["state"] == "BLOCKING_DOWN"


# ---- should_alert: transition-only alerting ---------------------------------

def test_no_alert_when_state_unchanged_healthy():
    assert should_alert("HEALTHY", "HEALTHY") is False

def test_no_alert_when_still_broken_same_way():
    assert should_alert("BLOCKING_DOWN", "BLOCKING_DOWN") is False

def test_alert_on_going_unhealthy():
    assert should_alert("HEALTHY", "BLOCKING_DOWN") is True

def test_alert_on_recovery():
    assert should_alert("BLOCKING_DOWN", "HEALTHY") is True

def test_alert_on_shift_between_unhealthy_kinds():
    assert should_alert("BLOCKING_DOWN", "RESOLVER_BYPASS") is True

def test_first_run_healthy_does_not_alert():
    assert should_alert(None, "HEALTHY") is False

def test_first_run_unhealthy_alerts():
    assert should_alert(None, "DNS_DOWN") is True
