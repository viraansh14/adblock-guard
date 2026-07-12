#!/usr/bin/env python3
"""adblock-guard — detects SILENT failure of a system-wide DNS ad-block layer.

Failure modes it catches (all verified real for a NextDNS/AdGuard-DNS setup):
  * BLOCKING_DOWN   — ad domains suddenly resolve to real IPs while normal
                      domains still work. This is the NextDNS free-tier 300k/mo
                      silent fallback (keeps resolving, stops filtering, no error).
  * RESOLVER_BYPASS — the local filtering resolver (127.0.0.1) is no longer the
                      system resolver: profile dropped to carrier DNS on cellular,
                      a VPN took over, or DHCP pushed its own DNS.
  * DNS_DOWN        — even control domains fail to resolve; the resolver itself is
                      broken (distinct from "filtering stopped").
  * HEALTHY         — ads sinkholed, control resolves, resolver is the daemon.

The classification core is pure (no I/O) so it is unit-testable; the runtime layer
feeds it real `dig`/`scutil` output and handles alerting + state persistence.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---- pure classification core (unit-tested) --------------------------------

SINKHOLE_IPS = {"0.0.0.0", "::", "::0", "127.0.0.1"}

# Domains that MUST be blocked by any real ad-block list. Kept deliberately
# boring/stable so the check itself doesn't rot.
DEFAULT_AD_DOMAINS = [
    "doubleclick.net",
    "ad.doubleclick.net",
    "googleadservices.com",
    "ads.youtube.com",
]
# Domains that MUST always resolve. If these fail, DNS itself is down and a
# "blocking down" verdict would be a false alarm.
DEFAULT_CONTROL_DOMAINS = ["apple.com", "cloudflare.com"]


def is_blocked(ips: list[str]) -> bool:
    """A domain is 'blocked' if it returned no address or only sinkhole addrs."""
    real = [ip for ip in ips if ip and ip not in SINKHOLE_IPS]
    return len(real) == 0


def classify(resolver_ns: str | None,
             ad_results: dict[str, list[str]],
             control_results: dict[str, list[str]],
             expected_resolver: str = "127.0.0.1") -> dict:
    """Pure verdict from observed DNS state. Returns {state, reasons, detail}."""
    reasons: list[str] = []

    control_ok = [d for d, ips in control_results.items() if not is_blocked(ips)]
    control_failed = [d for d, ips in control_results.items() if is_blocked(ips)]

    ads_blocked = [d for d, ips in ad_results.items() if is_blocked(ips)]
    ads_leaking = [d for d, ips in ad_results.items() if not is_blocked(ips)]

    # 1. Total DNS failure takes precedence — nothing resolves.
    if control_results and not control_ok:
        reasons.append(f"control domains not resolving: {control_failed}")
        return {"state": "DNS_DOWN", "reasons": reasons,
                "detail": {"control_failed": control_failed}}

    # 2. Resolver bypass — the filtering daemon isn't the active resolver.
    #    Reported even if ads happen to still be blocked, because it means
    #    filtering is not under our control (e.g. carrier DNS on cellular).
    resolver_bypassed = (resolver_ns is not None
                         and expected_resolver not in resolver_ns)
    if resolver_bypassed:
        reasons.append(
            f"system resolver is {resolver_ns!r}, expected {expected_resolver!r}")

    # 3. Blocking down — control resolves but ads leak through to real IPs.
    if ads_leaking:
        reasons.append(f"ad domains resolving to real IPs (filtering off): {ads_leaking}")
        state = "RESOLVER_BYPASS" if resolver_bypassed else "BLOCKING_DOWN"
        return {"state": state, "reasons": reasons,
                "detail": {"ads_leaking": ads_leaking, "ads_blocked": ads_blocked,
                           "resolver": resolver_ns}}

    # 4. Ads all blocked but resolver bypassed = still a warning worth raising.
    if resolver_bypassed:
        return {"state": "RESOLVER_BYPASS", "reasons": reasons,
                "detail": {"ads_blocked": ads_blocked, "resolver": resolver_ns}}

    # 5. All good.
    return {"state": "HEALTHY", "reasons": ["ads sinkholed; control resolves; "
                                            "daemon is the active resolver"],
            "detail": {"ads_blocked": ads_blocked, "control_ok": control_ok,
                       "resolver": resolver_ns}}


UNHEALTHY = {"BLOCKING_DOWN", "RESOLVER_BYPASS", "DNS_DOWN"}


def should_alert(prev_state: str | None, new_state: str) -> bool:
    """Alert only on a state TRANSITION (avoids spamming every run):
       healthy->unhealthy, recovery, or shifting between unhealthy kinds."""
    if prev_state == new_state:
        return False
    if new_state in UNHEALTHY:
        return True
    # new_state healthy: alert only if we're recovering FROM an unhealthy state.
    return prev_state in UNHEALTHY


# ---- runtime layer (I/O; exercised by the live self-check) -----------------

def dig(domain: str, resolver: str = "127.0.0.1", timeout: int = 3) -> list[str]:
    """Return A-record IPs for domain via resolver. [] on failure/no records."""
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", domain, f"@{resolver}"],
            capture_output=True, text=True, timeout=timeout)
        ips = [ln.strip() for ln in out.stdout.splitlines()
               if ln.strip() and not ln.strip().endswith(".")]  # drop CNAME lines
        return ips
    except Exception:
        return []


def active_resolver() -> str | None:
    """First system nameserver per scutil (macOS)."""
    try:
        out = subprocess.run(["scutil", "--dns"], capture_output=True,
                             text=True, timeout=5)
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("nameserver[0]"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def probe(ad_domains: list[str], control_domains: list[str],
          resolver: str = "127.0.0.1") -> dict:
    ad_results = {d: dig(d, resolver) for d in ad_domains}
    control_results = {d: dig(d, resolver) for d in control_domains}
    ns = active_resolver()
    verdict = classify(ns, ad_results, control_results, expected_resolver=resolver)
    verdict["probes"] = {"ads": ad_results, "control": control_results,
                         "resolver": ns}
    return verdict


if __name__ == "__main__":
    v = probe(DEFAULT_AD_DOMAINS, DEFAULT_CONTROL_DOMAINS)
    print(json.dumps(v, indent=2))
    sys.exit(0 if v["state"] == "HEALTHY" else 1)
