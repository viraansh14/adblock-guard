#!/usr/bin/env python3
"""adblock-guard runner: probe -> persist state -> alert on transition -> log.

Run modes:
  python3 guard_run.py            # one probe cycle (used by the LaunchAgent)
  python3 guard_run.py --status   # print last known state, no probe
  python3 guard_run.py --test-alert  # force an alert to verify the channel
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adblock_guard as ag  # noqa: E402

HOME = Path.home()
BASE = HOME / "adblock-guard"
CFG_PATH = BASE / "config" / "adblock-guard.json"
STATE_PATH = BASE / "config" / "state.json"
HISTORY_PATH = BASE / "config" / "history.jsonl"

DEFAULT_CFG = {
    "ad_domains": ag.DEFAULT_AD_DOMAINS,
    "control_domains": ag.DEFAULT_CONTROL_DOMAINS,
    "resolver": "127.0.0.1",
    "ntfy_topic": "vajra-alerts",
    "ntfy_base": "https://ntfy.sh",
    "use_capos_actuator": True,
}


def load_cfg() -> dict:
    cfg = dict(DEFAULT_CFG)
    if CFG_PATH.exists():
        try:
            cfg.update(json.loads(CFG_PATH.read_text()))
        except Exception:
            pass
    return cfg


def load_prev_state() -> str | None:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text()).get("state")
        except Exception:
            return None
    return None


def save_state(verdict: dict) -> None:
    STATE_PATH.write_text(json.dumps(
        {"state": verdict["state"], "reasons": verdict["reasons"],
         "ts": time.time(), "resolver": verdict.get("probes", {}).get("resolver")},
        indent=2))


def append_history(verdict: dict) -> None:
    row = {"ts": time.time(), "state": verdict["state"]}
    with HISTORY_PATH.open("a") as f:
        f.write(json.dumps(row) + "\n")
    # keep last 5000 rows
    try:
        lines = HISTORY_PATH.read_text().splitlines()
        if len(lines) > 5000:
            HISTORY_PATH.write_text("\n".join(lines[-5000:]) + "\n")
    except Exception:
        pass


EMOJI = {"HEALTHY": "white_check_mark", "BLOCKING_DOWN": "warning",
         "RESOLVER_BYPASS": "satellite", "DNS_DOWN": "rotating_light"}


def notify(cfg: dict, title: str, message: str, tag: str) -> bool:
    """Send an alert. Prefer the proven capos actuator (reaches the phone bus);
    fall back to a raw ntfy POST to the configured topic."""
    body = f"{title} — {message}"
    if cfg.get("use_capos_actuator"):
        try:
            r = subprocess.run(
                ["python3", str(HOME / ".claude/capability-os/capos-actuator.py"),
                 "ntfy", body],
                capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and ('ok' in r.stdout.lower()
                                      or '200' in r.stdout):
                return True
        except Exception:
            pass
    # raw ntfy fallback
    try:
        url = f"{cfg['ntfy_base'].rstrip('/')}/{cfg['ntfy_topic']}"
        r = subprocess.run(["curl", "-s", "-H", f"Title: {title}",
                            "-H", f"Tags: {tag}", "-d", message, url],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


def run_once() -> int:
    cfg = load_cfg()
    prev = load_prev_state()
    verdict = ag.probe(cfg["ad_domains"], cfg["control_domains"], cfg["resolver"])
    new = verdict["state"]

    append_history(verdict)
    save_state(verdict)

    if ag.should_alert(prev, new):
        if new == "HEALTHY":
            notify(cfg, "Ad-block recovered",
                   f"Blocking is back to HEALTHY (was {prev}).",
                   EMOJI["HEALTHY"])
        else:
            reason = "; ".join(verdict["reasons"])
            notify(cfg, f"Ad-block DEGRADED: {new}",
                   f"{reason}\nresolver={verdict['probes'].get('resolver')}",
                   EMOJI.get(new, "warning"))
        print(f"[{time.strftime('%H:%M:%S')}] {prev} -> {new}  (alerted)")
    else:
        print(f"[{time.strftime('%H:%M:%S')}] {new}  (no transition)")
    return 0 if new == "HEALTHY" else 1


def main() -> int:
    if "--status" in sys.argv:
        print(STATE_PATH.read_text() if STATE_PATH.exists() else "no state yet")
        return 0
    if "--test-alert" in sys.argv:
        cfg = load_cfg()
        ok = notify(cfg, "Ad-block guard test",
                    "This is a test alert from adblock-guard. Channel works.",
                    "test_tube")
        print("alert sent" if ok else "alert FAILED")
        return 0 if ok else 1
    return run_once()


if __name__ == "__main__":
    sys.exit(main())
