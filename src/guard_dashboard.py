#!/usr/bin/env python3
"""Render adblock-guard state + history into a self-contained status page.

Reads config/state.json and config/history.jsonl (written by guard_run.py),
runs one fresh probe for the live detail, and writes config/dashboard.html.
No external assets — system font stacks only, so it works under a strict CSP.
"""
from __future__ import annotations

import html
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adblock_guard as ag  # noqa: E402

BASE = Path.home() / "adblock-guard"
STATE_PATH = BASE / "config" / "state.json"
HISTORY_PATH = BASE / "config" / "history.jsonl"
OUT = BASE / "config" / "dashboard.html"

STATE_META = {
    "HEALTHY": ("healthy", "Blocking active", "good"),
    "BLOCKING_DOWN": ("blocking down", "Ads leaking through — filtering stopped", "crit"),
    "RESOLVER_BYPASS": ("resolver bypassed", "Not using the filtering resolver", "warn"),
    "DNS_DOWN": ("dns down", "Resolver not answering at all", "crit"),
}

WATCHED = [
    ("Silent filter fallback", "NextDNS free tier stops filtering past 300k queries/mo with no error — detected when ad domains start resolving to real IPs.", "BLOCKING_DOWN"),
    ("Resolver bypass", "Profile drops to carrier DNS on cellular, or a VPN / DHCP takes over the resolver.", "RESOLVER_BYPASS"),
    ("Total DNS failure", "The local daemon dies and nothing resolves.", "DNS_DOWN"),
]


def load_history() -> list[dict]:
    if not HISTORY_PATH.exists():
        return []
    rows = []
    for ln in HISTORY_PATH.read_text().splitlines():
        try:
            rows.append(json.loads(ln))
        except Exception:
            pass
    return rows


def uptime_pct(rows: list[dict], window_s: float, now: float) -> tuple[float, int]:
    recent = [r for r in rows if now - r["ts"] <= window_s]
    if not recent:
        return (100.0, 0)
    healthy = sum(1 for r in recent if r["state"] == "HEALTHY")
    return (100.0 * healthy / len(recent), len(recent))


def ago(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def strip_cells(rows: list[dict], now: float, buckets: int = 48,
                window_s: float = 86400) -> str:
    """A 24h heat strip: one cell per 30-min bucket, colored by worst state."""
    sev = {"HEALTHY": 0, "RESOLVER_BYPASS": 1, "BLOCKING_DOWN": 2, "DNS_DOWN": 2}
    cls = {0: "good", 1: "warn", 2: "crit", -1: "empty"}
    step = window_s / buckets
    cells = []
    for i in range(buckets):
        start = now - window_s + i * step
        end = start + step
        inb = [r for r in rows if start <= r["ts"] < end]
        worst = max((sev.get(r["state"], 0) for r in inb), default=-1)
        label = time.strftime("%H:%M", time.localtime(start))
        cells.append(f'<span class="cell {cls[worst]}" title="{label}"></span>')
    return "".join(cells)


def render() -> str:
    now = time.time()
    state = "HEALTHY"
    resolver = "127.0.0.1"
    reasons = []
    checked = now
    if STATE_PATH.exists():
        try:
            st = json.loads(STATE_PATH.read_text())
            state = st.get("state", "HEALTHY")
            resolver = st.get("resolver") or "?"
            reasons = st.get("reasons", [])
            checked = st.get("ts", now)
        except Exception:
            pass

    live = ag.probe(ag.DEFAULT_AD_DOMAINS, ag.DEFAULT_CONTROL_DOMAINS)
    rows = load_history()
    up24, n24 = uptime_pct(rows, 86400, now)
    up7, n7 = uptime_pct(rows, 7 * 86400, now)

    key, blurb, sev = STATE_META.get(state, ("unknown", "", "warn"))

    ad_rows = "".join(
        f'<tr><td>{html.escape(d)}</td>'
        f'<td class="mono">{html.escape(", ".join(ips) or "—")}</td>'
        f'<td><span class="tag {"good" if ag.is_blocked(ips) else "crit"}">'
        f'{"blocked" if ag.is_blocked(ips) else "LEAKING"}</span></td></tr>'
        for d, ips in live["probes"]["ads"].items())
    ctrl_rows = "".join(
        f'<tr><td>{html.escape(d)}</td>'
        f'<td class="mono">{html.escape(", ".join(ips) or "—")}</td>'
        f'<td><span class="tag {"good" if not ag.is_blocked(ips) else "crit"}">'
        f'{"resolves" if not ag.is_blocked(ips) else "FAILED"}</span></td></tr>'
        for d, ips in live["probes"]["control"].items())

    watch_cards = "".join(
        f'<div class="watch"><div class="watch-h">{html.escape(name)}'
        f'<span class="tag {"crit" if state==code else "good"}">'
        f'{"TRIGGERED" if state==code else "clear"}</span></div>'
        f'<p>{html.escape(desc)}</p></div>'
        for name, desc, code in WATCHED)

    events = []
    last = None
    for r in rows:
        if r["state"] != last:
            events.append(r)
            last = r["state"]
    events = events[-8:][::-1]
    ev_rows = "".join(
        f'<tr><td class="mono">{time.strftime("%b %d %H:%M", time.localtime(r["ts"]))}</td>'
        f'<td><span class="tag {STATE_META.get(r["state"],("","","warn"))[2]}">'
        f'{STATE_META.get(r["state"],(r["state"],))[0]}</span></td></tr>'
        for r in events) or '<tr><td colspan="2" class="muted">No state changes recorded yet.</td></tr>'

    strip = strip_cells(rows, now)

    return f"""<title>Ad-block Guard</title>
<style>
:root {{
  --bg:#0b0f14; --surface:#141a21; --surface2:#1b232c; --line:#26303b;
  --text:#dce4ec; --muted:#7d8b98; --accent:#39c5cf;
  --good:#3fb950; --warn:#d29922; --crit:#f85149;
}}
:root[data-theme="light"] {{
  --bg:#f4f6f8; --surface:#ffffff; --surface2:#eef2f5; --line:#dbe2e8;
  --text:#1a2027; --muted:#5c6773; --accent:#0f8b93;
  --good:#1a7f37; --warn:#9a6700; --crit:#cf222e;
}}
@media (prefers-color-scheme: light) {{
  :root:not([data-theme="dark"]) {{
    --bg:#f4f6f8; --surface:#ffffff; --surface2:#eef2f5; --line:#dbe2e8;
    --text:#1a2027; --muted:#5c6773; --accent:#0f8b93;
    --good:#1a7f37; --warn:#9a6700; --crit:#cf222e;
  }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  line-height:1.5; -webkit-font-smoothing:antialiased; }}
.mono {{ font-family:ui-monospace,"SF Mono",Menlo,monospace;
  font-variant-numeric:tabular-nums; }}
.wrap {{ max-width:920px; margin:0 auto; padding:32px 24px 64px; }}
header {{ display:flex; align-items:baseline; justify-content:space-between;
  gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
h1 {{ font-size:15px; font-weight:600; letter-spacing:.14em; text-transform:uppercase;
  margin:0; color:var(--muted); }}
h1 b {{ color:var(--text); font-weight:700; }}
.updated {{ font-size:12px; color:var(--muted); }}
.hero {{ background:var(--surface); border:1px solid var(--line); border-radius:14px;
  padding:24px; display:flex; align-items:center; gap:20px; margin-bottom:20px;
  position:relative; overflow:hidden; }}
.hero::before {{ content:""; position:absolute; left:0; top:0; bottom:0; width:4px;
  background:var(--st); }}
.dot {{ width:52px; height:52px; border-radius:50%; background:var(--st);
  box-shadow:0 0 0 6px color-mix(in srgb,var(--st) 18%,transparent); flex:none; }}
.hero-main {{ flex:1; }}
.state-name {{ font-size:26px; font-weight:700; text-transform:capitalize;
  letter-spacing:-.01em; }}
.state-blurb {{ color:var(--muted); font-size:14px; margin-top:2px; }}
.resolver {{ text-align:right; font-size:13px; color:var(--muted); }}
.resolver b {{ display:block; color:var(--text); font-size:16px; margin-top:2px; }}
.grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:20px; }}
.tile {{ background:var(--surface); border:1px solid var(--line); border-radius:12px;
  padding:16px; }}
.tile .k {{ font-size:11px; letter-spacing:.1em; text-transform:uppercase;
  color:var(--muted); }}
.tile .v {{ font-size:24px; font-weight:700; margin-top:6px; }}
.tile .v small {{ font-size:13px; font-weight:500; color:var(--muted); }}
.panel {{ background:var(--surface); border:1px solid var(--line); border-radius:12px;
  padding:20px; margin-bottom:20px; }}
.panel h2 {{ font-size:12px; letter-spacing:.1em; text-transform:uppercase;
  color:var(--muted); margin:0 0 14px; font-weight:600; }}
.strip {{ display:flex; gap:2px; }}
.cell {{ flex:1; height:34px; border-radius:2px; background:var(--surface2); }}
.cell.good {{ background:var(--good); }}
.cell.warn {{ background:var(--warn); }}
.cell.crit {{ background:var(--crit); }}
.cell.empty {{ background:var(--surface2); }}
.strip-legend {{ display:flex; justify-content:space-between; font-size:11px;
  color:var(--muted); margin-top:8px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
td {{ padding:8px 6px; border-top:1px solid var(--line); }}
tr:first-child td {{ border-top:none; }}
.tag {{ font-size:11px; font-weight:700; padding:2px 8px; border-radius:20px;
  text-transform:uppercase; letter-spacing:.04em; }}
.tag.good {{ background:color-mix(in srgb,var(--good) 18%,transparent); color:var(--good); }}
.tag.warn {{ background:color-mix(in srgb,var(--warn) 20%,transparent); color:var(--warn); }}
.tag.crit {{ background:color-mix(in srgb,var(--crit) 20%,transparent); color:var(--crit); }}
.cols {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
.watch {{ padding:14px 0; border-top:1px solid var(--line); }}
.watch:first-child {{ border-top:none; padding-top:0; }}
.watch-h {{ display:flex; justify-content:space-between; align-items:center;
  font-weight:600; font-size:14px; gap:12px; }}
.watch p {{ margin:6px 0 0; color:var(--muted); font-size:13px; }}
.muted {{ color:var(--muted); }}
footer {{ font-size:12px; color:var(--muted); margin-top:28px; text-align:center; }}
@media (max-width:680px) {{
  .grid {{ grid-template-columns:repeat(2,1fr); }}
  .cols {{ grid-template-columns:1fr; }}
  .hero {{ flex-wrap:wrap; }} .resolver {{ text-align:left; }}
}}
</style>
<div class="wrap" style="--st:var(--{sev})">
  <header>
    <h1><b>Ad-block</b> Guard</h1>
    <span class="updated">Checked {ago(now - checked)} · live probe {time.strftime("%H:%M:%S")}</span>
  </header>

  <div class="hero">
    <div class="dot"></div>
    <div class="hero-main">
      <div class="state-name">{key}</div>
      <div class="state-blurb">{html.escape(blurb)}</div>
    </div>
    <div class="resolver">system resolver<b class="mono">{html.escape(resolver)}</b></div>
  </div>

  <div class="grid">
    <div class="tile"><div class="k">Uptime 24h</div><div class="v">{up24:.1f}<small>%</small></div></div>
    <div class="tile"><div class="k">Uptime 7d</div><div class="v">{up7:.1f}<small>%</small></div></div>
    <div class="tile"><div class="k">Checks logged</div><div class="v">{len(rows)}</div></div>
    <div class="tile"><div class="k">Interval</div><div class="v">15<small>min</small></div></div>
  </div>

  <div class="panel">
    <h2>Last 24 hours</h2>
    <div class="strip">{strip}</div>
    <div class="strip-legend"><span>24h ago</span><span>now</span></div>
  </div>

  <div class="cols">
    <div class="panel">
      <h2>Ad domains — must be blocked</h2>
      <table>{ad_rows}</table>
    </div>
    <div class="panel">
      <h2>Control domains — must resolve</h2>
      <table>{ctrl_rows}</table>
    </div>
  </div>

  <div class="panel">
    <h2>Failure modes watched</h2>
    {watch_cards}
  </div>

  <div class="panel">
    <h2>Recent state changes</h2>
    <table>{ev_rows}</table>
  </div>

  <footer>adblock-guard · runs locally via launchd · alerts to your ntfy bridge on any state change</footer>
</div>
"""


if __name__ == "__main__":
    OUT.write_text(render())
    print(f"wrote {OUT}")
