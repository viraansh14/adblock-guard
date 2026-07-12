# adblock-guard

Watches your system-wide DNS ad-block layer (NextDNS config `288e6b` on this Mac)
and alerts your phone the moment blocking *silently* stops — the failure modes a
DNS ad-blocker never tells you about.

## Why it exists

DNS ad-blocking fails quietly. The research behind tonight's setup flagged three
real silent failures, none of which surface an error:

| Failure | What happens | How guard detects it |
|---|---|---|
| **Silent filter fallback** | NextDNS free tier stops filtering past 300k queries/mo but keeps *resolving* — ads just come back | ad domains start returning real IPs while control domains still resolve |
| **Resolver bypass** | Profile drops to carrier DNS on cellular, or a VPN/DHCP takes the resolver | system resolver is no longer `127.0.0.1` |
| **Total DNS failure** | The daemon dies; nothing resolves | control domains stop resolving too |

Without this, the first sign of any of these is ads reappearing and you not knowing why.

## How it works

Every 15 minutes (launchd), `guard_run.py`:
1. `dig`s known ad domains + control domains against `127.0.0.1`
2. classifies the result into `HEALTHY / BLOCKING_DOWN / RESOLVER_BYPASS / DNS_DOWN`
3. logs it, and **alerts your ntfy bridge only on a state *change*** (no spam)

The classification core (`adblock_guard.py`) is pure and unit-tested (19 tests).

## Commands

```bash
python3 src/guard_run.py            # one check (what launchd runs)
python3 src/guard_run.py --status   # last known state
python3 src/guard_run.py --test-alert   # verify the alert channel
python3 src/guard_dashboard.py      # regenerate config/dashboard.html
open config/dashboard.html          # view the status page
```

## Config — `config/adblock-guard.json`

```json
{
  "ad_domains": ["doubleclick.net", "..."],
  "control_domains": ["apple.com", "cloudflare.com"],
  "resolver": "127.0.0.1",
  "ntfy_topic": "vajra-alerts",
  "use_capos_actuator": true
}
```

Alerts prefer the CapOS ntfy actuator (reaches the phone bus `vajra-ad91673f75`);
a raw ntfy POST to `ntfy_topic` is the fallback.

## Manage the LaunchAgent

```bash
launchctl unload ~/Library/LaunchAgents/com.viraansh.adblockguard.plist  # stop
launchctl load   ~/Library/LaunchAgents/com.viraansh.adblockguard.plist  # start
tail -f config/guard.out.log                                             # watch
```

## Uninstall

```bash
launchctl unload ~/Library/LaunchAgents/com.viraansh.adblockguard.plist
rm ~/Library/LaunchAgents/com.viraansh.adblockguard.plist
rm -rf ~/adblock-guard
```
