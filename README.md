# VPN Kill Switch — Burp Suite Extension

Blocks all Burp Suite traffic the moment your VPN drops. Works with any VPN type — no interface name needed.

## How it works

On load the extension starts **armed** (all traffic blocked). It disarms only once both IP checks succeed. From then on:

- **Every 1 second** — checks local outbound IP via OS routing table (no network call, instant)
- **Every 30 seconds** — checks public IP via HTTPS to an external service (bypasses Burp's own proxy)

If either IP changes, or if the public check fails 3 times in a row, **all Burp traffic is immediately blocked** and must be manually resumed.

## What gets blocked

| Traffic type | How it's blocked |
|---|---|
| Browser → Burp Proxy | Dropped cleanly by proxy handler |
| Repeater, Intruder, Scanner | Redirected to `127.0.0.1:19999` (connection refused) |
| Active Scan, extensions | Same as above |

## Requirements

- Burp Suite (Community or Pro) with Montoya API 2026.2+
- Java 11+

## Build

```bash
git clone https://github.com/cooldadpresident/vpn-kill-switch
cd vpn-kill-switch
gradle jar
# Output: build/libs/vpn-kill-switch.jar
```

## Install

1. Burp Suite → **Extensions** → **Installed** → **Add**
2. Extension type: **Java**
3. Select `build/libs/vpn-kill-switch.jar`
4. Click **Next**

The **VPN Kill Switch** tab will appear in the suite.

## Usage

1. Connect your VPN
2. Load the extension — it will detect both IPs automatically and disarm
3. If it starts armed (VPN not connected), connect your VPN then click **Resume Traffic**
4. Drop VPN → extension arms within 1 second
5. Reconnect VPN → click **Resume Traffic** to verify and resume

The **Resume Traffic** button re-checks both IPs before disarming. If your VPN is not fully up, it will refuse to resume.

## Configuration

The **Check URL** field sets which HTTPS endpoint is used for the public IP check. Default: `https://ifconfig.me`. Must be `https://` or `http://`. The response must be a valid IP address.

Alternatives:
- `https://api.ipify.org`
- `https://checkip.amazonaws.com`

## Security properties

- **Fail-closed by default** — any detection failure (null IP, network error, unexpected response) triggers arming rather than allowing traffic
- **No boot window** — handlers are registered before IP detection runs, with `killed=true` from the start
- **Response validation** — public IP check validates the response matches an IP address pattern; rejects HTML, error pages, captive portal responses
- **URL scheme validation** — only `http://` and `https://` accepted as check URL; `file://`, `jar:`, and similar are rejected
- **Thread safety** — `AtomicBoolean` for kill state, `compareAndSet` prevents duplicate arm calls, all UI updates via `SwingUtilities.invokeLater`
- **Scheduler resilience** — both monitoring tasks wrapped in try/catch to prevent silent task cancellation on exceptions

## Limitations

- In-flight requests that already passed the handler check before the kill switch armed are not recalled — Montoya does not support request cancellation after the handler returns
- The local IP check uses routing toward `8.8.8.8` as a probe destination; on split-tunnel VPNs where the target subnet routes differently from `8.8.8.8`, the local check may not reflect the route to your actual target. The public IP check covers this case
- Traffic from other extensions using their own Java network calls (not Burp's HTTP engine) is not intercepted

## License

MIT
