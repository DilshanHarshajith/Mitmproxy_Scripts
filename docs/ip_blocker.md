# `ip_blocker.py` — Intelligent IP Blocker

Proactively blocks client IPs that exhibit suspicious behaviour — repeated authentication failures, excessive connection attempts, or repeated access to restricted endpoints — and automatically lifts blocks after a configurable cooldown period.

## How it works

Every response is checked against a set of trigger conditions. When a client IP accumulates enough trigger events within a rolling window, it is added to the block list. Subsequent connections from that IP are refused at the proxy level. A background job periodically reviews the block list and removes entries whose cooldown has expired.

The block manifest is persisted to disk so the list survives a proxy restart.

## Trigger conditions

| Condition | Default threshold |
|---|---|
| HTTP 401 Unauthorized | configurable via `config.py` |
| HTTP 403 Forbidden | configurable via `config.py` |
| HTTP 407 Proxy Auth Required | configurable via `config.py` |

## Output layout

```
Mitmproxy_Outputs/Other/
└── blocked_ips.json    # persistent block manifest
```

`blocked_ips.json` structure:

```json
{
  "192.168.1.42": {
    "blocked_at": "2024-11-10T14:00:00Z",
    "reason": "401 threshold exceeded (12 hits)",
    "unblock_at": "2024-11-10T15:00:00Z"
  }
}
```

## Configuration (`config.py`)

| Key | Description |
|---|---|
| `BLOCK_THRESHOLD` | Number of trigger events before an IP is blocked |
| `BLOCK_COOLDOWN` | Duration (seconds) before a blocked IP is released |
| `TRIGGER_CODES` | Set of HTTP status codes that count as trigger events |

## Usage

```bash
# via the loader
mitmdump -s script.py --set modules=ip_blocker

# standalone
mitmproxy -s ip_blocker.py
```

## Notes

- Blocking is enforced at the mitmproxy connection level; blocked clients receive a TCP RST rather than an HTTP error.
- The cooldown timer resets if a blocked IP attempts another connection while still blocked.
- Review `debug.log` for a timestamped record of block and unblock events.
