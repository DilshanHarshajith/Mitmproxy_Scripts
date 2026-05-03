# Mitmproxy Scripts

A modular suite of mitmproxy addons for capturing, analyzing, and managing HTTP/HTTPS traffic — network forensics, credential extraction, media harvesting, and automated IP blocking, all from a single proxy session.

## Quick start

```bash
pip install mitmproxy tldextract

# Run everything
mitmdump -s script.py

# Run specific modules
mitmdump -s script.py --set modules="har_capture,token_extractor"
```

## Modules

| Module | Purpose | Docs |
|---|---|---|
| [`script.py`](docs/script.md) | Dynamic loader — mounts any combination of the modules below | [docs/script.md](docs/script.md) |
| [`har_capture.py`](docs/har_capture.md) | Saves full request/response traffic as `.har` files, organized by date and client IP | [docs/har_capture.md](docs/har_capture.md) |
| [`token_extractor.py`](docs/token_extractor.md) | Extracts JWTs, session cookies, and API keys from headers, cookies, and query parameters | [docs/token_extractor.md](docs/token_extractor.md) |
| [`media_extractor.py`](docs/media_extractor.md) | Downloads images and videos from responses; filterable by type, extension, size, and domain | [docs/media_extractor.md](docs/media_extractor.md) |
| [`ip_blocker.py`](docs/ip_blocker.md) | Auto-blocks IPs that exceed auth failure thresholds; releases them after a cooldown | [docs/ip_blocker.md](docs/ip_blocker.md) |
| [`config.py`](docs/script.md) | Shared configuration — paths, thresholds, and status codes used across modules | — |

## Output layout

All output lands under `Mitmproxy_Outputs/` relative to your working directory:

```
Mitmproxy_Outputs/
├── HAR_Out/          # .har files per date / client IP / hostname
├── Tokens/           # extracted auth tokens per client IP / hostname
├── Media/            # captured images and videos per date / hostname
└── Other/
    ├── debug.log         # timestamped log shared across all modules
    └── blocked_ips.json  # persistent IP block manifest
```

## Adding a new module

1. Create `your_module.py` in the project root with a top-level `addons = [...]` list.
2. `script.py` will discover and load it automatically on next startup.
3. Add a doc file at `docs/your_module.md` and link it in the table above.
