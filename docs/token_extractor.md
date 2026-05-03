# `token_extractor.py` — Token Extraction

Automatically parses intercepted requests to extract sensitive authentication material — JWTs, session cookies, API keys, and bearer tokens — and saves them as structured JSON files organized by client IP and target application.

## How it works

On every request, the module scans:

- **Headers** — `Authorization`, `X-Auth-Token`, `X-Api-Key`, and similar.
- **Cookies** — all cookie values are inspected; known session cookie names are flagged.
- **Query parameters** — URL parameters that commonly carry tokens (e.g. `access_token`, `token`, `api_key`).

Detected values are written to a per-client JSON file. JWTs are decoded (header + payload, signature not verified) so the claims are immediately readable.

## Output layout

```
Mitmproxy_Outputs/Tokens/
└── <client-ip>/
    └── <hostname>.json
```

Each JSON file is an append-only list of extraction events:

```json
[
  {
    "timestamp": "2024-11-10T14:32:01Z",
    "url": "https://api.example.com/v1/user",
    "source": "header",
    "key": "Authorization",
    "value": "Bearer eyJ...",
    "decoded": { "sub": "user_42", "exp": 1731000000 }
  }
]
```

## Options

| Option | Default | Description |
|---|---|---|
| _(none yet)_ | — | Configuration is currently handled via `config.py`. |

## Usage

```bash
# via the loader
mitmdump -s script.py --set modules=token_extractor

# standalone
mitmproxy -s token_extractor.py
```

## Notes

- Token values are written verbatim — no redaction is applied. Treat output files as sensitive material.
- The module does not modify requests or responses; it is read-only.
