# `har_capture.py` — Traffic Capture

Records every HTTP and HTTPS request and response as a valid `.har` (HTTP Archive) file for later inspection, replay, or import into tools like Charles Proxy, Insomnia, or browser DevTools.

## How it works

Every completed flow is appended to a rolling HAR file. Files are bucketed by date and client IP so a long capture session stays organized and individual clients can be reviewed in isolation.

## Output layout

```
Mitmproxy_Outputs/HAR_Out/
└── YYYY-MM-DD/
    └── <client-ip>/
        └── <hostname>.har
```

## Options

| Option | Default | Description |
|---|---|---|
| _(none yet)_ | — | Configuration is currently handled via `config.py`. |

## Usage

```bash
# via the loader
mitmdump -s script.py --set modules=har_capture

# standalone
mitmproxy -s har_capture.py
```

## Notes

- HAR files are flushed after every response, so captures survive a crash mid-session.
- The `debug.log` in `Mitmproxy_Outputs/Other/` records every file written and any serialization errors.
