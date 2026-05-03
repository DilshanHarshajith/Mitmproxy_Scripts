# `script.py` — Dynamic Module Loader

The central orchestrator for the suite. Discovers and mounts other addon modules in the same directory at startup, so you run one command regardless of which combination of features you need.

## How it works

On startup, `script.py` scans the current directory for `.py` files that expose a mitmproxy `addons` list. It imports each qualifying file as a module and registers its addons with the mitmproxy event loop. The set of modules to load can be restricted with the `modules` option.

## Options

| Option | Default | Description |
|---|---|---|
| `modules` | _(all discovered)_ | Comma-separated list of module names (without `.py`) to load. If omitted, every discoverable addon in the directory is loaded. |

## Usage

```bash
# Load all available modules
mitmdump -s script.py

# Load specific modules
mitmdump -s script.py --set modules="har_capture,token_extractor"

# Load a single module through the loader
mitmdump -s script.py --set modules=media_extractor

# Pass module-specific options alongside the loader
mitmdump -s script.py \
  --set modules="media_extractor,token_extractor" \
  --set media_types=pics \
  --set media_domains="*.example.com"
```

## Available modules

| Module | Purpose | Doc |
|---|---|---|
| `har_capture` | Save full request/response traffic as HAR files | [docs/har_capture.md](har_capture.md) |
| `token_extractor` | Extract JWTs, session cookies, and API keys | [docs/token_extractor.md](token_extractor.md) |
| `media_extractor` | Download images and videos from responses | [docs/media_extractor.md](media_extractor.md) |
| `ip_blocker` | Auto-block IPs that hit auth failure thresholds | [docs/ip_blocker.md](ip_blocker.md) |

## Notes

- Module load order follows directory listing order. Modules that depend on each other should be loaded together; there is no explicit dependency resolution.
- Errors during a module's import are logged to `debug.log` and that module is skipped; other modules continue loading normally.
- `config.py` is not a loadable addon — it is a shared configuration file imported by other modules.
