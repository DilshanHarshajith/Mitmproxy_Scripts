# Mitmproxy Scripts

A powerful, modular suite of mitmproxy addons designed to capture, analyze, and manage HTTP/HTTPS traffic. This tool acts as a transparent proxy controller, dynamically loading advanced modules for network forensics, credential extraction, media harvesting, and automated IP blocking.

## Features

- **Dynamic Module Loader (`script.py`)**: A central orchestrator that automatically discovers and loads other addon modules in the directory. You can specify which modules to load with the `--set modules="har_capture,token_extractor"` configuration.
- **Traffic Capture (`har_capture.py`)**: Records full HTTP and HTTPS requests and responses, converting them into valid `.har` (HTTP Archive) files for detailed inspection. Sessions are organized per domain and client IP.
- **Token Extraction (`token_extractor.py`)**: Automatically parses request headers, cookies, and URLs to extract sensitive authentication data, such as JWTs and session cookies. Outputs are neatly saved to JSON per client IP and targeted application.
- **Media Extractor (`media_extractor.py`)**: Intercepts HTTP responses and saves image and video files to disk, organized by date and host. Supports fine-grained filtering by media type, file extension, minimum file size, and domain — including wildcard and exclusion patterns. Deduplicates captures within a session by content hash.
- **Intelligent IP Blocker (`ip_blocker.py`)**: A proactive security module that tracks connection attempts and authentication failures (401, 403, 407). Automatically blocks malicious IPs that hit a defined failure threshold and manages automatic unblocking after a cooldown period.
- **Configurable Settings (`config.py`)**: Centralized configuration management for file paths, intervals, status codes, and threshold definitions.

## Installation

1. First, ensure you have Python 3 and `mitmproxy` installed on your system.
2. Clone this repository into your project directory.
3. Install required Python packages. Most notably, you will need `mitmproxy` and `tldextract`:
   ```bash
   pip install mitmproxy tldextract
   ```

## Usage

Run mitmproxy (or mitmdump/mitmweb) passing the primary `script.py` as the main addon. The loader script will take care of mounting the other functionalities.

**Basic usage:**

```bash
mitmdump -s script.py
```

**Loading specific modules:**

```bash
mitmdump -s script.py --set modules="har_capture,token_extractor"
```

**Running a single addon directly:**

```bash
mitmproxy -s media_extractor.py
```

## Module Options

### `media_extractor.py`

Captures image and video files from intercepted HTTP responses.

| Option           | Default                     | Description                                                                                 |
| ---------------- | --------------------------- | ------------------------------------------------------------------------------------------- |
| `media_types`    | `all`                       | `all`, `pics` (images only), or `vids` (videos only). Ignored when `media_ext` is set.      |
| `media_ext`      | _(empty)_                   | Comma-separated list of extensions to capture, e.g. `jpg,png,mp4`. Overrides `media_types`. |
| `media_out`      | `./Mitmproxy_Outputs/Media` | Output directory for captured files.                                                        |
| `media_min_size` | `512`                       | Minimum response body size in bytes. Smaller responses are skipped.                         |
| `media_domains`  | _(empty)_                   | Domain filter with wildcard support (see below). Empty = capture from all hosts.            |

**Domain filtering (`media_domains`):**

Pass a comma-separated list of hostname patterns. Patterns are matched case-insensitively against the request host (port stripped). Block patterns are prefixed with `!` and are always evaluated before allow patterns.

| Pattern                          | Effect                                                   |
| -------------------------------- | -------------------------------------------------------- |
| `cdn.example.com`                | Allow only that exact host                               |
| `*.example.com`                  | Allow any subdomain (bare `example.com` is not included) |
| `example.com,*.example.com`      | Allow bare domain and all subdomains                     |
| `!ads.example.com`               | Block that host; all others pass                         |
| `*.example.com,!ads.example.com` | Allow all subdomains, except the ads host                |

Wildcards follow shell-glob rules: `*` matches any sequence of characters, `?` matches exactly one character.

**Examples:**

```bash
# Capture all images and videos (default)
mitmproxy -s media_extractor.py

# Images only
mitmproxy -s media_extractor.py --set media_types=pics

# Specific extensions
mitmproxy -s media_extractor.py --set media_ext=jpg,gif,webp,mp4

# Only capture from one domain family, skip its ads subdomain
mitmproxy -s media_extractor.py --set media_domains="*.example.com,!ads.example.com"

# Block one noisy CDN, capture everything else
mitmproxy -s media_extractor.py --set media_domains="!tracking-cdn.net"

# Combine filters: images only, from a specific CDN, skipping tiny files
mitmproxy -s media_extractor.py \
  --set media_types=pics \
  --set media_domains="cdn.example.com" \
  --set media_min_size=2048
```

## Directory Structure

Generated data, logs, token extracts, HAR files, and media are stored under a `Mitmproxy_Outputs/` directory created dynamically relative to the current working directory:

```
Mitmproxy_Outputs/
├── HAR_Out/          # Daily HAR network logs, organized by domain and client IP
├── Tokens/           # Extracted JSON authentication cookies and JWTs, per client IP
├── Media/            # Captured image and video files (media_extractor.py)
│   └── YYYY-MM-DD/
│       └── <hostname>/
│           ├── images/
│           └── videos/
└── Other/
    ├── debug.log         # Shared timestamped debug log across all modules
    └── blocked_ips.json  # IP block manifest managed by ip_blocker.py
```
