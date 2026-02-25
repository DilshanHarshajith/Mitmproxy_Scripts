# Mitmproxy Scripts

A powerful, modular suite of mitmproxy addons designed to capture, analyze, and manage HTTP/HTTPS traffic. This tool acts as a transparent proxy controller, dynamically loading advanced modules for network forensics, credential extraction, and automated IP blocking.

## Features

- **Dynamic Module Loader (`script.py`)**: A central orchestrator that automatically discovers and loads other addon modules in the directory. You can specify which modules to load with the `--set modules="har_capture,token_extractor"` configuration.
- **Traffic Capture (`har_capture.py`)**: Records full HTTP and HTTPS requests and responses, converting them into valid `.har` (HTTP Archive) files for detailed inspection. Sessions are organized per domain and client IP.
- **Token Extraction (`token_extractor.py`)**: Automatically parses request headers, cookies, and URLs to extract sensitive authentication data, such as JWTs and session cookies. Outputs are neatly saved to JSON per client IP and targeted application.
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

**Basic Usage:**

```bash
mitmdump -s script.py
```

**Loading Specific Modules:**
You can pass the `modules` option to selectively load addons:

```bash
mitmdump -s script.py --set modules="har_capture,token_extractor"
```

## Directory Structure

Generated data, logs, token extracts, and HAR files are stored by default under a `Mitmproxy_Outputs/` directory created dynamically relative current working directory:

- `Mitmproxy_Outputs/HAR_Out/`: Contains daily tracked HAR networks logs.
- `Mitmproxy_Outputs/Tokens/`: Contains extracted JSON authentication cookies and JWTs.
- `Mitmproxy_Outputs/Other/`: Contains the `debug.log` and the `blocked_ips.json` manifest.
