#!/usr/bin/env python3
"""
Configuration constants for the mitmproxy script.
"""

from pathlib import Path
from datetime import timedelta
import re

# === Directory Paths ===
OUT_DIR = Path.cwd() / "Mitmproxy_Outputs"
CAPTURE_DIR = OUT_DIR / "HAR_Out"
EXTRACT_DIR = OUT_DIR / "Tokens"
BLOCKLIST_FILE = OUT_DIR / "Other" / "blocked_ips.json"
DEBUG_LOG = OUT_DIR / "Other" / "debug.log"

# === HTTP Status Codes ===
HTTP_OK = 200
HTTP_MULTIPLE_CHOICES = 300
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_PROXY_AUTH_REQUIRED = 407

# === Blocking Configuration ===
BLOCK_RESET_INTERVAL = timedelta(hours=1)  # Auto-unblock after 1 hour
BLOCK_THRESHOLD = 10  # Block after 10 attempts
CLEANUP_INTERVAL = 60  # Check every 1 minute for more responsive unblocking
CONNECTION_TIMEOUT = 30  # Seconds to track connection attempts

# === Regular Expressions ===
JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+')

# === Timing Configuration ===
SAVE_INTERVAL = 60  # Save flows every 60 seconds
STATUS_LOG_INTERVAL = 300  # Log status every 5 minutes
