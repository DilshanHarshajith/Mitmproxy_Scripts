#!/usr/bin/env python3
"""
HAR (HTTP Archive) traffic capture functionality.
"""

import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from pathlib import Path
from mitmproxy import http, ctx
import base64
import tldextract

try:
    from config import (
        CAPTURE_DIR, SAVE_INTERVAL, HTTP_OK, HTTP_MULTIPLE_CHOICES, DEBUG_LOG
    )
except ImportError:
    # Standalone config fallbacks
    OUT_DIR = Path.cwd() / "Mitmproxy_Outputs"
    CAPTURE_DIR = OUT_DIR / "HAR_Out"
    SAVE_INTERVAL = 60
    HTTP_OK = 200
    HTTP_MULTIPLE_CHOICES = 300
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

def safe_decode(content: Optional[bytes], encoding: str = "utf-8") -> str:
    """Safely decode bytes to string with base64 fallback."""
    if not content:
        return ""
    
    try:
        return content.decode(encoding)
    except (UnicodeDecodeError, AttributeError):
        return base64.b64encode(content).decode("ascii")


class HAREntry:
    """Helper class to create HAR entries from flows."""
    
    @staticmethod
    def create_request_entry(request: http.Request) -> Dict:
        """
        Create HAR request entry.
        
        Args:
            request: HTTP request object
            
        Returns:
            HAR request dictionary
        """
        req_headers = [{"name": k, "value": v} for k, v in request.headers.items()]
        req_body = safe_decode(request.content)
        
        entry = {
            "method": request.method,
            "url": request.pretty_url,
            "httpVersion": f"HTTP/{request.http_version}",
            "headers": req_headers,
            "queryString": [{"name": k, "value": v} for k, v in request.query.items()],
            "headersSize": -1,
            "bodySize": len(request.content) if request.content else 0
        }
        
        if req_body:
            entry["postData"] = {
                "mimeType": request.headers.get("content-type", ""),
                "text": req_body
            }
        
        return entry
    
    @staticmethod
    def create_response_entry(response: http.Response) -> Dict:
        """
        Create HAR response entry.
        
        Args:
            response: HTTP response object
            
        Returns:
            HAR response dictionary
        """
        if not response:
            return {
                "status": 0,
                "statusText": "No Response",
                "httpVersion": "",
                "headers": [],
                "content": {"size": 0, "mimeType": "", "text": ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": 0
            }
        
        resp_headers = [{"name": k, "value": v} for k, v in response.headers.items()]
        resp_body = safe_decode(response.content)
        
        return {
            "status": response.status_code,
            "statusText": response.reason,
            "httpVersion": f"HTTP/{response.http_version}",
            "headers": resp_headers,
            "content": {
                "size": len(response.content) if response.content else 0,
                "mimeType": response.headers.get("content-type", ""),
                "text": resp_body
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(response.content) if response.content else 0
        }
    
    @staticmethod
    def create_timings_entry(flow: http.HTTPFlow) -> Dict:
        """
        Create HAR timings entry.
        
        Args:
            flow: HTTP flow object
            
        Returns:
            HAR timings dictionary
        """
        start_time = flow.timestamp_start
        end_time = getattr(flow, "timestamp_end", None) or \
                   getattr(flow.response, "timestamp_end", None) if flow.response else start_time
        total_time = max(0, (end_time - start_time) * 1000)
        
        return {
            "blocked": -1,
            "dns": -1,
            "connect": -1,
            "send": 0,
            "wait": total_time,
            "receive": 0,
            "ssl": -1
        }


class TrafficCapture:
    """Captures HTTP traffic and saves to HAR files."""
    
    def __init__(self):
        self.base_dir = CAPTURE_DIR
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.flows: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
        self.save_interval = SAVE_INTERVAL
        self.lock = threading.Lock()
        
        # Start background save thread
        threading.Thread(target=self._periodic_save, daemon=True).start()
        
        debug_log("TrafficCapture initialized")

    def create_har_entry(self, flow: http.HTTPFlow) -> Dict:
        """
        Create HAR entry from flow.
        
        Args:
            flow: HTTP flow object
            
        Returns:
            Complete HAR entry dictionary
        """
        client_ip = get_client_ip(flow)
        
        return {
            "startedDateTime": datetime.fromtimestamp(flow.timestamp_start).isoformat() + "Z",
            "time": HAREntry.create_timings_entry(flow)["wait"],
            "request": HAREntry.create_request_entry(flow.request),
            "response": HAREntry.create_response_entry(flow.response),
            "cache": {},
            "timings": HAREntry.create_timings_entry(flow),
            "serverIPAddress": flow.server_conn.peername[0] if flow.server_conn and flow.server_conn.peername else "",
            "connection": str(id(flow.client_conn)),
            "_clientIP": client_ip
        }

    def add_flow(self, client_ip: str, har_entry: Dict) -> None:
        """
        Add a flow entry for global and domain-specific captures.
        
        Args:
            client_ip: Client IP address
            har_entry: HAR entry dictionary
        """
        url = har_entry.get("request", {}).get("url", "")
        extracted = tldextract.extract(url)
        domain = extracted.registered_domain or extracted.domain or "unknown"
        
        with self.lock:
            # Global capture
            self.flows[(client_ip, "global")].append(har_entry)
            # Domain-specific capture
            self.flows[(client_ip, domain)].append(har_entry)

    def _periodic_save(self) -> None:
        """Periodically save flows to HAR files."""
        while True:
            time.sleep(self.save_interval)
            try:
                self._save_flows()
            except Exception as e:
                debug_log(f"Error in periodic save: {e}")

    def _save_flows(self) -> None:
        """Save accumulated flows to HAR files."""
        with self.lock:
            if not self.flows:
                return
            flows_copy = dict(self.flows)
            self.flows.clear()

        current_date = datetime.now().strftime("%Y-%m-%d")
        for (client_ip, domain), entries in flows_copy.items():
            if domain == "global":
                client_dir = self.base_dir / current_date
            else:
                client_dir = self.base_dir / current_date / domain
                
            client_dir.mkdir(parents=True, exist_ok=True)
            har_file = client_dir / f"{client_ip}.har"

            try:
                # Load existing entries
                if har_file.exists():
                    with open(har_file, "r") as f:
                        old = json.load(f).get("log", {}).get("entries", [])
                else:
                    old = []
            except Exception as e:
                debug_log(f"Error loading existing HAR file: {e}")
                old = []

            # Merge and save
            all_entries = old + entries
            har_data = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "Evil_Proxy", "version": "1.0"},
                    "browser": {"name": "Unknown", "version": "Unknown"},
                    "pages": [],
                    "entries": all_entries
                }
            }

            try:
                # Atomic write
                temp_file = har_file.with_suffix('.tmp')
                with open(temp_file, "w") as f:
                    json.dump(har_data, f, indent=2)
                temp_file.replace(har_file)
                
                debug_log(f"Saved {len(entries)} entries for {client_ip} under {domain}")
            except Exception as e:
                debug_log(f"Error saving HAR file: {e}")
                


class HARCaptureAddon:
    """Mitmproxy addon for HAR capture."""
    
    def __init__(self):
        self.traffic_capture = TrafficCapture()
        debug_log("HARCaptureAddon initialized")

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle responses - capture traffic."""
        try:
            client_ip = get_client_ip(flow)
            
            # Capture all traffic
            har_entry = self.traffic_capture.create_har_entry(flow)
            self.traffic_capture.add_flow(client_ip, har_entry)
                
        except Exception as e:
            debug_log(f"Error in response handler: {e}")

    def done(self) -> None:
        """Handle mitmproxy shutdown - ensure flows are saved."""
        debug_log("HARCaptureAddon shutting down - saving flows...")
        try:
            self.traffic_capture._save_flows()
        except Exception as e:
            debug_log(f"Error saving flows on shutdown: {e}")

addons = [HARCaptureAddon()]
