#!/usr/bin/env python3
"""
IP blocking and rate limiting functionality.
"""

import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
from pathlib import Path
from mitmproxy import ctx, http

try:
    from config import (
        BLOCKLIST_FILE, BLOCK_RESET_INTERVAL, BLOCK_THRESHOLD,
        CLEANUP_INTERVAL, CONNECTION_TIMEOUT, STATUS_LOG_INTERVAL,
        HTTP_OK, HTTP_MULTIPLE_CHOICES, HTTP_UNAUTHORIZED,
        HTTP_FORBIDDEN, HTTP_PROXY_AUTH_REQUIRED, DEBUG_LOG
    )
except ImportError:
    # Standalone config fallbacks
    OUT_DIR = Path.cwd() / "Mitmproxy_Outputs"
    BLOCKLIST_FILE = OUT_DIR / "Other" / "blocked_ips.json"
    BLOCK_RESET_INTERVAL = timedelta(hours=1)
    BLOCK_THRESHOLD = 10
    CLEANUP_INTERVAL = 60
    CONNECTION_TIMEOUT = 30
    STATUS_LOG_INTERVAL = 300
    HTTP_OK = 200
    HTTP_MULTIPLE_CHOICES = 300
    HTTP_UNAUTHORIZED = 401
    HTTP_FORBIDDEN = 403
    HTTP_PROXY_AUTH_REQUIRED = 407
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


class IPBlocker:
    """Manages IP blocking, rate limiting, and auto-unblocking."""
    
    def __init__(self):
        self.blocked_ips: Dict[str, str] = {}  # IP -> block_time mapping
        self.to_block: Dict[str, int] = defaultdict(int)  # IP -> failure count
        self.connection_attempts: Dict[str, List[float]] = defaultdict(list)  # IP -> [timestamps]
        self.block_threshold = BLOCK_THRESHOLD
        self.lock = threading.Lock()
        
        # Ensure directory exists
        BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        self._last_save_state: Optional[str] = None
        self._last_file_mtime: float = 0  # Track file modification time
        
        self._load_blocked_ips()
        self._start_background_threads()
        
        debug_log(f"IPBlocker initialized with threshold: {self.block_threshold}")

    def _start_background_threads(self) -> None:
        """Start all background threads."""
        threading.Thread(target=self._periodic_cleanup, daemon=True).start()
        threading.Thread(target=self._periodic_status, daemon=True).start()

    def _periodic_status(self) -> None:
        """Periodically log status for debugging."""
        while True:
            time.sleep(STATUS_LOG_INTERVAL)
            with self.lock:
                blocked_count = len(self.blocked_ips)
                pending_count = len(self.to_block)
                connection_count = len(self.connection_attempts)
                debug_log(
                    f"Status: {blocked_count} blocked, {pending_count} pending, "
                    f"{connection_count} tracked connections"
                )
                
                if self.blocked_ips:
                    current_time = datetime.now()
                    for ip, block_time_str in self.blocked_ips.items():
                        try:
                            block_time = datetime.fromisoformat(block_time_str)
                            time_remaining = BLOCK_RESET_INTERVAL - (current_time - block_time)
                            if time_remaining.total_seconds() > 0:
                                debug_log(
                                    f"  Blocked: {ip} - {time_remaining.total_seconds():.0f}s remaining"
                                )
                        except (ValueError, TypeError):
                            debug_log(f"  Blocked: {ip} - invalid timestamp")

    def _load_blocked_ips(self) -> None:
        """Load blocked IPs from file."""
        if BLOCKLIST_FILE.exists():
            try:
                # Track file modification time
                self._last_file_mtime = BLOCKLIST_FILE.stat().st_mtime
                
                with open(BLOCKLIST_FILE) as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.blocked_ips = data
                    else:
                        # Old format - convert to new format
                        self.blocked_ips = {}
                        for ip in data:
                            self.blocked_ips[ip] = datetime.now().isoformat()
                debug_log(f"Loaded {len(self.blocked_ips)} blocked IPs from file")
            except Exception as e:
                debug_log(f"Failed to load blocked IPs: {e}")
                self.blocked_ips = {}

    def _save_blocked_ips(self) -> None:
        """Save blocked IPs to file with deduplication."""
        # Only save if state has changed
        current_state = json.dumps(self.blocked_ips, sort_keys=True)
        if current_state == self._last_save_state:
            return
        
        try:
            # Atomic write using temporary file
            temp_file = BLOCKLIST_FILE.with_suffix('.tmp')
            with open(temp_file, "w") as f:
                json.dump(self.blocked_ips, f, indent=2)
            temp_file.replace(BLOCKLIST_FILE)
            
            # Update modification time tracking to avoid reloading our own changes
            if BLOCKLIST_FILE.exists():
                self._last_file_mtime = BLOCKLIST_FILE.stat().st_mtime
            
            self._last_save_state = current_state
            debug_log(f"Saved {len(self.blocked_ips)} blocked IPs to file")
        except Exception as e:
            debug_log(f"Failed to save blocked IPs: {e}")

    def _check_external_changes(self) -> None:
        """Check if blocklist file was modified externally and reload if needed."""
        if not BLOCKLIST_FILE.exists():
            # File was deleted externally, clear blocklist
            if self.blocked_ips:
                debug_log("Blocklist file deleted externally, clearing all blocks")
                self.blocked_ips = {}
                self._last_file_mtime = 0
            return
        
        try:
            current_mtime = BLOCKLIST_FILE.stat().st_mtime
            if current_mtime > self._last_file_mtime:
                debug_log(f"Blocklist file modified externally (mtime: {current_mtime} > {self._last_file_mtime}), reloading...")
                old_count = len(self.blocked_ips)
                self._load_blocked_ips()
                new_count = len(self.blocked_ips)
                
                if old_count != new_count:
                    debug_log(f"Reloaded blocklist: {old_count} -> {new_count} blocked IPs")
                    try:
                        if hasattr(ctx, 'log') and ctx.log:
                            ctx.log.info(f"[SYNC] Blocklist reloaded from file: {old_count} -> {new_count} IPs")
                    except (AttributeError, NameError):
                        pass
        except Exception as e:
            debug_log(f"Error checking for external changes: {e}")

    def _periodic_cleanup(self) -> None:
        """Periodically unblock IPs and clean up old connection attempts."""
        debug_log("Starting periodic cleanup thread")
        while True:
            time.sleep(CLEANUP_INTERVAL)
            try:
                self._check_external_changes()  # Check for external modifications first
                self._cleanup_expired_blocks()
                self._cleanup_old_connections()
            except Exception as e:
                debug_log(f"Error in periodic cleanup: {e}")

    def _cleanup_expired_blocks(self) -> None:
        """Remove expired IP blocks."""
        current_time = datetime.now()
        to_unblock = []
        
        with self.lock:
            for ip, block_time_str in self.blocked_ips.items():
                try:
                    block_time = datetime.fromisoformat(block_time_str)
                    if current_time - block_time > BLOCK_RESET_INTERVAL:
                        to_unblock.append(ip)
                except (ValueError, TypeError):
                    debug_log(f"Invalid timestamp for {ip}: {block_time_str}")
                    to_unblock.append(ip)
            
            if to_unblock:
                for ip in to_unblock:
                    del self.blocked_ips[ip]
                    self.to_block.pop(ip, None)
                    self.connection_attempts.pop(ip, None)
                    debug_log(f"AUTO-UNBLOCKED {ip} after {BLOCK_RESET_INTERVAL}")
                
                self._save_blocked_ips()
                try:
                    if hasattr(ctx, 'log') and ctx.log:
                        ctx.log.info(f"Auto-unblocked {len(to_unblock)} IPs after timeout")
                except (AttributeError, NameError):
                    pass

    def _cleanup_old_connections(self) -> None:
        """Clean up old connection attempt records."""
        current_time = time.time()
        cutoff_time = current_time - CONNECTION_TIMEOUT
        
        with self.lock:
            for ip in list(self.connection_attempts.keys()):
                # Remove old attempts
                self.connection_attempts[ip] = [
                    t for t in self.connection_attempts[ip] 
                    if t > cutoff_time
                ]
                # Remove IPs with no recent attempts
                if not self.connection_attempts[ip]:
                    del self.connection_attempts[ip]

    def track_connection_attempt(self, ip: str) -> bool:
        """
        Track connection attempts and block if too many.
        
        Args:
            ip: Client IP address
            
        Returns:
            True if IP should be blocked, False otherwise
        """
        current_time = time.time()
        
        with self.lock:
            if ip in self.blocked_ips:
                debug_log(f"Connection attempt from already blocked IP: {ip}")
                return True
            
            # Add current attempt
            self.connection_attempts[ip].append(current_time)
            
            # Remove old attempts
            cutoff_time = current_time - CONNECTION_TIMEOUT
            self.connection_attempts[ip] = [
                t for t in self.connection_attempts[ip] 
                if t > cutoff_time
            ]
            
            attempt_count = len(self.connection_attempts[ip])
            debug_log(f"Connection attempt from {ip}: {attempt_count} attempts in {CONNECTION_TIMEOUT}s")
            
            # Block if too many attempts
            if attempt_count >= self.block_threshold:
                self.blocked_ips[ip] = datetime.now().isoformat()
                self.to_block.pop(ip, None)
                del self.connection_attempts[ip]
                self._save_blocked_ips()
                debug_log(f"BLOCKED {ip} after {attempt_count} connection attempts")
                try:
                    if hasattr(ctx, 'log') and ctx.log:
                        ctx.log.warn(f"[BLOCKED] {ip} blocked after {attempt_count} rapid connection attempts")
                except (AttributeError, NameError):
                    pass
                return True
            
            return False

    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if an IP is currently blocked.
        
        Args:
            ip: Client IP address
            
        Returns:
            True if blocked, False otherwise
        """
        with self.lock:
            if ip in self.blocked_ips:
                # Double-check if block has expired
                try:
                    block_time = datetime.fromisoformat(self.blocked_ips[ip])
                    if datetime.now() - block_time > BLOCK_RESET_INTERVAL:
                        # Block has expired, remove it
                        del self.blocked_ips[ip]
                        self.to_block.pop(ip, None)
                        self.connection_attempts.pop(ip, None)
                        self._save_blocked_ips()
                        debug_log(f"AUTO-UNBLOCKED {ip} during check (expired)")
                        return False
                    return True
                except (ValueError, TypeError):
                    # Invalid timestamp, unblock
                    del self.blocked_ips[ip]
                    return False
            return False

    def block_ip(self, ip: str, reason: str = "Manual") -> None:
        """
        Block an IP address.
        
        Args:
            ip: Client IP address
            reason: Reason for blocking
        """
        with self.lock:
            self.blocked_ips[ip] = datetime.now().isoformat()
            self.to_block.pop(ip, None)
            self.connection_attempts.pop(ip, None)
            self._save_blocked_ips()
            debug_log(f"BLOCKED {ip} - Reason: {reason}")
            try:
                if hasattr(ctx, 'log') and ctx.log:
                    ctx.log.warn(f"[BLOCKED] {ip} - {reason}")
            except (AttributeError, NameError):
                pass

    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip: Client IP address
            
        Returns:
            True if IP was blocked and is now unblocked, False otherwise
        """
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self.to_block.pop(ip, None)
                self.connection_attempts.pop(ip, None)
                self._save_blocked_ips()
                debug_log(f"MANUALLY UNBLOCKED {ip}")
                try:
                    if hasattr(ctx, 'log') and ctx.log:
                        ctx.log.info(f"[UNBLOCKED] {ip} manually unblocked")
                except (AttributeError, NameError):
                    pass
                return True
            else:
                debug_log(f"IP {ip} not found in blocklist")
                return False

    def increment_failure_count(self, ip: str) -> bool:
        """
        Increment failure count for an IP and block if threshold reached.
        
        Args:
            ip: Client IP address
            
        Returns:
            True if IP was blocked, False otherwise
        """
        with self.lock:
            if ip in self.blocked_ips:
                debug_log(f"IP {ip} already blocked, ignoring failure")
                return False
            
            self.to_block[ip] += 1/2
            current_count = self.to_block[ip]
            
            debug_log(f"Incremented failure count for {ip}: {current_count}/{self.block_threshold}")
            
            if current_count >= self.block_threshold:
                self.blocked_ips[ip] = datetime.now().isoformat()
                del self.to_block[ip]
                self.connection_attempts.pop(ip, None)
                self._save_blocked_ips()
                debug_log(f"BLOCKED {ip} after {self.block_threshold} failures")
                try:
                    if hasattr(ctx, 'log') and ctx.log:
                        ctx.log.warn(f"[BLOCKED] {ip} blocked after {self.block_threshold} authentication failures")
                except (AttributeError, NameError):
                    pass
                return True
            
            return False

    def reset_failure_count(self, ip: str) -> None:
        """
        Reset failure count for an IP on successful response.
        
        Args:
            ip: Client IP address
        """
        with self.lock:
            if ip in self.to_block:
                old_count = self.to_block[ip]
                del self.to_block[ip]
                debug_log(f"Reset failure count for {ip} (was {old_count})")

    def get_status(self) -> Dict:
        """
        Get current blocking status.
        
        Returns:
            Dictionary with blocking statistics
        """
        with self.lock:
            return {
                "blocked_ips": dict(self.blocked_ips),
                "pending_blocks": dict(self.to_block),
                "block_threshold": self.block_threshold
            }


# Global singleton instance
ip_blocker_instance = IPBlocker()

class IPBlockerAddon:
    """Mitmproxy addon that coordinates IP blocking functionality."""
    
    def __init__(self):
        self.ip_blocker = ip_blocker_instance
        debug_log("IPBlockerAddon initialized")

    def tcp_start(self, flow: http.HTTPFlow) -> None:
        """Handle TCP connection start - block connections from blocked IPs immediately."""
        try:
            if flow.client_conn and flow.client_conn.peername:
                client_ip = normalize_ip(flow.client_conn.peername[0])
                
                # Check if IP is blocked FIRST
                if self.ip_blocker.is_ip_blocked(client_ip):
                    debug_log(f"KILLING TCP connection from blocked IP: {client_ip}")
                    flow.kill()
                    return
                
                debug_log(f"TCP connection from {client_ip}")
                
                # Track connection attempt for rate limiting
                should_block = self.ip_blocker.track_connection_attempt(client_ip)
                
                if should_block:
                    debug_log(f"KILLING TCP connection from {client_ip} (rate limited)")
                    flow.kill()
                    return
                    
        except Exception as e:
            debug_log(f"Error in tcp_start: {e}")

    def tcp_end(self, flow: http.HTTPFlow) -> None:
        """Handle TCP connection end."""
        try:
            if flow.client_conn and flow.client_conn.peername:
                client_ip = normalize_ip(flow.client_conn.peername[0])
                debug_log(f"TCP disconnect from {client_ip}")
                
        except Exception as e:
            debug_log(f"Error in tcp_end: {e}")

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP CONNECT requests - block at tunnel establishment."""
        try:
            client_ip = get_client_ip(flow)
            
            if self.ip_blocker.is_ip_blocked(client_ip):
                debug_log(f"KILLING HTTP CONNECT from blocked IP {client_ip}")
                flow.kill()
                return
                
        except Exception as e:
            debug_log(f"Error in http_connect: {e}")

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        """Handle request headers - earliest point to block HTTP flows."""
        try:
            client_ip = get_client_ip(flow)
            
            # Check if IP is blocked at the earliest possible moment
            if self.ip_blocker.is_ip_blocked(client_ip):
                debug_log(f"KILLING flow at headers stage from blocked IP {client_ip}")
                flow.kill()
                return
                
        except Exception as e:
            debug_log(f"Error in requestheaders: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle incoming requests - perform secondary blocking check."""
        try:
            # Get client IP
            client_ip = get_client_ip(flow)
            
            # Double-check if IP is blocked (should be caught earlier)
            if self.ip_blocker.is_ip_blocked(client_ip):
                debug_log(f"KILLING request from blocked IP {client_ip} (fallback)")
                flow.kill()
                return
            
        except Exception as e:
            debug_log(f"Error in request handler: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle responses - process only flows from non-blocked IPs."""
        try:
            client_ip = get_client_ip(flow)
            
            # Skip ALL processing for blocked IPs
            if self.ip_blocker.is_ip_blocked(client_ip):
                debug_log(f"Skipping response processing for blocked IP {client_ip}")
                return
            
            if not flow.response:
                debug_log(f"No response for {client_ip}")
                return
            
            status_code = flow.response.status_code
            debug_log(f"Response {status_code} for {client_ip}")
            
            # Handle authentication failures
            if status_code == HTTP_PROXY_AUTH_REQUIRED:
                debug_log(f"407 Proxy Authentication Required from {client_ip}")
                was_blocked = self.ip_blocker.increment_failure_count(client_ip)
                if was_blocked:
                    try:
                        if hasattr(ctx, 'log') and ctx.log:
                            ctx.log.warn(f"[BLOCKED] {client_ip} after repeated 407 errors")
                    except (AttributeError, NameError):
                        pass
                    return
            
            # Handle other authentication/authorization failures
            elif status_code in [HTTP_UNAUTHORIZED, HTTP_FORBIDDEN]:
                debug_log(f"{status_code} Auth failure from {client_ip}")
                was_blocked = self.ip_blocker.increment_failure_count(client_ip)
                if was_blocked:
                    try:
                        if hasattr(ctx, 'log') and ctx.log:
                            ctx.log.warn(f"[BLOCKED] {client_ip} after repeated auth failures")
                    except (AttributeError, NameError):
                        pass
                    return
            
            # Reset failure count on successful responses
            elif HTTP_OK <= status_code < HTTP_MULTIPLE_CHOICES:
                self.ip_blocker.reset_failure_count(client_ip)
                
        except Exception as e:
            debug_log(f"Error in response handler: {e}")

    def error(self, flow: http.HTTPFlow) -> None:
        """Handle flow errors - only process flows from non-blocked IPs."""
        try:
            client_ip = get_client_ip(flow)
            
            # Skip processing for blocked IPs
            if self.ip_blocker.is_ip_blocked(client_ip):
                debug_log(f"Skipping error processing for blocked IP {client_ip}")
                return
            
            error_msg = str(flow.error) if flow.error else "Unknown error"
            debug_log(f"Flow error for {client_ip}: {error_msg}")
            
        except Exception as e:
            debug_log(f"Error in error handler: {e}")

    def done(self) -> None:
        """Handle mitmproxy shutdown - ensure blocklist is saved."""
        debug_log("IPBlockerAddon shutting down - saving blocklist...")
        try:
            self.ip_blocker._save_blocked_ips()
        except Exception as e:
            debug_log(f"Error saving blocklist on shutdown: {e}")

addons = [IPBlockerAddon()]
