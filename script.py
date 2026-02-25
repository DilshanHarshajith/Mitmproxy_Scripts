#!/usr/bin/env python3
"""
Mitmproxy Controller Script

This script dynamically loads other addon scripts from the same directory.
It acts as a central entry point for mitmproxy.
"""

import importlib
import sys
from datetime import datetime
from pathlib import Path
from mitmproxy import ctx

try:
    from config import DEBUG_LOG
except ImportError:
    OUT_DIR = Path.cwd() / "Mitmproxy_Outputs"
    DEBUG_LOG = OUT_DIR / "Other" / "debug.log"

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

class MitmLoader:
    def __init__(self):
        self.loaded_addons = []

    def load(self, loader):
        loader.add_option(
            name="modules",
            typespec=str,
            default="",
            help="Comma-separated list of modules to load (default: load all valid scripts)",
        )

    def running(self):
        """
        Called when mitmproxy is running. We load the addons here because
        we need access to the options.
        """
        self._load_dynamic_addons()

    def _load_dynamic_addons(self):
        current_dir = Path(__file__).parent.resolve()
        sys.path.insert(0, str(current_dir))

        debug_log(f"Scanning for addons in {current_dir}")

        # Files to exclude from loading
        excluded_files = {
            "__init__.py",
            "config.py",
            "script.py",
            "loader.py"
        }

        # Parse the option
        # If empty string, load all. If not empty, only load those specified.
        allowed_modules_str = ctx.options.modules.strip()
        allowed_modules = None
        if allowed_modules_str:
            allowed_modules = {m.strip() for m in allowed_modules_str.split(",") if m.strip()}
            debug_log(f"Filtering modules. Allowed: {allowed_modules}")

        count = 0
        for file_path in current_dir.glob("*.py"):
            if file_path.name in excluded_files:
                continue

            module_name = file_path.stem

            # Filter check
            if allowed_modules is not None and module_name not in allowed_modules:
                debug_log(f"Skipping {module_name}: Not in allowed list")
                continue

            try:
                debug_log(f"Loading addon: {module_name}")
                module = importlib.import_module(module_name)

                if hasattr(module, "addons") and isinstance(module.addons, list):
                    # Register the addons with mitmproxy
                    ctx.master.addons.add(*module.addons)
                    self.loaded_addons.extend(module.addons)
                    count += 1
                    debug_log(f"Successfully loaded {module_name}")
                else:
                    debug_log(f"Skipping {module_name}: No 'addons' list found")

            except Exception as e:
                debug_log(f"Failed to load {module_name}: {e}")
                if hasattr(ctx, 'log'):
                     ctx.log.error(f"Failed to load addon {module_name}: {e}")

        debug_log(f"Total addons loaded: {len(self.loaded_addons)}")
        if hasattr(ctx, 'log'):
            ctx.log.info(f"Controller loaded {count} script modules with {len(self.loaded_addons)} addons")

    def done(self):
        """
        Called when the script is unloaded. We need to remove the addons we loaded
        to prevent duplicates when the script is reloaded.
        """
        if self.loaded_addons:
            debug_log(f"Unloading {len(self.loaded_addons)} dynamic addons")
            for addon in self.loaded_addons:
                try:
                    ctx.master.addons.remove(addon)
                except Exception as e:
                    debug_log(f"Error removing addon: {e}")
            self.loaded_addons = []


addons = [MitmLoader()]