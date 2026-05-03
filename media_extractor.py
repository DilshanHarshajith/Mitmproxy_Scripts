#!/usr/bin/env python3
"""
Media Extractor - Mitmproxy Addon

Intercepts HTTP responses and saves image and video files to disk.

By default, captures ALL images and videos found in traffic.
Use mitmproxy's --set flag to narrow the scope:

    --set media_types=pics       # images only
    --set media_types=vids       # videos only
    --set media_types=all        # both (default)
    --set media_ext=jpg,png,mp4  # specific extensions (overrides media_types)
    --set media_out=./my_folder  # custom output directory
    --set media_min_size=1024    # skip files smaller than N bytes (default: 512)

Usage examples:
    mitmproxy -s media_extractor.py
    mitmproxy -s media_extractor.py --set media_types=pics
    mitmproxy -s media_extractor.py --set media_ext=jpg,gif,webp,mp4
    mitmproxy -s script.py --set modules=media_extractor   # via loader
"""

import hashlib
import mimetypes
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from mitmproxy import ctx, http

# ---------------------------------------------------------------------------
# Config import (mirrors the pattern used by other scripts in this repo)
# ---------------------------------------------------------------------------
try:
    from config import OUT_DIR, DEBUG_LOG
except ImportError:
    OUT_DIR   = Path.cwd() / "Mitmproxy_Outputs"
    DEBUG_LOG = OUT_DIR / "Other" / "debug.log"

MEDIA_DIR = OUT_DIR / "Media"

# ---------------------------------------------------------------------------
# Extension sets
# ---------------------------------------------------------------------------
IMAGE_EXTENSIONS: frozenset[str] = frozenset({
    "jpg", "jpeg", "png", "gif", "webp", "bmp",
    "tiff", "tif", "svg", "ico", "avif", "heic", "heif",
})

VIDEO_EXTENSIONS: frozenset[str] = frozenset({
    "mp4", "m4v", "mkv", "webm", "avi", "mov", "wmv",
    "flv", "ts", "m3u8", "mpg", "mpeg", "3gp", "ogv",
})

# Content-Type prefix → human-readable category folder name
MIME_CATEGORY: dict[str, str] = {
    "image/": "images",
    "video/": "videos",
}

# Map MIME type → typical file extension (fallback when URL has none)
MIME_TO_EXT: dict[str, str] = {
    "image/jpeg":     "jpg",
    "image/png":      "png",
    "image/gif":      "gif",
    "image/webp":     "webp",
    "image/bmp":      "bmp",
    "image/svg+xml":  "svg",
    "image/tiff":     "tiff",
    "image/avif":     "avif",
    "image/heic":     "heic",
    "video/mp4":      "mp4",
    "video/webm":     "webm",
    "video/ogg":      "ogv",
    "video/quicktime":"mov",
    "video/x-msvideo":"avi",
    "video/x-flv":    "flv",
    "video/mpeg":     "mpg",
    "video/mp2t":     "ts",
    "video/3gpp":     "3gp",
    "application/x-mpegurl":          "m3u8",
    "application/vnd.apple.mpegurl":  "m3u8",
}

# ---------------------------------------------------------------------------
# Shared helpers  (same pattern as token_extractor / har_capture)
# ---------------------------------------------------------------------------

def _normalize_ip(ip: str) -> str:
    """Normalize an IP address string into a safe filesystem token."""
    if not ip:
        return "unknown"
    return ip.replace(":", "_").replace("[", "").replace("]", "")


def _get_client_ip(flow: http.HTTPFlow) -> str:
    """Extract the originating client IP with the standard fallback chain."""
    if not flow or not flow.client_conn:
        return "unknown"

    if flow.request:
        for header in ("X-Real-IP", "X-Forwarded-For"):
            value = flow.request.headers.get(header)
            if value:
                return _normalize_ip(value.split(",")[0].strip())

    if flow.client_conn.peername:
        return _normalize_ip(flow.client_conn.peername[0])

    return "unknown"


def _debug_log(message: str) -> None:
    """Append a timestamped message to the shared debug log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [media_extractor] {message}"
    try:
        DEBUG_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_LOG, "a") as fh:
            fh.write(entry + "\n")
    except Exception:
        pass
    try:
        if hasattr(ctx, "log") and ctx.log:
            ctx.log.info(f"[media_extractor] {message}")
    except (AttributeError, NameError):
        pass


# ---------------------------------------------------------------------------
# Core extraction logic
# ---------------------------------------------------------------------------

class MediaExtractor:
    """
    Examines every completed HTTP response and saves media files to disk.

    Directory layout:
        <output_dir>/
          <YYYY-MM-DD>/
            <host>/
              images/
                <filename_or_hash>.ext
              videos/
                <filename_or_hash>.ext
    """

    def __init__(
        self,
        allowed_extensions: frozenset[str],
        output_dir: Path,
        min_size: int,
    ) -> None:
        self.allowed_extensions = allowed_extensions
        self.output_dir = output_dir
        self.min_size = min_size
        self._seen_hashes: set[str] = set()   # dedup within a session
        output_dir.mkdir(parents=True, exist_ok=True)
        _debug_log(
            f"MediaExtractor ready — extensions={sorted(allowed_extensions)}, "
            f"out={output_dir}, min_size={min_size}B"
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def handle_response(self, flow: http.HTTPFlow) -> None:
        """Called for every HTTP response; saves qualifying media."""
        if not flow.response or not flow.response.content:
            return

        content_type = flow.response.headers.get("content-type", "").lower().split(";")[0].strip()
        url = flow.request.pretty_url

        ext, category = self._resolve_ext_and_category(url, content_type)
        if ext is None:
            return  # not a media type we care about

        if ext not in self.allowed_extensions:
            return

        body = flow.response.content
        if len(body) < self.min_size:
            _debug_log(f"Skipping {url} — body too small ({len(body)}B)")
            return

        # Deduplicate by content hash
        digest = hashlib.md5(body, usedforsecurity=False).hexdigest()
        if digest in self._seen_hashes:
            _debug_log(f"Duplicate skipped: {url}")
            return
        self._seen_hashes.add(digest)

        dest = self._build_dest_path(flow, url, ext, category, digest)
        self._atomic_write(dest, body)

        client_ip = _get_client_ip(flow)
        _debug_log(f"Saved {category}/{ext} from {client_ip} → {dest.name} ({len(body):,}B)")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_ext_and_category(
        self, url: str, content_type: str
    ) -> tuple[str | None, str | None]:
        """
        Return (extension, category) for a response, or (None, None) to skip.
        Detection order: URL path extension → Content-Type header → skip.
        """
        # 1. Try URL path first
        path_ext = _ext_from_url(url)
        if path_ext:
            cat = _category_for_ext(path_ext)
            if cat:
                return path_ext, cat

        # 2. Fall back to Content-Type header
        if content_type:
            for prefix, cat in MIME_CATEGORY.items():
                if content_type.startswith(prefix):
                    ext = MIME_TO_EXT.get(content_type) or _ext_from_mime(content_type)
                    return (ext or "bin"), cat

        return None, None

    def _build_dest_path(
        self,
        flow: http.HTTPFlow,
        url: str,
        ext: str,
        category: str,
        digest: str,
    ) -> Path:
        """Compute the destination file path, avoiding name collisions."""
        today = datetime.now().strftime("%Y-%m-%d")
        host = _safe_dirname(flow.request.host)
        folder = self.output_dir / today / host / category
        folder.mkdir(parents=True, exist_ok=True)

        # Try to use the original filename from the URL
        raw_name = Path(urlparse(url).path).stem
        safe_name = re.sub(r"[^\w\-.]", "_", raw_name)[:80] or "media"
        candidate = folder / f"{safe_name}.{ext}"

        # If the name is already taken (different content), append part of the hash
        if candidate.exists():
            candidate = folder / f"{safe_name}_{digest[:8]}.{ext}"

        return candidate

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        """Write *data* to *path* atomically via a temp file."""
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_bytes(data)
            tmp.replace(path)
        except Exception as exc:
            _debug_log(f"Write error for {path}: {exc}")
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Pure helper functions
# ---------------------------------------------------------------------------

def _ext_from_url(url: str) -> str | None:
    """Extract a lowercase file extension from a URL path, without the dot."""
    try:
        path = urlparse(url).path
        ext = Path(path).suffix.lstrip(".").lower()
        return ext if ext else None
    except Exception:
        return None


def _ext_from_mime(mime: str) -> str | None:
    """Guess an extension from a MIME type using the stdlib."""
    ext = mimetypes.guess_extension(mime)
    return ext.lstrip(".") if ext else None


def _category_for_ext(ext: str) -> str | None:
    """Return 'images', 'videos', or None for a given extension."""
    if ext in IMAGE_EXTENSIONS:
        return "images"
    if ext in VIDEO_EXTENSIONS:
        return "videos"
    return None


def _safe_dirname(name: str) -> str:
    """Sanitise a hostname so it can be used as a directory name."""
    return re.sub(r"[^\w\-.]", "_", name)[:100] or "unknown_host"


def _parse_ext_arg(raw: str) -> frozenset[str]:
    """Parse a comma-separated extension list into a frozenset."""
    return frozenset(e.strip().lower().lstrip(".") for e in raw.split(",") if e.strip())


def _resolve_allowed_extensions(
    media_types: str,
    media_ext: str,
) -> frozenset[str]:
    """
    Determine which extensions to capture based on option values.

    Priority:
      1. --set media_ext=...  (explicit list, highest priority)
      2. --set media_types=pics|vids|all
      3. default → all images + all videos
    """
    if media_ext:
        return _parse_ext_arg(media_ext)

    mt = media_types.strip().lower()
    if mt == "pics":
        return IMAGE_EXTENSIONS
    if mt == "vids":
        return VIDEO_EXTENSIONS
    # "all" or anything unrecognised → everything
    return IMAGE_EXTENSIONS | VIDEO_EXTENSIONS


# ---------------------------------------------------------------------------
# Mitmproxy Addon class
# ---------------------------------------------------------------------------

class MediaExtractorAddon:
    """Mitmproxy addon that wires option parsing to MediaExtractor."""

    def __init__(self) -> None:
        self._extractor: MediaExtractor | None = None

    # ------------------------------------------------------------------
    # Mitmproxy lifecycle hooks
    # ------------------------------------------------------------------

    def load(self, loader) -> None:
        loader.add_option(
            name="media_types",
            typespec=str,
            default="all",
            help=(
                "Which media category to capture: "
                "'all' (default), 'pics' (images only), 'vids' (videos only). "
                "Ignored when media_ext is set."
            ),
        )
        loader.add_option(
            name="media_ext",
            typespec=str,
            default="",
            help=(
                "Comma-separated list of file extensions to capture, e.g. "
                "'jpg,png,mp4'. Overrides media_types when non-empty."
            ),
        )
        loader.add_option(
            name="media_out",
            typespec=str,
            default="",
            help=(
                "Output directory for captured media. "
                "Defaults to <cwd>/Mitmproxy_Outputs/Media."
            ),
        )
        loader.add_option(
            name="media_min_size",
            typespec=int,
            default=512,
            help="Minimum response body size in bytes to save (default: 512).",
        )

    def running(self) -> None:
        self._build_extractor()

    def configure(self, updated) -> None:
        # Rebuild whenever any of our options change
        if updated & {"media_types", "media_ext", "media_out", "media_min_size"}:
            self._build_extractor()

    def response(self, flow: http.HTTPFlow) -> None:
        if self._extractor:
            try:
                self._extractor.handle_response(flow)
            except Exception as exc:
                _debug_log(f"Unhandled error in response hook: {exc}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_extractor(self) -> None:
        try:
            media_types = ctx.options.media_types
            media_ext   = ctx.options.media_ext
            media_out   = ctx.options.media_out
            min_size    = ctx.options.media_min_size
        except AttributeError:
            # Called before options are available (e.g. during unit tests)
            return

        allowed = _resolve_allowed_extensions(media_types, media_ext)
        out_dir = Path(media_out).expanduser() if media_out else MEDIA_DIR

        self._extractor = MediaExtractor(
            allowed_extensions=allowed,
            output_dir=out_dir,
            min_size=min_size,
        )


# ---------------------------------------------------------------------------
# Addon registration  (required by mitmproxy and the script.py loader)
# ---------------------------------------------------------------------------
addons = [MediaExtractorAddon()]
