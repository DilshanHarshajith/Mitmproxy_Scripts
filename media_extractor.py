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
    --set media_out=./my_folder  # custom output directory — files are written
                                 # directly into images/ and videos/ with no
                                 # per-site sub-folders (flat layout)
    --set media_min_size=1024    # skip files smaller than N bytes (default: 512)
                                 # also accepts human-readable suffixes:
                                 #   512B  →  512 bytes
                                 #   10KB  →  10 240 bytes
                                 #   1MB   →  1 048 576 bytes
                                 #   0.5GB →  536 870 912 bytes

    --set media_domains=...      # domain filter with wildcard support (see below)

Domain filtering (media_domains):
    A comma-separated list of domain patterns.  When the option is empty (the
    default) every host is captured.  Patterns are matched case-insensitively
    against the request hostname (port is ignored).

    Wildcards follow Unix shell-glob rules via fnmatch:
        *   matches any sequence of characters within a label or across labels
        ?   matches exactly one character

    Prefix a pattern with ! to *exclude* that host even if another pattern
    would otherwise allow it.  Exclusions are evaluated first.

    Examples:
        # Only capture from one exact host
        --set media_domains=cdn.example.com

        # Capture all subdomains of example.com (but not bare example.com)
        --set media_domains="*.example.com"

        # Capture bare domain AND all its subdomains
        --set media_domains="example.com,*.example.com"

        # Multiple unrelated domains
        --set media_domains="*.example.com,static.other.net,img?.site.io"

        # Allow all of example.com but skip its ads subdomain
        --set media_domains="*.example.com,!ads.example.com"

        # Block a specific CDN across all traffic (allow everything else)
        --set media_domains="!tracking-cdn.net"

Usage examples:
    mitmproxy -s media_extractor.py
    mitmproxy -s media_extractor.py --set media_types=pics
    mitmproxy -s media_extractor.py --set media_ext=jpg,gif,webp,mp4
    mitmproxy -s media_extractor.py --set media_domains="*.example.com,!ads.example.com"
    mitmproxy -s script.py --set modules=media_extractor   # via loader
"""

import fnmatch
import hashlib
import mimetypes
import re
import struct
from collections import defaultdict
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
# Pre-compiled regexes (avoids repeated compilation on hot paths)
# ---------------------------------------------------------------------------
_RE_SAFE_NAME  = re.compile(r"[^\w\-.]")
_RE_SAFE_DIR   = re.compile(r"[^\w\-.]")
_RE_DIGITS     = re.compile(r"\d+")
_RE_SIZE_SUFFIX = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[KMGTP]I?B|B)?\s*$",
    re.IGNORECASE,
)

_SIZE_UNITS: dict[str, int] = {
    "b":   1,
    "kb":  1_024,
    "kib": 1_024,
    "mb":  1_024 ** 2,
    "mib": 1_024 ** 2,
    "gb":  1_024 ** 3,
    "gib": 1_024 ** 3,
    "tb":  1_024 ** 4,
    "tib": 1_024 ** 4,
    "pb":  1_024 ** 5,
    "pib": 1_024 ** 5,
}


def _parse_min_size(raw: str | int) -> int:
    """
    Convert a size value to bytes.

    Accepts:
      - plain int or str of digits → bytes directly
      - human-readable strings: "512B", "10KB", "1.5MB", "2GiB", …
        (case-insensitive; both SI-prefix "KB" and IEC "KiB" are treated as
        powers of 1024 for simplicity)

    Raises ValueError on unrecognisable input.
    """
    if isinstance(raw, int):
        return max(0, raw)

    raw = str(raw).strip()
    m = _RE_SIZE_SUFFIX.match(raw)
    if not m:
        raise ValueError(f"Cannot parse size value: {raw!r}")

    value = float(m.group("value"))
    unit  = (m.group("unit") or "b").lower()
    return int(value * _SIZE_UNITS[unit])

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


def _parse_domain_patterns(raw: str) -> tuple[list[str], list[str]]:
    """
    Parse a comma-separated domain pattern string into two lists:
      allow_patterns – plain patterns; if non-empty, a host must match at least one
      block_patterns – patterns prefixed with '!'; a matching host is always skipped

    Patterns are stored in lowercase; matching is case-insensitive.
    An empty *raw* string produces two empty lists (= capture everything).
    """
    allow_patterns: list[str] = []
    block_patterns: list[str] = []
    for token in raw.split(","):
        token = token.strip().lower()
        if not token:
            continue
        if token.startswith("!"):
            pat = token[1:].strip()
            if pat:
                block_patterns.append(pat)
        else:
            allow_patterns.append(token)
    return allow_patterns, block_patterns


def _host_from_flow(flow: http.HTTPFlow) -> str:
    """Return the bare lowercase hostname (no port) for a flow's request."""
    host = flow.request.host or ""
    # flow.request.host normally has no port, but guard anyway
    return host.split(":")[0].lower()


def _domain_is_allowed(
    host: str,
    allow_patterns: list[str],
    block_patterns: list[str],
) -> bool:
    """
    Return True if *host* passes the domain filter.

    Rules (evaluated in order):
      1. If *host* matches any block pattern  → False  (blocked)
      2. If allow_patterns is non-empty and *host* matches none → False  (not in allow list)
      3. Otherwise                            → True   (allowed)

    An empty allow_patterns + empty block_patterns means "allow everything".
    """
    for pat in block_patterns:
        if fnmatch.fnmatch(host, pat):
            return False
    if allow_patterns:
        return any(fnmatch.fnmatch(host, pat) for pat in allow_patterns)
    return True


# ---------------------------------------------------------------------------
# Video stream helpers
# ---------------------------------------------------------------------------

def _hls_stream_key(url: str) -> str:
    """
    Derive a stable key that groups all .ts segments belonging to the same
    HLS stream.  We strip the final path component (the segment filename)
    so that e.g.
        https://cdn.example.com/hls/stream1/seg001.ts
        https://cdn.example.com/hls/stream1/seg002.ts
    both map to  "cdn.example.com/hls/stream1".
    """
    parsed = urlparse(url)
    parent = str(Path(parsed.path).parent).lstrip("/")
    return f"{parsed.netloc}/{parent}"


def _segment_index(url: str) -> int:
    """
    Extract an integer index from a segment URL so segments can be sorted
    into the correct playback order even if they arrive out of order.

    Tries, in order:
      1. The last run of digits in the filename stem  (seg_0042.ts → 42)
      2. 0 as a fallback (preserves insertion order for non-numbered names)
    """
    stem = Path(urlparse(url).path).stem
    digits = _RE_DIGITS.findall(stem)
    return int(digits[-1]) if digits else 0


def _is_fmp4_init(data: bytes) -> bool:
    """
    Return True if *data* looks like an fMP4 initialisation segment.

    An init segment contains a 'moov' box but no 'mdat' box.
    Both box types are identified by their 4-byte type field at offset 4.
    We scan for box headers rather than assuming a fixed layout.
    """
    has_moov = False
    has_mdat = False
    offset = 0
    while offset + 8 <= len(data):
        try:
            box_size = struct.unpack_from(">I", data, offset)[0]
            box_type = data[offset + 4: offset + 8]
        except struct.error:
            break
        if box_type == b"moov":
            has_moov = True
        elif box_type == b"mdat":
            has_mdat = True
        if box_size < 8:
            break
        offset += box_size
    return has_moov and not has_mdat


def _is_fmp4_media_segment(data: bytes) -> bool:
    """
    Return True if *data* looks like an fMP4 media segment.

    A media segment contains 'moof' + 'mdat' boxes (no 'moov').
    """
    has_moof = False
    has_mdat = False
    has_moov = False
    offset = 0
    while offset + 8 <= len(data):
        try:
            box_size = struct.unpack_from(">I", data, offset)[0]
            box_type = data[offset + 4: offset + 8]
        except struct.error:
            break
        if box_type == b"moof":
            has_moof = True
        elif box_type == b"mdat":
            has_mdat = True
        elif box_type == b"moov":
            has_moov = True
        if box_size < 8:
            break
        offset += box_size
    return has_moof and has_mdat and not has_moov


# ---------------------------------------------------------------------------
# Core extraction logic
# ---------------------------------------------------------------------------

class MediaExtractor:
    """
    Examines every completed HTTP response and saves media files to disk.

    Directory layout — default (no media_out set):
        <output_dir>/
          <YYYY-MM-DD>/
            <host>/
              images/
                <filename>.ext
              videos/
                <filename>.ext

    Directory layout — user-specified output dir (media_out set, flat):
        <output_dir>/
          images/
            <filename>.ext          ← no per-site sub-folder
          videos/
            <filename>.ext
          hls_playlists/
            <playlist>.m3u8

    Video streaming formats
    -----------------------
    HLS (.m3u8 / .ts):
        Modern video is typically delivered via HTTP Live Streaming.  The
        .m3u8 playlist is a text manifest — not a video — and each .ts file
        is only a short segment (~2–10 s).  Saving them individually produces
        unplayable fragments.

        Fix: .ts segments are buffered per-stream (keyed by host + URL
        directory) and written out as a single concatenated .ts file once the
        stream is flushed.  Call flush_streams() at the end of a capture
        session to finalise any in-progress streams.  .m3u8 files are saved
        as metadata only (not in the videos/ folder) so they don't appear as
        broken video files.

    Fragmented MP4 (fMP4 / CMAF / DASH):
        Many MP4 streams split video into an initialisation segment (contains
        codec/track metadata, no media data) and media segments (contain
        frames but no codec metadata).  Playing a media segment without its
        init segment yields a blank/unplayable file.

        Fix: init segments are detected via ISO BMFF box scanning and cached
        per host.  When a media segment arrives its init data is prepended
        before writing, producing a self-contained, playable MP4.
    """

    def __init__(
        self,
        allowed_extensions: frozenset[str],
        output_dir: Path,
        min_size: int,
        allow_domains: list[str] | None = None,
        block_domains: list[str] | None = None,
        custom_output: bool = False,
    ) -> None:
        self.allowed_extensions = allowed_extensions
        self.output_dir = output_dir
        self.min_size = min_size
        self.allow_domains: list[str] = allow_domains or []
        self.block_domains: list[str] = block_domains or []
        self.custom_output = custom_output
        self._seen_hashes: set[str] = set()   # dedup within a session

        # HLS segment accumulation: stream_key → list of (index, url, data)
        self._hls_streams: dict[str, list[tuple[int, str, bytes]]] = defaultdict(list)
        # HLS stream metadata: stream_key → (flow_snapshot, category)
        self._hls_meta: dict[str, tuple] = {}

        # fMP4 init segment cache: host → init_bytes
        self._fmp4_init: dict[str, bytes] = {}

        output_dir.mkdir(parents=True, exist_ok=True)

        domain_summary = (
            f"allow={self.allow_domains or '*'}, block={self.block_domains or 'none'}"
        )
        _debug_log(
            f"MediaExtractor ready — extensions={sorted(allowed_extensions)}, "
            f"out={output_dir}, min_size={min_size}B, domains=({domain_summary})"
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def handle_response(self, flow: http.HTTPFlow) -> None:
        """Called for every HTTP response; saves qualifying media."""
        resp = flow.response
        if not resp or not resp.content:
            return

        # ── Domain filter ────────────────────────────────────────────────
        host = _host_from_flow(flow)
        if not _domain_is_allowed(host, self.allow_domains, self.block_domains):
            _debug_log(f"Domain filtered: {host}")
            return
        # ─────────────────────────────────────────────────────────────────

        content_type = resp.headers.get("content-type", "").lower().split(";")[0].strip()
        url = flow.request.pretty_url

        ext, category = self._resolve_ext_and_category(url, content_type)
        if ext is None or ext not in self.allowed_extensions:
            return  # not a media type we care about

        # Size check before copying the body into a local variable
        content_length = len(resp.content)
        if content_length < self.min_size:
            _debug_log(f"Skipping {url} — body too small ({content_length}B < {self.min_size}B)")
            return

        body = resp.content  # single reference; no extra copy

        # ── HLS playlist (.m3u8) ─────────────────────────────────────────
        if ext == "m3u8":
            self._save_m3u8(flow, url, body)
            return

        # ── HLS transport-stream segment (.ts) ───────────────────────────
        if ext == "ts":
            self._buffer_ts_segment(flow, url, body, category)
            return

        # ── Fragmented MP4 init segment ───────────────────────────────────
        if ext in ("mp4", "m4v") and _is_fmp4_init(body):
            self._fmp4_init[host] = body
            _debug_log(f"Cached fMP4 init segment from {host} ({len(body):,}B)")
            return

        # ── Fragmented MP4 media segment ──────────────────────────────────
        if ext in ("mp4", "m4v") and _is_fmp4_media_segment(body):
            init = self._fmp4_init.get(host)
            if init:
                body = init + body
                _debug_log(f"Prepended fMP4 init to media segment from {host}")
            else:
                _debug_log(
                    f"fMP4 media segment from {host} has no cached init — "
                    "file may be unplayable. Init segment may not have been intercepted yet."
                )

        # ── Regular / non-streaming media ────────────────────────────────
        # Compute hash once; reuse for both dedup check and filename suffix.
        digest = hashlib.md5(body, usedforsecurity=False).hexdigest()
        if digest in self._seen_hashes:
            _debug_log(f"Duplicate skipped: {url}")
            return
        self._seen_hashes.add(digest)

        dest = self._build_dest_path(flow, url, ext, category, digest)
        self._atomic_write(dest, body)

        client_ip = _get_client_ip(flow)
        _debug_log(f"Saved {category}/{ext} from {client_ip} → {dest.name} ({len(body):,}B)")

    def flush_streams(self) -> None:
        """
        Concatenate and write out all buffered HLS streams.

        Call this at the end of a capture session (e.g. from the addon's
        `done` hook) to ensure partially-captured streams are flushed to disk.
        """
        for key, segments in list(self._hls_streams.items()):
            self._flush_hls_stream(key, segments)
        self._hls_streams.clear()
        self._hls_meta.clear()

    # ------------------------------------------------------------------
    # HLS helpers
    # ------------------------------------------------------------------

    def _save_m3u8(self, flow: http.HTTPFlow, url: str, body: bytes) -> None:
        """Save an HLS playlist as a text sidecar (not in the videos/ folder)."""
        if self.custom_output:
            folder = self.output_dir / "hls_playlists"
        else:
            host  = _safe_dirname(flow.request.host)
            today = datetime.now().strftime("%Y-%m-%d")
            folder = self.output_dir / today / host / "hls_playlists"
        folder.mkdir(parents=True, exist_ok=True)

        raw_name  = Path(urlparse(url).path).stem
        safe_name = _RE_SAFE_NAME.sub("_", raw_name)[:80] or "playlist"
        dest = folder / f"{safe_name}.m3u8"
        if dest.exists():
            digest = hashlib.md5(body, usedforsecurity=False).hexdigest()
            dest = folder / f"{safe_name}_{digest[:8]}.m3u8"

        self._atomic_write(dest, body)
        _debug_log(f"Saved HLS playlist → {dest.name}")

    def _buffer_ts_segment(
        self,
        flow: http.HTTPFlow,
        url: str,
        body: bytes,
        category: str,
    ) -> None:
        """
        Buffer a .ts segment for later concatenation.

        Segments are grouped by stream key (host + URL directory) so that
        segments from different streams don't get mixed together.
        """
        key = _hls_stream_key(url)
        idx = _segment_index(url)
        self._hls_streams[key].append((idx, url, body))

        # Store flow metadata the first time we see this stream
        if key not in self._hls_meta:
            self._hls_meta[key] = (flow, category)

        _debug_log(
            f"Buffered HLS segment #{idx} for stream '{key}' "
            f"({len(body):,}B, total {len(self._hls_streams[key])} segments)"
        )

    def _flush_hls_stream(
        self,
        key: str,
        segments: list[tuple[int, str, bytes]],
    ) -> None:
        """Sort and concatenate all buffered segments for one stream, then write."""
        if not segments:
            return

        meta = self._hls_meta.get(key)
        if meta is None:
            _debug_log(f"No metadata for HLS stream '{key}' — skipping flush")
            return

        flow, category = meta

        # Sort by the numeric index embedded in each segment's URL
        segments.sort(key=lambda t: t[0])
        combined = b"".join(data for _, _, data in segments)

        # Use the URL of the first segment to derive an output filename
        first_url = segments[0][1]
        digest = hashlib.md5(combined, usedforsecurity=False).hexdigest()

        if digest in self._seen_hashes:
            _debug_log(f"HLS stream '{key}' already saved — skipping")
            return
        self._seen_hashes.add(digest)

        dest = self._build_dest_path(flow, first_url, "ts", category, digest)
        # Rename to reflect that this is the merged stream
        stem = dest.stem
        dest = dest.with_name(f"{stem}_merged.ts")

        self._atomic_write(dest, combined)
        client_ip = _get_client_ip(flow)
        _debug_log(
            f"Flushed HLS stream '{key}': {len(segments)} segments → "
            f"{dest.name} ({len(combined):,}B) from {client_ip}"
        )

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
        """Compute the destination file path, avoiding name collisions.

        Layout when *media_out* is provided (flat — no per-site folder):
            <output_dir>/<category>/<filename>.ext

        Default layout (no *media_out*):
            <output_dir>/<YYYY-MM-DD>/<host>/<category>/<filename>.ext
        """
        if self.custom_output:
            # Flat layout: group only by media category, not by site
            folder = self.output_dir / category
        else:
            host  = _safe_dirname(flow.request.host)
            today = datetime.now().strftime("%Y-%m-%d")
            folder = self.output_dir / today / host / category
        folder.mkdir(parents=True, exist_ok=True)

        # Try to use the original filename from the URL
        raw_name  = Path(urlparse(url).path).stem
        safe_name = _RE_SAFE_NAME.sub("_", raw_name)[:80] or "media"
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
    return _RE_SAFE_DIR.sub("_", name)[:100] or "unknown_host"


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
            name="media_domains",
            typespec=str,
            default="",
            help=(
                "Comma-separated domain patterns to filter captures. "
                "Empty (default) = capture from every host. "
                "Supports fnmatch wildcards (* and ?). "
                "Prefix a pattern with ! to block that host. "
                "Block patterns are evaluated before allow patterns. "
                "Example: '*.example.com,!ads.example.com'"
            ),
        )
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
            typespec=str,
            default="512",
            help=(
                "Minimum response body size to save. "
                "Accepts plain bytes or human-readable suffixes: "
                "512B, 10KB, 1.5MB, 2GiB … (default: 512)."
            ),
        )

    def running(self) -> None:
        self._build_extractor()

    def configure(self, updated) -> None:
        # Rebuild whenever any of our options change
        if updated & {"media_types", "media_ext", "media_out", "media_min_size", "media_domains"}:
            self._build_extractor()

    def response(self, flow: http.HTTPFlow) -> None:
        if self._extractor:
            try:
                self._extractor.handle_response(flow)
            except Exception as exc:
                _debug_log(f"Unhandled error in response hook: {exc}")

    def done(self) -> None:
        """Flush any buffered HLS streams when mitmproxy shuts down."""
        if self._extractor:
            try:
                self._extractor.flush_streams()
            except Exception as exc:
                _debug_log(f"Error flushing HLS streams on done: {exc}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_extractor(self) -> None:
        try:
            media_types   = ctx.options.media_types
            media_ext     = ctx.options.media_ext
            media_out     = ctx.options.media_out
            media_domains = ctx.options.media_domains
        except AttributeError:
            # Called before options are available (e.g. during unit tests)
            return

        allowed = _resolve_allowed_extensions(media_types, media_ext)
        out_dir = Path(media_out).expanduser() if media_out else MEDIA_DIR
        allow_domains, block_domains = _parse_domain_patterns(media_domains)

        try:
            min_size = _parse_min_size(ctx.options.media_min_size)
        except ValueError as exc:
            _debug_log(f"Invalid media_min_size value — falling back to 512B: {exc}")
            min_size = 512

        self._extractor = MediaExtractor(
            allowed_extensions=allowed,
            output_dir=out_dir,
            min_size=min_size,
            allow_domains=allow_domains,
            block_domains=block_domains,
            custom_output=bool(media_out),
        )


# ---------------------------------------------------------------------------
# Addon registration  (required by mitmproxy and the script.py loader)
# ---------------------------------------------------------------------------
addons = [MediaExtractorAddon()]