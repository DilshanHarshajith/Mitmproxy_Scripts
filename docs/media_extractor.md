# `media_extractor.py` — Media Extractor

Intercepts HTTP responses and saves image and video files to disk. Supports filtering by media category, file extension, minimum size, and domain — including wildcard and block patterns. Deduplicates captures within a session by content hash.

## How it works

On every completed response, the extractor checks the URL path extension and `Content-Type` header to classify the file. If it passes the active filters it is written atomically to the output folder. Files with identical content (same MD5 digest) are silently skipped for the remainder of the session.

## Output layout

The folder structure depends on whether `media_out` is set.

**Default** (no `media_out`):
```
Mitmproxy_Outputs/Media/
└── YYYY-MM-DD/
    └── <hostname>/
        ├── images/
        │   └── <filename>.ext
        ├── videos/
        │   └── <filename>.ext
        └── hls_playlists/
            └── <playlist>.m3u8
```

**User-specified output dir** (`--set media_out=<path>`):
```
<path>/
├── images/
│   └── <hostname>/
│       └── <filename>.ext
├── videos/
│   └── <hostname>/
│       └── <filename>.ext
└── hls_playlists/
    └── <hostname>/
        └── <playlist>.m3u8
```

Original filenames from the URL are preserved where possible. If a name collision is detected the first eight characters of the content hash are appended.

## Supported formats

**Images** — `jpg`, `jpeg`, `png`, `gif`, `webp`, `bmp`, `tiff`, `tif`, `svg`, `ico`, `avif`, `heic`, `heif`

**Videos** — `mp4`, `m4v`, `mkv`, `webm`, `avi`, `mov`, `wmv`, `flv`, `ts`, `mpg`, `mpeg`, `3gp`, `ogv`

> **Note:** `.m3u8` playlists are saved to `hls_playlists/` rather than `videos/` — see [Video streaming formats](#video-streaming-formats) below.

## Options

| Option | Default | Description |
|---|---|---|
| `media_types` | `all` | `all`, `pics` (images only), or `vids` (videos only). Ignored when `media_ext` is set. |
| `media_ext` | _(empty)_ | Comma-separated list of extensions, e.g. `jpg,png,mp4`. Overrides `media_types`. |
| `media_out` | `./Mitmproxy_Outputs/Media` | Output directory. Also switches to the flat `images/<host>/` / `videos/<host>/` layout. |
| `media_min_size` | `512` | Minimum response body size in bytes. Smaller files are skipped. |
| `media_domains` | _(empty)_ | Domain filter (see below). Empty = capture from all hosts. |

## Domain filtering (`media_domains`)

A comma-separated list of hostname patterns matched case-insensitively against the request host (port ignored). Uses shell-glob wildcards via Python's `fnmatch`: `*` matches any sequence of characters, `?` matches exactly one character.

Prefix a pattern with `!` to make it a **block pattern**. Block patterns are evaluated first and always win.

**Evaluation order:**
1. If the host matches any `!` block pattern → **skip**
2. If allow patterns are present and none match → **skip**
3. Otherwise → **capture**

### Pattern examples

| `media_domains` value | Captures from |
|---|---|
| _(empty)_ | Every host |
| `cdn.example.com` | That exact host only |
| `*.example.com` | Any subdomain of example.com (bare domain excluded) |
| `example.com,*.example.com` | Bare domain and all subdomains |
| `*.example.com,!ads.example.com` | All subdomains except the ads host |
| `!tracking-cdn.net` | Every host except tracking-cdn.net |
| `*.example.com,static.other.net` | Two unrelated domain families |

## Video streaming formats

Modern video is rarely delivered as a single file. The extractor handles the two most common streaming formats automatically.

### HLS (`.m3u8` / `.ts`)

An HLS stream consists of a text playlist (`.m3u8`) that references dozens of short transport-stream segments (`.ts`, typically 2–10 seconds each). Saving them individually produces unplayable fragments.

**What the extractor does:**
- `.ts` segments are buffered in memory, grouped by stream (host + URL directory).
- When the capture session ends, segments for each stream are sorted by the sequence number in their filename and concatenated into a single `<name>_merged.ts` file.
- `.m3u8` playlists are saved as text sidecars in `hls_playlists/` — not in `videos/` — so they are not mistaken for playable video files.

### Fragmented MP4 (fMP4 / CMAF / DASH)

Many MP4 streams split video into an initialisation segment (codec and track metadata, no media data) followed by media segments (frames, but no codec metadata). A media segment played without its init segment produces a blank or unplayable file.

**What the extractor does:**
- Init segments are identified by scanning ISO BMFF box headers (`moov` present, `mdat` absent) and cached per host.
- When a media segment arrives (`moof` + `mdat`, no `moov`), the cached init data is prepended before writing, producing a self-contained playable MP4.
- If a media segment arrives before its init segment has been intercepted, the file is still saved and a warning is written to the debug log.

## Usage

```bash
# via the loader
mitmdump -s script.py --set modules=media_extractor

# standalone — capture everything
mitmproxy -s media_extractor.py

# images only
mitmproxy -s media_extractor.py --set media_types=pics

# specific extensions
mitmproxy -s media_extractor.py --set media_ext=jpg,gif,webp,mp4

# custom output directory (uses flat images/<host>/ / videos/<host>/ layout)
mitmproxy -s media_extractor.py --set media_out=~/captures

# one domain family, excluding its ads subdomain
mitmproxy -s media_extractor.py \
  --set media_domains="*.example.com,!ads.example.com"

# combine filters
mitmproxy -s media_extractor.py \
  --set media_types=pics \
  --set media_domains="cdn.example.com" \
  --set media_min_size=2048
```

## Notes

- Files are written atomically via a `.tmp` rename — a crash mid-write will not produce a corrupt file.
- HLS segment buffers and the fMP4 init cache are in-memory only and reset when mitmproxy restarts.
- The deduplication hash set is also in-memory only; it resets on restart.
- All filter checks happen before any I/O, so skipped traffic has negligible overhead.
- See `Mitmproxy_Outputs/Other/debug.log` for a timestamped log of every save and every skip with its reason.