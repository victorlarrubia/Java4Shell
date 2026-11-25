#!/usr/bin/env python3
# language: Python 3.10+, file: java4shell_mass_scan.py, target: CVE-2026-114938
# Mass scanner — reads a list of targets from a file and fans them out in parallel.
# Wraps java4shell_scanner.py logic directly (no subprocess).

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from java4shell_scanner import (
    malformed_b64_padding, build_requests, get_baseline,
    send_request, print_result, print_summary, save_json_report,
    ScanResult, BOLD, RESET
)
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


def scan_target(target: str, timeout: float, payload_size: int, threads: int, verbose: bool) -> list[ScanResult]:
    target = target.strip()
    if not target or target.startswith("#"):
        return []

    if not target.startswith("http"):
        target = "https://" + target

    baseline = get_baseline(target, timeout)
    payloads = malformed_b64_padding(payload_size)
    requests_list = build_requests(target, payloads)

    results: list[ScanResult] = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(send_request, req, timeout, baseline): req for req in requests_list}
        for future in as_completed(futures):
            r = future.result()
            with lock:
                results.append(r)
                if r.vulnerable:
                    print_result(r, verbose=verbose)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Java4Shell mass scanner — scans a list of targets from a file",
    )
    parser.add_argument("targets_file", help="File with one target URL per line")
    parser.add_argument("--target-threads", type=int, default=10, help="Parallel targets (default: 10)")
    parser.add_argument("--req-threads", type=int, default=5, help="Requests per target (default: 5)")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", help="JSON report output path")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--payload-size", type=int, default=60)
    args = parser.parse_args()

    with open(args.targets_file, encoding="utf-8") as f:
        targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    print(f"\n{BOLD}  Java4Shell Mass Scanner — CVE-2026-114938{RESET}")
    print(f"  Targets loaded: {len(targets)}")
    print(f"  Target threads: {args.target_threads}  |  Req threads: {args.req_threads}\n")

    all_results: list[ScanResult] = []
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=args.target_threads) as pool:
        futures = {
            pool.submit(scan_target, t, args.timeout, args.payload_size, args.req_threads, args.verbose): t
            for t in targets
        }
        for future in as_completed(futures):
            target = futures[future]
            results = future.result()
            with lock:
                all_results.extend(results)
                vulns = [r for r in results if r.vulnerable]
                if vulns:
                    print(f"  \033[91m[HIT]\033[0m {target}  —  {len(vulns)} vulnerable surface(s)")
                else:
                    print(f"  \033[90m[   ]\033[0m {target}")

    print_summary(all_results)

    if args.output:
        save_json_report(all_results, args.output)


if __name__ == "__main__":
    main()
