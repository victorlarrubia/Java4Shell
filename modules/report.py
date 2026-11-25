# language: Python 3.10+, file: modules/report.py
# Structured report output for Java4Shell (CVE-2026-114938).
# Generates: Markdown (pentest-ready) and JUnit XML (CI/CD pipeline integration).
#
# Usage:
#   from modules.report import save_markdown_report, save_junit_xml_report
#   save_markdown_report(scan_results, "report.md", target="https://target.com")
#   save_junit_xml_report(scan_results, "report.xml", target="https://target.com")

import html
import json
import time
from dataclasses import dataclass, field
from typing import Optional


# ─── Shared report data model ─────────────────────────────────────────────────

@dataclass
class ReportFinding:
    target: str
    surface: str
    confidence: str             # none | low | medium | high
    vulnerable: bool
    payload_preview: str = ""
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None
    response_snippet: str = ""


@dataclass
class ReportMeta:
    cve: str = "CVE-2026-114938"
    tool: str = "Java4Shell"
    target: str = ""
    timestamp: str = ""
    total_probes: int = 0
    vulnerable_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


# ─── Markdown report ──────────────────────────────────────────────────────────

def save_markdown_report(
    findings: list[ReportFinding],
    output_path: str,
    meta: Optional[ReportMeta] = None,
) -> None:
    """
    Write a pentest-ready Markdown report to output_path.

    Sections:
      1. Executive Summary
      2. Vulnerability Details (per surface)
      3. Evidence table
      4. Remediation
    """
    if meta is None:
        meta = ReportMeta()
        meta.timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        meta.total_probes = len(findings)
        meta.vulnerable_count = sum(1 for f in findings if f.vulnerable)
        meta.high_count   = sum(1 for f in findings if f.vulnerable and f.confidence == "high")
        meta.medium_count = sum(1 for f in findings if f.vulnerable and f.confidence == "medium")
        meta.low_count    = sum(1 for f in findings if f.vulnerable and f.confidence == "low")

    vulns = [f for f in findings if f.vulnerable]
    unique_targets = sorted(set(f.target for f in findings))
    unique_vulns   = sorted(set((f.target, f.surface) for f in vulns))

    lines = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        f"# Java4Shell Vulnerability Report",
        f"",
        f"| Field           | Value |",
        f"|-----------------|-------|",
        f"| **CVE**         | {meta.cve} |",
        f"| **Tool**        | {meta.tool} |",
        f"| **Generated**   | {meta.timestamp} |",
        f"| **Target(s)**   | {meta.target or ', '.join(unique_targets[:5])} |",
        f"",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    risk_level = "CRITICAL" if meta.high_count > 0 else ("HIGH" if meta.medium_count > 0 else ("MEDIUM" if meta.low_count > 0 else "INFORMATIONAL"))
    lines += [
        f"## Executive Summary",
        f"",
        f"**Overall Risk: {risk_level}**",
        f"",
        f"The target was scanned for **{meta.cve} (Java4Shell)** — a heap buffer overflow in the",
        f"HotSpot JVM `java.util.Base64.Decoder.decode0()` AVX-512 VBMI intrinsic. A malformed",
        f"Base64 payload causes an integer underflow that writes ~63 bytes past the output buffer,",
        f"enabling heap type confusion and arbitrary read/write primitives.",
        f"",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total probes sent | {meta.total_probes} |",
        f"| Vulnerable surfaces detected | {meta.vulnerable_count} |",
        f"| High confidence | {meta.high_count} |",
        f"| Medium confidence | {meta.medium_count} |",
        f"| Low confidence | {meta.low_count} |",
        f"| Targets tested | {len(unique_targets)} |",
        f"",
    ]

    if not vulns:
        lines += [
            f"> **No vulnerable surfaces detected.** A negative result does not confirm patch status.",
            f"> Verify JDK version ≥ 17 and CPU AVX-512 VBMI support independently.",
            f"",
        ]
    else:
        lines += [
            f"> **Vulnerable surfaces detected.** Immediate remediation required.",
            f"",
        ]

    # ── Vulnerability Details ─────────────────────────────────────────────────
    lines += [
        f"## Vulnerability Details",
        f"",
        f"**{meta.cve} — Java4Shell (Heap OOB Write via AVX-512 VBMI Base64 Intrinsic)**",
        f"",
        f"- **CVSS v4.0:** 9.2 Critical  ",
        f"- **CWE:** CWE-122 (Heap-based Buffer Overflow)  ",
        f"- **Component:** `java.util.Base64.Decoder.decode0()` HotSpot intrinsic  ",
        f"- **Affected CPUs:** x86_64 with AVX-512 VBMI (Intel Skylake-X+, Ice Lake+)  ",
        f"- **Affected JDK:** OpenJDK / Oracle JDK 17.x, 21.x, 25.x, 27.x (pre-patch)  ",
        f"- **References:**  ",
        f"  - https://calif.io/java4shell/  ",
        f"  - https://github.com/scadastrangelove/java4shell  ",
        f"",
    ]

    # ── Findings table ────────────────────────────────────────────────────────
    if vulns:
        lines += [
            f"## Findings",
            f"",
            f"| Target | Surface | Confidence | HTTP | Notes |",
            f"|--------|---------|-----------|------|-------|",
        ]
        seen = set()
        for f in vulns:
            key = (f.target, f.surface)
            if key in seen:
                continue
            seen.add(key)
            notes_short = " / ".join(f.notes[:2])[:80] if f.notes else ""
            code_str = str(f.status_code) if f.status_code else "—"
            lines.append(
                f"| `{f.target}` | {f.surface} | **{f.confidence.upper()}** | {code_str} | {notes_short} |"
            )
        lines.append("")

    # ── Evidence ──────────────────────────────────────────────────────────────
    if vulns:
        lines += [f"## Evidence", f""]
        for i, f in enumerate(vulns[:20], 1):
            lines += [
                f"### Finding {i}: {f.surface} → `{f.target}`",
                f"",
                f"- **Confidence:** {f.confidence.upper()}",
                f"- **HTTP Status:** {f.status_code or 'N/A'}",
                f"- **Response time:** {f.response_time_ms:.1f}ms",
                f"- **Payload (preview):** `{f.payload_preview}`",
            ]
            if f.notes:
                lines += ["- **Indicators:**"]
                for note in f.notes:
                    lines.append(f"  - {note}")
            if f.response_snippet:
                lines += [
                    "",
                    "**Response snippet:**",
                    "```",
                    f.response_snippet[:400],
                    "```",
                ]
            lines.append("")

    # ── Remediation ───────────────────────────────────────────────────────────
    lines += [
        f"## Remediation",
        f"",
        f"### Immediate Actions",
        f"",
        f"1. **Upgrade JDK** to a patched version that disables the vulnerable AVX-512 VBMI intrinsic:",
        f"   - OpenJDK 17.0.x ≥ 17.0.12 (verify with vendor advisory)",
        f"   - OpenJDK 21.0.x ≥ 21.0.5",
        f"   - Confirm patch via: `java -XX:+PrintVMOptions -version 2>&1 | grep Base64`",
        f"",
        f"2. **Workaround** (if immediate upgrade is not possible):",
        f"   ```",
        f"   -XX:-UseBASE64Intrinsics",
        f"   ```",
        f"   Add to JVM startup flags. Disables the intrinsic; Base64 falls back to pure-Java path.",
        f"",
        f"3. **Verify CPU exposure:**",
        f"   ```bash",
        f"   grep -m1 avx512_vbmi /proc/cpuinfo",
        f"   ```",
        f"   If `avx512_vbmi` is absent from flags, the vulnerable intrinsic path is not activated.",
        f"",
        f"4. **Network controls:** WAF rules blocking malformed Base64 padding in HTTP headers,",
        f"   bodies, and query parameters reduce attack surface while patching is in progress.",
        f"",
        f"### CVSS Vector",
        f"",
        f"```",
        f"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        f"```",
        f"",
        f"---",
        f"",
        f"*Report generated by Java4Shell — authorized penetration testing use only.*",
        f"",
    ]

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ─── JUnit XML report ─────────────────────────────────────────────────────────

def save_junit_xml_report(
    findings: list[ReportFinding],
    output_path: str,
    meta: Optional[ReportMeta] = None,
) -> None:
    """
    Write a JUnit-compatible XML report to output_path.
    Compatible with Jenkins, GitLab CI, and GitHub Actions test report parsers.

    Schema: each target+surface pair is a test case.
    VULNERABLE → failure  |  ERROR → error  |  CLEAN → pass
    """
    if meta is None:
        meta = ReportMeta()
        meta.timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        meta.total_probes = len(findings)
        meta.vulnerable_count = sum(1 for f in findings if f.vulnerable)

    failures = sum(1 for f in findings if f.vulnerable)
    errors   = sum(1 for f in findings if f.error and not f.vulnerable)
    ts_name  = f"java4shell.{meta.cve.replace('-', '_')}"

    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="{html.escape(meta.cve)}" tests="{len(findings)}" '
        f'failures="{failures}" errors="{errors}" time="0">',
        f'  <testsuite name="{html.escape(ts_name)}" tests="{len(findings)}" '
        f'failures="{failures}" errors="{errors}" '
        f'timestamp="{html.escape(meta.timestamp)}" hostname="{html.escape(meta.target)}">',
    ]

    for f in findings:
        classname = html.escape(f.target.replace("https://", "").replace("http://", "").replace("/", ".").strip("."))
        testname  = html.escape(f.surface)
        time_sec  = f"{f.response_time_ms / 1000:.3f}"

        xml_lines.append(
            f'    <testcase classname="{classname}" name="{testname}" time="{time_sec}">'
        )

        if f.vulnerable:
            msg = html.escape(" | ".join(f.notes) if f.notes else "Vulnerable surface detected")
            detail = html.escape(
                f"Surface: {f.surface}\n"
                f"Confidence: {f.confidence}\n"
                f"HTTP status: {f.status_code}\n"
                f"Response time: {f.response_time_ms:.1f}ms\n"
                f"Payload: {f.payload_preview}\n"
                f"Notes:\n" + "\n".join(f"  - {n}" for n in f.notes) +
                (f"\n\nResponse snippet:\n{f.response_snippet[:500]}" if f.response_snippet else "")
            )
            xml_lines += [
                f'      <failure message="{msg}" type="{html.escape(meta.cve)}">',
                f'        {detail}',
                f'      </failure>',
            ]
        elif f.error:
            xml_lines += [
                f'      <error message="{html.escape(str(f.error))}" type="NetworkError">',
                f'        {html.escape(str(f.error))}',
                f'      </error>',
            ]

        xml_lines.append("    </testcase>")

    xml_lines += [
        "  </testsuite>",
        "</testsuites>",
    ]

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(xml_lines))


# ─── Auto-dispatch from extension ────────────────────────────────────────────

def save_report(findings: list[ReportFinding], output_path: str, meta: Optional[ReportMeta] = None) -> None:
    """
    Save report to output_path, format inferred from extension:
      .md   → Markdown
      .xml  → JUnit XML
      .json → raw JSON (passthrough for existing json reporters)
    """
    ext = output_path.lower().rsplit(".", 1)[-1] if "." in output_path else ""
    if ext == "md":
        save_markdown_report(findings, output_path, meta)
    elif ext == "xml":
        save_junit_xml_report(findings, output_path, meta)
    elif ext == "json":
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(
                [
                    {
                        "target": f.target,
                        "surface": f.surface,
                        "confidence": f.confidence,
                        "vulnerable": f.vulnerable,
                        "payload_preview": f.payload_preview,
                        "status_code": f.status_code,
                        "response_time_ms": round(f.response_time_ms, 2),
                        "notes": f.notes,
                        "error": f.error,
                    }
                    for f in findings
                ],
                fh,
                indent=2,
                ensure_ascii=False,
            )
    else:
        # Default to Markdown
        save_markdown_report(findings, output_path, meta)


# ─── Adapter: convert ScanResult → ReportFinding ─────────────────────────────

def scan_results_to_findings(scan_results: list) -> list[ReportFinding]:
    """Convert java4shell_scanner.ScanResult objects to ReportFinding objects."""
    findings = []
    for r in scan_results:
        f = ReportFinding(
            target=r.target,
            surface=r.surface,
            confidence=r.confidence,
            vulnerable=r.vulnerable,
            payload_preview=getattr(r, "payload_preview", ""),
            status_code=r.status_code,
            response_time_ms=r.response_time_ms,
            notes=list(r.notes),
            error=r.error,
            response_snippet=getattr(r, "response_snippet", ""),
        )
        findings.append(f)
    return findings
