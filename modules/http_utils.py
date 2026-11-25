# language: Python 3.10+, file: modules/http_utils.py
# Shared HTTP utilities: User-Agent rotation and adaptive jitter delay.
# Used by scanner, exploit_core, grooming, fingerprint, heap_oracle.

import random
import time

# ─── Realistic User-Agent pool ───────────────────────────────────────────────
# Mix of browsers, curl, Java clients, and enterprise scanners.
# Avoids static "Java4Shell-*/1.0" strings that WAF rules trivially block.

_USER_AGENTS: list[str] = [
    # Chrome — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome — Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox — Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # curl — common in CI pipelines and health checks
    "curl/8.7.1",
    "curl/7.88.1",
    # Java HttpClient (plausible for SAML/REST integrations)
    "Java/21.0.13",
    "Java/17.0.11",
    # Spring Boot actuator default client (Micrometer/OkHttp)
    "okhttp/4.12.0",
    # Apache HttpComponents (Jenkins, Confluence internal calls)
    "Apache-HttpClient/5.3 (Java/21.0.13)",
    "Apache-HttpClient/4.5.14 (Java/11.0.23)",
    # Keycloak internal REST calls
    "RESTEasy Client 6.2.9.Final",
    # Generic enterprise scanner baseline
    "python-requests/2.31.0",
]


def random_ua() -> str:
    """Return a random User-Agent from the pool."""
    return random.choice(_USER_AGENTS)


def jitter(min_ms: float = 0.0, max_ms: float = 0.0) -> None:
    """
    Sleep for a random duration between min_ms and max_ms milliseconds.
    No-op when both are 0 (default — preserves existing behaviour).
    """
    if max_ms <= 0:
        return
    lo = max(0.0, min_ms)
    hi = max(lo, max_ms)
    time.sleep(random.uniform(lo, hi) / 1000.0)


# Default jitter window used by scanner and exploit when --jitter is set.
# Values are milliseconds. Caller overrides as needed.
DEFAULT_JITTER_MIN_MS: float = 100.0
DEFAULT_JITTER_MAX_MS: float = 800.0
