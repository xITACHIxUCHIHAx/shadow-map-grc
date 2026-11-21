import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "shadow_map.db"

# Local-only by default. Configure these through environment variables
# when running in a controlled shared environment.
SECRET_KEY = os.environ.get(
    "SHADOW_MAP_SECRET_KEY",
    "local-development-only-change-before-hosting",
)
HOST = os.environ.get("SHADOW_MAP_HOST", "127.0.0.1")
PORT = int(os.environ.get("SHADOW_MAP_PORT", "5000"))


def _positive_int_setting(name, default, minimum=1):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc

    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}.")

    return value


def _bounded_int_setting(name, default, minimum, maximum):
    value = _positive_int_setting(name, default, minimum=minimum)
    if value > maximum:
        raise RuntimeError(
            f"{name} must not exceed {maximum}."
        )
    return value


# Aggregate Web Security resource limits for one Unified Scan run.
WEB_UNIFIED_MAX_REQUESTS = _bounded_int_setting(
    "SHADOW_MAP_WEB_UNIFIED_MAX_REQUESTS",
    2500,
    minimum=1,
    maximum=12500,
)
WEB_UNIFIED_TIMEOUT_SECONDS = _bounded_int_setting(
    "SHADOW_MAP_WEB_UNIFIED_TIMEOUT_SECONDS",
    1800,
    minimum=1,
    maximum=7200,
)


# Web Security discovery defaults. Override through environment variables.
WEB_CRAWLER_MAX_PAGES = _positive_int_setting(
    "SHADOW_MAP_WEB_MAX_PAGES", 50
)
WEB_CRAWLER_MAX_REQUESTS = _positive_int_setting(
    "SHADOW_MAP_WEB_MAX_REQUESTS", 200
)
WEB_CRAWLER_MAX_BODY_BYTES = _positive_int_setting(
    "SHADOW_MAP_WEB_MAX_BODY_BYTES", 1048576, minimum=1024
)
WEB_CRAWLER_MAX_URLS = _positive_int_setting(
    "SHADOW_MAP_WEB_MAX_URLS", 2000
)

# Web App Assessment profiles.
# These settings define limits only; they do not execute assessments.
WEB_ASSESSMENT_DEFAULT_PROFILE = os.environ.get(
    "SHADOW_MAP_WEB_ASSESSMENT_PROFILE", "standard"
).strip().lower()

if WEB_ASSESSMENT_DEFAULT_PROFILE not in {
    "standard", "comprehensive", "deep"
}:
    raise RuntimeError(
        "SHADOW_MAP_WEB_ASSESSMENT_PROFILE must be "
        "standard, comprehensive, or deep."
    )

# Absolute safety ceilings shared by all assessment profiles.
WEB_ASSESSMENT_HARD_LIMITS = {
    "max_requests": 500,
    "max_body_bytes": 1048576,
    "max_redirects": 10,
    "connect_timeout": 5,
    "read_timeout": 15,
    "max_sqli_candidates": 100,
    "max_boolean_sqli_candidates": 50,
    "max_reflected_input_candidates": 100,
}

WEB_ASSESSMENT_PROFILES = {
    "standard": {
        "max_requests": 50,
        "max_body_bytes": 262144,
        "max_redirects": 5,
        "connect_timeout": 3,
        "read_timeout": 7,
        "max_sqli_candidates": 10,
        "max_boolean_sqli_candidates": 5,
        "max_reflected_input_candidates": 10,
    },
    "comprehensive": {
        "max_requests": 250,
        "max_body_bytes": 524288,
        "max_redirects": 8,
        "connect_timeout": 5,
        "read_timeout": 10,
        "max_sqli_candidates": 50,
        "max_boolean_sqli_candidates": 25,
        "max_reflected_input_candidates": 50,
    },
    "deep": {
        "max_requests": 500,
        "max_body_bytes": 1048576,
        "max_redirects": 10,
        "connect_timeout": 5,
        "read_timeout": 15,
        "max_sqli_candidates": 100,
        "max_boolean_sqli_candidates": 50,
        "max_reflected_input_candidates": 100,
    },
}

# Comma-separated trusted reverse-proxy IPs/CIDRs.
# Leave empty unless the application is behind a trusted proxy.
TRUSTED_PROXY_CIDRS = tuple(
    item.strip()
    for item in os.environ.get("SHADOW_MAP_TRUSTED_PROXIES", "").split(",")
    if item.strip()
)

DATA_DIR.mkdir(parents=True, exist_ok=True)


# Continuous Vulnerability Intelligence monitoring.
# NVD incremental checks run every 6 hours by default.
VULNERABILITY_NVD_SYNC_INTERVAL = _bounded_int_setting(
    "SHADOW_MAP_VULN_NVD_SYNC_INTERVAL",
    21600,
    minimum=300,
    maximum=86400,
)

# CISA Known Exploited Vulnerabilities catalogue refreshes daily.
VULNERABILITY_KEV_SYNC_INTERVAL = _bounded_int_setting(
    "SHADOW_MAP_VULN_KEV_SYNC_INTERVAL",
    86400,
    minimum=3600,
    maximum=604800,
)

# FIRST EPSS scores are refreshed daily by default.
VULNERABILITY_EPSS_SYNC_INTERVAL = _bounded_int_setting(
    "SHADOW_MAP_VULN_EPSS_SYNC_INTERVAL",
    86400,
    minimum=3600,
    maximum=604800,
)

# Optional HexBrain enrichment.
# API key is read from the environment at call time inside sync_hexbrain;
# it is never stored in this file, in SQLite, or in logs.
# Missing key means HexBrain runs in Disabled mode; NVD/KEV/EPSS unaffected.
VULNERABILITY_HEXBRAIN_SYNC_INTERVAL = _bounded_int_setting(
    "SHADOW_MAP_VULN_HEXBRAIN_SYNC_INTERVAL",
    86400,
    minimum=3600,
    maximum=604800,
)

HEXBRAIN_BATCH_SIZE = _bounded_int_setting(
    "SHADOW_MAP_HEXBRAIN_BATCH_SIZE",
    20,
    minimum=1,
    maximum=90,
)

HEXBRAIN_MAX_BATCHES_PER_RUN = _bounded_int_setting(
    "SHADOW_MAP_HEXBRAIN_MAX_BATCHES_PER_RUN",
    3,
    minimum=1,
    maximum=20,
)

HEXBRAIN_MAX_RESPONSE_BYTES = _bounded_int_setting(
    "SHADOW_MAP_HEXBRAIN_MAX_RESPONSE_BYTES",
    524288,
    minimum=4096,
    maximum=2097152,
)

HEXBRAIN_API_URL = "https://hexbrainai.com/api/v1/get_cve"
