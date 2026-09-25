from pathlib import Path

# --- Network ---
LISTEN_IP = "127.0.0.1"
LISTEN_PORT_TEST = 5353   # use for dev (no admin needed)
LISTEN_PORT_PROD = 53     # use for real LAN deployment
UPSTREAM_DOH_URLS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]
UPSTREAM_FALLBACK_UDP = ("8.8.8.8", 53)
UPSTREAM_TIMEOUT_SEC = 3.0
UPSTREAM_RETRIES = 2

# --- Sinkhole (Artin) ---
SINKHOLE_IPV4 = "0.0.0.0"
SINKHOLE_IPV6 = "::"
SINKHOLE_TTL = 60

# --- Cache (Minkyu) ---
CACHE_MAX_ENTRIES = 5000
CACHE_MIN_TTL = 30
CACHE_MAX_TTL = 3600

# --- Detection thresholds (tuned by owners, wired here) ---
# TODO Megan: set TYPO_MAX_DISTANCE after FP test
TYPO_MAX_DISTANCE = 2
# TODO Chaiyun: set ENTROPY_THRESHOLD after Tranco vs malicious eval
ENTROPY_THRESHOLD = 4.0
DGA_MIN_LABEL_LEN = 12

# --- Paths ---
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"      # blocklists, allowlist, tranco top200
LOGS_DIR = BASE_DIR / "logs"
DB_PATH = LOGS_DIR / "dns_proxy.db"

# TODO: add load_config(yaml) if team wants file override.
