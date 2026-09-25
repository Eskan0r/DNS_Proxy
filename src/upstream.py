"""Upstream resolver (DoH + fallback), Toan Nguyen

Contract for proxy.py:
    up = UpstreamResolver()
    answers, ttl, latency_ms = up.resolve("example.com", "A")
    # answers=["93.184.216.34"], ttl=300 -> cache + reply
    # On total failure -> raise UpstreamError so proxy returns SERVFAIL.

Requirements:
- DoH (https://cloudflare-dns.com/dns-query, dns.google) via httpx/requests.
- Timeout (config.UPSTREAM_TIMEOUT_SEC) + retries + UDP fallback to 8.8.8.8.
- Measure latency_ms per query for Kareem's eval (direct vs proxy overhead).
"""
# TODO: import httpx, dnslib, time


class UpstreamError(Exception):
    """Raised when all upstreams fail."""
    pass


class UpstreamResolver:
    """TODO: implement resolve() + _doh_query() + _udp_fallback()."""

    def __init__(self, doh_urls: list[str] | None = None, timeout: float = 3.0):
        raise NotImplementedError

    def resolve(self, domain: str, qtype: str = "A") -> tuple[list[str], int, float]:
        """Try each DoH URL, then UDP fallback. Return (ips, ttl, latency_ms)."""
        raise NotImplementedError
