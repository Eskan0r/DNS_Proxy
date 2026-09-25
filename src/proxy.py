"""Core DNS proxy engine, rc

Pipeline (order matters):
  1. UDP listener (socket, ThreadPoolExecutor for concurrent queries)
  2. Parse wire format (dnslib.DNSRecord.parse)
  3. Normalize (utils.normalize_domain)
  4. Cache lookup (Minkyu) -> reply immediately on HIT
  5. Allowlist (Artin) -> ALLOW override
  6. Blocklist (Justin, subdomain-aware) -> SINKHOLE
  7. Typosquat (Megan) -> SINKHOLE
  8. DGA/entropy (Chaiyun) -> SINKHOLE
  9. Upstream DoH (Toan) -> cache store -> reply
  10. Log everything (Vinh) with latency_ms
  Only A/AAAA handled initially, others -> upstream passthrough.

Run: python main.py --port 5353
Test: nslookup example.com 127.0.0.1 -port=5353  /  dig @127.0.0.1 -p 5353 evil.com
"""
# TODO: imports socket, concurrent.futures, time, dnslib, config, all layers
import time

# TODO: from .cache import DNSCache
# TODO: from .blocklist import BlocklistChecker ... etc.


class DNSProxy:
    """TODO: wire all layers together."""

    def __init__(self, ip: str = "127.0.0.1", port: int = 5353):
        # TODO: init cache, blocklist, allowlist, typo, dga, upstream, logger
        # TODO: init UDP socket + ThreadPoolExecutor(max_workers=20)
        raise NotImplementedError

    def serve_forever(self) -> None:
        """TODO: bind, loop recvfrom(512), submit to pool. Handle KeyboardInterrupt."""
        raise NotImplementedError

    def handle_query(self, data: bytes, client: tuple[str, int]) -> bytes:
        """TODO: full pipeline, always return wire-format reply bytes.
        Steps:
          start = time.time()
          req = DNSRecord.parse(data); qname, qtype = parse
          domain = normalize_domain(str(qname))
          1. cache.get -> build reply from cache, log 'cache'
          2. allowlist -> upstream (skip blocks)
          3-5. blocklist/typo/dga -> build_sinkhole_reply, log 'block:<reason>'
          6. upstream.resolve -> cache.set -> build reply, log 'allow:upstream'
          on exception -> SERVFAIL reply, log 'error'
          record latency_ms = (time.time()-start)*1000
        """
        raise NotImplementedError

    def _build_reply(self, request, answers: list[str], ttl: int, qtype: str):
        """TODO: request.reply(), add RR for each IP. Used for cache + upstream."""
        raise NotImplementedError


# TODO: add if __name__ == "__main__" smoke test with stub layers.
