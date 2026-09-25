"""Layer 0 - TTL-aware LRU cache, Minkyu Jeong

Contract for proxy.py:
    cache = DNSCache(max_entries=5000)
    hit = cache.get("example.com", "A")   # -> CacheEntry | None (None = miss/expired)
    cache.set("example.com", "A", ["1.2.3.4"], ttl=300)
    cache.stats()  # -> {"hits": int, "misses": int, "size": int} for report

Requirements:
- Check expiry on every get() using time.time(), enforce real TTL.
- Clamp TTL between config.CACHE_MIN_TTL / CACHE_MAX_TTL.
- LRU eviction when full (hint: collections.OrderedDict).
- Only cache A/AAAA, don't cache sinkholed blocks.
"""
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class CacheEntry:
    """What proxy needs to rebuild a DNS reply without upstream."""
    answers: list[str]      # IPs, e.g. ["1.2.3.4"]
    ttl: int                # original TTL from upstream
    expires_at: float       # time.time() + ttl
    qtype: str = "A"        # "A" or "AAAA"


class DNSCache:
    """TODO: implement get/set with expiry + LRU."""

    def __init__(self, max_entries: int = 5000):
        # TODO: self._store: OrderedDict[tuple[str,str], CacheEntry] = OrderedDict()
        # TODO: self.hits / self.misses counters, self.max_entries
        raise NotImplementedError

    def get(self, domain: str, qtype: str = "A") -> CacheEntry | None:
        """Return entry if present and not expired, else None.
        TODO: normalize domain, move-to-end on hit (LRU), delete if expired.
        """
        raise NotImplementedError

    def set(self, domain: str, qtype: str, answers: list[str], ttl: int) -> None:
        """Store with expires_at = now + clamped ttl. Evict LRU if full.
        TODO: clamp ttl, popitem(last=False) when over capacity.
        """
        raise NotImplementedError

    def stats(self) -> dict:
        """TODO: return {'hits':..,'misses':..,'size':..} for Kareem's report."""
        raise NotImplementedError

    # TODO: add test_hit_rate() + test_speed() for Deliverable 1.
