"""Layer 0 - TTL-aware LRU cache, Minkyu Jeong

Contract for proxy.py:
    cache = DNSCache()                    # sizes/TTL bounds from config
    hit = cache.get("example.com", "A")   # -> CacheEntry | None (None = miss/expired)
    if hit: reply with hit.answers, ttl=hit.remaining_ttl()
    cache.set("example.com", "A", ["1.2.3.4"], ttl=300)  # -> False if not cacheable
    cache.stats()  # -> {"hits", "misses", "size", "evictions", "hit_rate"} for report

Benchmark (hit rate + speed, Deliverable 1):
    python -m src.cache

Requirements:
- Check expiry on every get(), enforce real TTL.
- Clamp TTL between config.CACHE_MIN_TTL / CACHE_MAX_TTL.
- LRU eviction when full (collections.OrderedDict).
- Only cache A/AAAA, don't cache sinkholed blocks.
"""
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from . import config

CACHEABLE_QTYPES = ("A", "AAAA")
SINKHOLE_ANSWERS = {config.SINKHOLE_IPV4, config.SINKHOLE_IPV6}


@dataclass
class CacheEntry:
    """What proxy needs to rebuild a DNS reply without upstream."""
    answers: list[str]      # IPs, e.g. ["1.2.3.4"]
    ttl: int                # clamped TTL at store time
    expires_at: float       # time.monotonic() + ttl
    qtype: str = "A"        # "A" or "AAAA"

    def remaining_ttl(self, now: float | None = None) -> int:
        """Seconds left, so cached replies count down instead of repeating the original TTL."""
        now = time.monotonic() if now is None else now
        return max(0, int(self.expires_at - now))


def _normalize(domain: str) -> str:
    # Same rule as utils.normalize_domain; swap to that once it's implemented.
    return domain.strip().lower().rstrip(".")


class DNSCache:
    """Thread-safe TTL + LRU cache keyed by (domain, qtype)."""

    def __init__(self, max_entries: int = config.CACHE_MAX_ENTRIES,
                 min_ttl: int = config.CACHE_MIN_TTL,
                 max_ttl: int = config.CACHE_MAX_TTL,
                 clock=time.monotonic):
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self.max_entries = max_entries
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self._clock = clock     # injectable so tests can fake time
        self._store: OrderedDict[tuple[str, str], CacheEntry] = OrderedDict()
        self._lock = threading.Lock()  # proxy handles queries in a thread pool
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, domain: str, qtype: str = "A") -> CacheEntry | None:
        """Return entry if present and not expired, else None."""
        key = (_normalize(domain), qtype.upper())
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.misses += 1
                return None
            if self._clock() >= entry.expires_at:
                del self._store[key]
                self.misses += 1
                return None
            self._store.move_to_end(key)
            self.hits += 1
            return entry

    def set(self, domain: str, qtype: str, answers: list[str], ttl: int) -> bool:
        """Store with expires_at = now + clamped ttl. Evict LRU if full.
        Returns False (not stored) for non-A/AAAA, empty or sinkholed answers.
        """
        qtype = qtype.upper()
        if qtype not in CACHEABLE_QTYPES or not answers:
            return False
        if any(ip in SINKHOLE_ANSWERS for ip in answers):
            return False
        ttl = max(self.min_ttl, min(self.max_ttl, int(ttl)))
        key = (_normalize(domain), qtype)
        entry = CacheEntry(answers=list(answers), ttl=ttl,
                           expires_at=self._clock() + ttl, qtype=qtype)
        with self._lock:
            self._store[key] = entry
            self._store.move_to_end(key)
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)
                self.evictions += 1
        return True

    def purge_expired(self) -> int:
        """Drop all expired entries, return how many were removed."""
        now = self._clock()
        with self._lock:
            expired = [k for k, e in self._store.items() if now >= e.expires_at]
            for k in expired:
                del self._store[k]
        return len(expired)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self.hits = self.misses = self.evictions = 0

    def __len__(self) -> int:
        return len(self._store)

    def stats(self) -> dict:
        """Counters for Kareem's report."""
        with self._lock:
            lookups = self.hits + self.misses
            return {
                "hits": self.hits,
                "misses": self.misses,
                "size": len(self._store),
                "evictions": self.evictions,
                "hit_rate": self.hits / lookups if lookups else 0.0,
            }


# --- Benchmarks (Deliverable 1: hit rate + speed) ---

def _zipf_workload(n_domains: int, n_queries: int, skew: float, seed: int) -> list[str]:
    """Real DNS traffic is heavy-tailed: a few domains get most queries."""
    import random
    rng = random.Random(seed)
    domains = [f"site{i}.example" for i in range(n_domains)]
    weights = [1 / (rank + 1) ** skew for rank in range(n_domains)]
    return rng.choices(domains, weights=weights, k=n_queries)


def benchmark_hit_rate(max_entries: int = config.CACHE_MAX_ENTRIES, n_domains: int = 2000,
                       n_queries: int = 20000, qps: float = 20.0, ttl: int = 300,
                       skew: float = 1.0, seed: int = 0) -> dict:
    """Replay a Zipf workload on a simulated clock (qps queries/sec) so TTL expiry counts.
    Every miss is "resolved" and stored, like the proxy does after upstream."""
    now = [0.0]
    cache = DNSCache(max_entries=max_entries, clock=lambda: now[0])
    for domain in _zipf_workload(n_domains, n_queries, skew, seed):
        if cache.get(domain, "A") is None:
            cache.set(domain, "A", ["192.0.2.1"], ttl=ttl)
        now[0] += 1 / qps
    return cache.stats()


def benchmark_speed(n_ops: int = 100_000, max_entries: int = config.CACHE_MAX_ENTRIES) -> dict:
    """Wall-clock cost per operation in microseconds."""
    cache = DNSCache(max_entries=max_entries)
    domains = [f"site{i}.example" for i in range(max_entries)]
    keys = [domains[i % max_entries] for i in range(n_ops)]
    missing = [f"missing{i}.example" for i in range(n_ops)]

    t0 = time.perf_counter()
    for d in keys:
        cache.set(d, "A", ["192.0.2.1"], ttl=300)
    t1 = time.perf_counter()
    for d in keys:
        cache.get(d, "A")
    t2 = time.perf_counter()
    for d in missing:
        cache.get(d, "A")
    t3 = time.perf_counter()

    us = 1e6 / n_ops
    return {"set_us": (t1 - t0) * us, "get_hit_us": (t2 - t1) * us,
            "get_miss_us": (t3 - t2) * us, "n_ops": n_ops}


if __name__ == "__main__":
    print("Hit rate (Zipf s=1.0, 2000 domains, 20k queries @ 20 qps, TTL 300s):")
    for size in (50, 200, 1000, config.CACHE_MAX_ENTRIES):
        s = benchmark_hit_rate(max_entries=size)
        print(f"  max_entries={size:>5}: hit_rate={s['hit_rate']:.1%}  evictions={s['evictions']}")
    sp = benchmark_speed()
    print(f"Speed ({sp['n_ops']} ops): set {sp['set_us']:.2f} us, "
          f"get hit {sp['get_hit_us']:.2f} us, get miss {sp['get_miss_us']:.2f} us")
