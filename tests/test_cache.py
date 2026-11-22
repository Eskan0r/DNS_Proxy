"""Minkyu: cache correctness + hit rate / speed benchmarks (Deliverable 1)."""
import threading

import pytest

from src import config
from src.cache import DNSCache, benchmark_hit_rate, benchmark_speed


class FakeClock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, sec: float) -> None:
        self.t += sec


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def cache(clock):
    return DNSCache(max_entries=3, min_ttl=30, max_ttl=3600, clock=clock)


def test_set_get_hit(cache):
    cache.set("example.com", "A", ["1.2.3.4"], ttl=300)
    entry = cache.get("example.com", "A")
    assert entry is not None
    assert entry.answers == ["1.2.3.4"]
    assert entry.qtype == "A"


def test_miss_on_unknown(cache):
    assert cache.get("nothere.com", "A") is None
    assert cache.stats()["misses"] == 1


def test_normalized_key(cache):
    cache.set("Example.COM.", "a", ["1.2.3.4"], ttl=300)
    assert cache.get(" example.com ", "A") is not None


def test_a_and_aaaa_are_separate(cache):
    cache.set("example.com", "A", ["1.2.3.4"], ttl=300)
    assert cache.get("example.com", "AAAA") is None
    cache.set("example.com", "AAAA", ["2001:db8::1"], ttl=300)
    assert cache.get("example.com", "AAAA").answers == ["2001:db8::1"]
    assert cache.get("example.com", "A").answers == ["1.2.3.4"]


def test_expiry(cache, clock):
    cache.set("example.com", "A", ["1.2.3.4"], ttl=60)
    clock.advance(59)
    assert cache.get("example.com", "A") is not None
    clock.advance(1)
    assert cache.get("example.com", "A") is None
    assert len(cache) == 0  # expired entry removed on access


def test_remaining_ttl_counts_down(cache, clock):
    cache.set("example.com", "A", ["1.2.3.4"], ttl=300)
    clock.advance(100)
    assert cache.get("example.com", "A").remaining_ttl(clock()) == 200


def test_ttl_clamped_low(cache, clock):
    cache.set("example.com", "A", ["1.2.3.4"], ttl=1)
    assert cache.get("example.com", "A").ttl == 30
    clock.advance(29)
    assert cache.get("example.com", "A") is not None


def test_ttl_clamped_high(cache, clock):
    cache.set("example.com", "A", ["1.2.3.4"], ttl=86400)
    assert cache.get("example.com", "A").ttl == 3600
    clock.advance(3600)
    assert cache.get("example.com", "A") is None


def test_lru_eviction(cache):
    cache.set("a.com", "A", ["1.1.1.1"], ttl=300)
    cache.set("b.com", "A", ["2.2.2.2"], ttl=300)
    cache.set("c.com", "A", ["3.3.3.3"], ttl=300)
    cache.get("a.com", "A")  # a is now most recent, b is LRU
    cache.set("d.com", "A", ["4.4.4.4"], ttl=300)
    assert len(cache) == 3
    assert cache.get("b.com", "A") is None
    assert cache.get("a.com", "A") is not None
    assert cache.stats()["evictions"] == 1


def test_overwrite_refreshes(cache, clock):
    cache.set("a.com", "A", ["1.1.1.1"], ttl=60)
    clock.advance(50)
    cache.set("a.com", "A", ["9.9.9.9"], ttl=60)
    clock.advance(50)
    entry = cache.get("a.com", "A")
    assert entry.answers == ["9.9.9.9"]
    assert len(cache) == 1


@pytest.mark.parametrize("qtype", ["MX", "TXT", "CNAME", "NS"])
def test_only_a_aaaa_cached(cache, qtype):
    assert cache.set("example.com", qtype, ["x"], ttl=300) is False
    assert len(cache) == 0


@pytest.mark.parametrize("ip,qtype", [(config.SINKHOLE_IPV4, "A"), (config.SINKHOLE_IPV6, "AAAA")])
def test_sinkhole_not_cached(cache, ip, qtype):
    assert cache.set("evil.com", qtype, [ip], ttl=60) is False
    assert cache.get("evil.com", qtype) is None


def test_empty_answers_not_cached(cache):
    assert cache.set("example.com", "A", [], ttl=300) is False


def test_stats(cache):
    cache.set("a.com", "A", ["1.1.1.1"], ttl=300)
    cache.get("a.com", "A")
    cache.get("a.com", "A")
    cache.get("b.com", "A")
    s = cache.stats()
    assert s["hits"] == 2 and s["misses"] == 1 and s["size"] == 1
    assert s["hit_rate"] == pytest.approx(2 / 3)


def test_purge_expired(cache, clock):
    cache.set("a.com", "A", ["1.1.1.1"], ttl=60)
    cache.set("b.com", "A", ["2.2.2.2"], ttl=600)
    clock.advance(100)
    assert cache.purge_expired() == 1
    assert len(cache) == 1


def test_defaults_from_config():
    c = DNSCache()
    assert c.max_entries == config.CACHE_MAX_ENTRIES
    assert (c.min_ttl, c.max_ttl) == (config.CACHE_MIN_TTL, config.CACHE_MAX_TTL)


def test_thread_safety():
    c = DNSCache(max_entries=100)

    def worker(n):
        for i in range(2000):
            d = f"d{(n * 7 + i) % 300}.com"
            c.set(d, "A", ["1.2.3.4"], ttl=300)
            c.get(d, "A")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    s = c.stats()
    assert s["size"] <= 100
    assert s["hits"] + s["misses"] == 8 * 2000


# --- Deliverable 1: hit rate + speed ---

def test_hit_rate_realistic_workload():
    # Zipf traffic, cache big enough to never evict: misses ~ first sight + TTL refresh
    s = benchmark_hit_rate()
    assert s["hits"] + s["misses"] == 20000
    assert s["evictions"] == 0
    assert s["hit_rate"] >= 0.75


def test_hit_rate_grows_with_size():
    rates = [benchmark_hit_rate(max_entries=n)["hit_rate"] for n in (50, 200, 1000)]
    assert rates == sorted(rates)
    assert rates[0] > 0.25  # LRU keeps the hot head even when tiny


def test_hit_rate_drops_when_ttl_expires():
    long_ttl = benchmark_hit_rate(ttl=3600)["hit_rate"]
    short_ttl = benchmark_hit_rate(ttl=30)["hit_rate"]
    assert short_ttl < long_ttl


def test_speed():
    # Upstream DoH is ~10-100 ms; a cache op must be orders of magnitude cheaper.
    sp = benchmark_speed(n_ops=20_000)
    assert sp["get_hit_us"] < 100
    assert sp["get_miss_us"] < 100
    assert sp["set_us"] < 200
