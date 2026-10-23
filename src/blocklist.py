"""Layer 1 - Blocklist checker, Justin Truong

Contract for proxy.py:
    checker = BlocklistChecker()
    checker.load(["bad.com", "evil.net"])  # or .load_file("data/blocklist.txt")
    blocked, matched = checker.is_blocked("a.bad.com")
    # blocked=True, matched="bad.com" -> sinkhole
    # Handles subdomains: a.bad.com is part of bad.com.

Requirements:
- Must scale to 100k+ domains, fast per-query (<1ms goal).
- Normalize via utils.normalize_domain.
- Data structure: hash set for O(1) exact lookup + parent suffix walk.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from pathlib import Path

from . import utils as _utils


def _fallback_normalize_domain(raw: str) -> str:
    """Lowercase, strip whitespace and leading/trailing dots."""
    return raw.strip().lower().strip(".")


try:
    _utils.normalize_domain("example.com")
    _utils_normalize = _utils.normalize_domain
except NotImplementedError:
    _utils_normalize = _fallback_normalize_domain


def normalize_domain(raw: str) -> str:
    """Normalize a raw domain string using utils.normalize_domain with fallback."""
    if not raw or not isinstance(raw, str):
        return ""
    return _utils_normalize(raw).strip(".")


def is_subdomain(candidate: str, parent: str) -> bool:
    """True if candidate == parent or candidate is a subdomain of parent.
    Ex: is_subdomain('a.bad.com', 'bad.com') -> True
        is_subdomain('notbad.com', 'bad.com') -> False
    """
    cand = normalize_domain(candidate)
    par = normalize_domain(parent)
    if not cand or not par:
        return False
    return cand == par or cand.endswith("." + par)


def _clean_entry(raw: str) -> str:
    """Extract and normalize a single domain entry from a raw list/file line.

    Supports plain domains ('bad.com'), trailing dots ('BAD.COM.'),
    inline comments ('bad.com # malware'), hosts-file lines ('0.0.0.0 bad.com'),
    and wildcard prefixes ('*.bad.com').
    """
    if not raw or not isinstance(raw, str):
        return ""
    line = raw.strip()
    if not line or line.startswith("#"):
        return ""
    if "#" in line:
        line = line.split("#", 1)[0].strip()
    if not line:
        return ""
    parts = line.split()
    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
        line = parts[1]
    elif len(parts) > 1:
        line = parts[0]
    if line.startswith("*."):
        line = line[2:]
    domain = normalize_domain(line)
    if not domain or "." not in domain or ".." in domain or " " in domain:
        return ""
    return domain


class BlocklistChecker:
    """Subdomain-aware banned domain checker backed by an O(1) hash set.

    For a query with k labels (typically 2-4), lookup performs at most k hash
    probes by walking parent suffixes from most-specific to least-specific
    ('a.b.bad.com' -> 'b.bad.com' -> 'bad.com' -> 'com'), independent of
    whether the blocklist holds 100 or 1,000,000+ domains.
    """

    def __init__(self, domains: Iterable[str] | None = None):
        self._blocked: set[str] = set()
        self._lock = threading.Lock()
        if domains is not None:
            self.load(domains)

    def load(self, domains: Iterable[str]) -> None:
        """Load + normalize an iterable of bad domains into the blocklist."""
        cleaned = {d for raw in domains if (d := _clean_entry(raw))}
        if not cleaned:
            return
        with self._lock:
            self._blocked = self._blocked | cleaned

    def load_file(self, path: str | Path) -> int:
        """Load domains from a text file (one domain per line).

        Ignores blank lines and '#' comments. Returns count of unique valid
        domains loaded from the file.
        """
        file_path = Path(path)
        with file_path.open("r", encoding="utf-8") as fh:
            cleaned = {d for line in fh if (d := _clean_entry(line))}
        with self._lock:
            self._blocked = self._blocked | cleaned
        return len(cleaned)

    def add(self, domain: str) -> bool:
        """Add a single domain to the blocklist. Returns True if valid."""
        cleaned = _clean_entry(domain)
        if not cleaned:
            return False
        with self._lock:
            if cleaned not in self._blocked:
                self._blocked = self._blocked | {cleaned}
        return True

    def remove(self, domain: str) -> bool:
        """Remove a domain from the blocklist. Returns True if it was present."""
        cleaned = normalize_domain(domain)
        if not cleaned:
            return False
        with self._lock:
            if cleaned not in self._blocked:
                return False
            updated = set(self._blocked)
            updated.discard(cleaned)
            self._blocked = updated
            return True

    def clear(self) -> None:
        """Remove all domains from the blocklist."""
        with self._lock:
            self._blocked = set()

    def is_blocked(self, domain: str) -> tuple[bool, str | None]:
        """Check if domain or any of its parent domains is in the blocklist.

        Returns:
            (True, matched_parent_or_exact) if blocked (e.g. (True, "bad.com")),
            (False, None) if clean.
        """
        candidate = normalize_domain(domain)
        if not candidate:
            return False, None

        blocked = self._blocked
        if not blocked:
            return False, None

        # Fast path: exact match
        if candidate in blocked:
            return True, candidate

        # Walk parent suffixes from most specific to least specific
        idx = candidate.find(".")
        while idx != -1:
            parent = candidate[idx + 1 :]
            if parent in blocked:
                return True, parent
            idx = candidate.find(".", idx + 1)

        return False, None

    def check(self, domain: str) -> str:
        """Return 'blocked' or 'clean' status string for a domain name."""
        blocked, _ = self.is_blocked(domain)
        return "blocked" if blocked else "clean"

    def __len__(self) -> int:
        return len(self._blocked)

    def __contains__(self, domain: str) -> bool:
        blocked, _ = self.is_blocked(domain)
        return blocked


# --- Deliverable 1: 100k+ domain speed benchmark ---


def benchmark_speed(
    n_domains: int = 100_000,
    n_queries: int = 100_000,
) -> dict[str, float | int]:
    """Benchmark load time and lookup latency on a 100k+ domain blocklist.

    Evaluates three query workloads (exact match, deep subdomain match, and
    clean miss) and verifies per-query latency is well below the 1 ms goal.
    """
    banned_domains = [f"malicious-host-{i}.bad{i % 97}.com" for i in range(n_domains)]

    checker = BlocklistChecker()
    t_load_start = time.perf_counter()
    checker.load(banned_domains)
    load_ms = (time.perf_counter() - t_load_start) * 1000.0

    exact_queries = [
        f"malicious-host-{i % n_domains}.bad{(i % n_domains) % 97}.com"
        for i in range(n_queries)
    ]
    subdomain_queries = [
        f"cdn.api.malicious-host-{i % n_domains}.bad{(i % n_domains) % 97}.com"
        for i in range(n_queries)
    ]
    clean_queries = [
        f"www.benign-service-{i}.example.org" for i in range(n_queries)
    ]

    t0 = time.perf_counter()
    for q in exact_queries:
        checker.is_blocked(q)
    t1 = time.perf_counter()
    for q in subdomain_queries:
        checker.is_blocked(q)
    t2 = time.perf_counter()
    for q in clean_queries:
        checker.is_blocked(q)
    t3 = time.perf_counter()

    exact_total_s = t1 - t0
    sub_total_s = t2 - t1
    clean_total_s = t3 - t2
    total_s = t3 - t0
    total_queries = n_queries * 3

    exact_us = (exact_total_s * 1e6) / n_queries
    sub_us = (sub_total_s * 1e6) / n_queries
    clean_us = (clean_total_s * 1e6) / n_queries
    avg_us = (total_s * 1e6) / total_queries
    avg_ms = avg_us / 1000.0

    return {
        "n_domains": len(checker),
        "n_queries": total_queries,
        "load_ms": round(load_ms, 2),
        "exact_hit_us": round(exact_us, 4),
        "subdomain_hit_us": round(sub_us, 4),
        "clean_miss_us": round(clean_us, 4),
        "avg_us": round(avg_us, 4),
        "avg_ms": round(avg_ms, 6),
        "qps": round(total_queries / total_s, 1) if total_s > 0 else 0.0,
    }


if __name__ == "__main__":
    stats = benchmark_speed(n_domains=100_000, n_queries=100_000)
    print(f"Blocklist Benchmark ({stats['n_domains']:,} banned domains loaded in {stats['load_ms']:.1f} ms):")
    print(f"  Exact hit     : {stats['exact_hit_us']:.3f} us/query")
    print(f"  Subdomain hit : {stats['subdomain_hit_us']:.3f} us/query")
    print(f"  Clean miss    : {stats['clean_miss_us']:.3f} us/query")
    print(
        f"  Overall avg   : {stats['avg_us']:.3f} us/query "
        f"({stats['avg_ms']:.6f} ms/query, <1ms goal) | {stats['qps']:,.0f} queries/sec"
    )
