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
- Data structure hint: set for exact + walk parent suffixes, or reversed trie.
- TODO: add benchmark_speed(100k) for Deliverable 1.
"""
from .utils import normalize_domain


class BlocklistChecker:
    """TODO: implement efficient lookup."""

    def __init__(self):
        # TODO: self._blocked: set[str] = set()
        raise NotImplementedError

    def load(self, domains: list[str]) -> None:
        """Load + normalize list of bad domains."""
        raise NotImplementedError

    def load_file(self, path: str) -> int:
        """Load from text file (one domain per line). Return count loaded."""
        raise NotImplementedError

    def is_blocked(self, domain: str) -> tuple[bool, str | None]:
        """Check domain + all parents.
        Returns: (True, "bad.com") if 'a.bad.com' matches 'bad.com',
                 (False, None) if clean.
        TODO: split labels, test 'a.bad.com','bad.com' against set.
        """
        raise NotImplementedError
