"""Justin: Blocklist checker correctness, subdomain handling, and 100k+ speed benchmark."""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from src.blocklist import BlocklistChecker, benchmark_speed, is_subdomain, normalize_domain


def test_exact_match():
    checker = BlocklistChecker(["bad.com", "evil.net", "malware.org"])
    assert checker.is_blocked("bad.com") == (True, "bad.com")
    assert checker.is_blocked("evil.net") == (True, "evil.net")
    assert checker.is_blocked("malware.org") == (True, "malware.org")
    assert checker.check("bad.com") == "blocked"
    assert "bad.com" in checker


def test_subdomain_match():
    checker = BlocklistChecker(["bad.com", "evil.net"])
    # Single-level subdomain
    assert checker.is_blocked("a.bad.com") == (True, "bad.com")
    # Multi-level deep subdomain
    assert checker.is_blocked("login.secure.a.bad.com") == (True, "bad.com")
    assert checker.is_blocked("sub.evil.net") == (True, "evil.net")
    assert checker.check("a.bad.com") == "blocked"
    assert "a.bad.com" in checker


def test_most_specific_parent_matched():
    checker = BlocklistChecker(["bad.com", "sub.bad.com"])
    assert checker.is_blocked("sub.bad.com") == (True, "sub.bad.com")
    assert checker.is_blocked("deep.sub.bad.com") == (True, "sub.bad.com")
    assert checker.is_blocked("other.bad.com") == (True, "bad.com")


def test_no_false_positive():
    checker = BlocklistChecker(["bad.com", "evil.net"])
    # Prefix lookalike on same label must NOT match (notbad.com is not a subdomain of bad.com)
    assert checker.is_blocked("notbad.com") == (False, None)
    assert checker.is_blocked("mybad.com") == (False, None)
    assert checker.is_blocked("sub.notbad.com") == (False, None)
    # Different TLD / suffix must NOT match
    assert checker.is_blocked("bad.com.org") == (False, None)
    assert checker.is_blocked("bad.co") == (False, None)
    # Unrelated benign domains
    assert checker.is_blocked("google.com") == (False, None)
    assert checker.is_blocked("www.wikipedia.org") == (False, None)
    assert checker.check("google.com") == "clean"
    assert "notbad.com" not in checker


def test_normalization_case_whitespace_and_dots():
    checker = BlocklistChecker(["  BAD.COM. ", "Evil.Net."])
    assert checker.is_blocked("A.Bad.COM.") == (True, "bad.com")
    assert checker.is_blocked("  sub.EVIL.net.  ") == (True, "evil.net")
    assert normalize_domain("  A.Bad.COM. ") == "a.bad.com"


def test_empty_and_invalid_inputs():
    checker = BlocklistChecker(["bad.com", "", "   ", "# comment", "."])
    assert len(checker) == 1
    assert checker.is_blocked("") == (False, None)
    assert checker.is_blocked("   ") == (False, None)
    assert checker.is_blocked(".") == (False, None)


def test_is_subdomain_helper():
    assert is_subdomain("a.bad.com", "bad.com") is True
    assert is_subdomain("bad.com", "bad.com") is True
    assert is_subdomain("x.y.bad.com.", "BAD.COM") is True
    assert is_subdomain("notbad.com", "bad.com") is False
    assert is_subdomain("bad.com", "a.bad.com") is False
    assert is_subdomain("", "bad.com") is False


def test_load_file():
    content = "\n".join([
        "# Sample threat feed blocklist",
        "",
        "bad.com",
        "  EVIL.NET.  ",
        "phishing.org # inline comment",
        "0.0.0.0 hosts-malware.io",
        "127.0.0.1 local-bad.dev",
        "*.wildcard-bad.com",
        "bad.com",  # duplicate
    ])
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "blocklist.txt"
        path.write_text(content, encoding="utf-8")

        checker = BlocklistChecker()
        loaded_count = checker.load_file(path)

    assert loaded_count == 6
    assert len(checker) == 6
    assert checker.is_blocked("a.bad.com") == (True, "bad.com")
    assert checker.is_blocked("evil.net") == (True, "evil.net")
    assert checker.is_blocked("login.phishing.org") == (True, "phishing.org")
    assert checker.is_blocked("sub.hosts-malware.io") == (True, "hosts-malware.io")
    assert checker.is_blocked("local-bad.dev") == (True, "local-bad.dev")
    assert checker.is_blocked("deep.wildcard-bad.com") == (True, "wildcard-bad.com")


def test_add_remove_clear():
    checker = BlocklistChecker()
    assert checker.add("bad.com") is True
    assert checker.add("") is False
    assert len(checker) == 1
    assert checker.is_blocked("a.bad.com") == (True, "bad.com")

    assert checker.remove("BAD.COM.") is True
    assert checker.remove("bad.com") is False
    assert checker.is_blocked("a.bad.com") == (False, None)

    checker.load(["one.com", "two.com"])
    assert len(checker) == 2
    checker.clear()
    assert len(checker) == 0
    assert checker.is_blocked("one.com") == (False, None)


def test_thread_safety():
    checker = BlocklistChecker([f"bad{i}.com" for i in range(500)])
    errors: list[Exception] = []

    def reader():
        try:
            for i in range(1000):
                blocked, matched = checker.is_blocked(f"sub.bad{i % 500}.com")
                if not blocked or matched != f"bad{i % 500}.com":
                    raise AssertionError(f"Unexpected result: {(blocked, matched)}")
                clean, _ = checker.is_blocked(f"benign{i}.org")
                if clean:
                    raise AssertionError("Unexpected false positive")
        except Exception as exc:
            errors.append(exc)

    def writer():
        try:
            for i in range(500, 600):
                checker.add(f"bad{i}.com")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(6)] + [
        threading.Thread(target=writer) for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread safety errors: {errors}"
    assert len(checker) == 600


def test_speed_100k():
    stats = benchmark_speed(n_domains=100_000, n_queries=20_000)
    assert stats["n_domains"] == 100_000
    assert stats["n_queries"] == 60_000
    # Must be well below 1.0 ms per query (< 0.05 ms = 50 us easily achieved)
    assert stats["avg_ms"] < 1.0, f"Per-query avg {stats['avg_ms']} ms exceeded 1 ms goal"
    assert stats["exact_hit_us"] < 100.0
    assert stats["subdomain_hit_us"] < 100.0
    assert stats["clean_miss_us"] < 100.0


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for name, obj in list(globals().items()):
        if name.startswith("test_") and callable(obj):
            suite.addTest(unittest.FunctionTestCase(obj))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
