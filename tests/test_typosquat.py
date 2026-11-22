"""Lookalike contract, legitimate-name exclusions, and suffix handling."""
import pytest

from src.typosquat import TyposquatChecker, levenshteinFullMatrix


def test_distance():
    assert levenshteinFullMatrix("", "abc") == 3
    assert levenshteinFullMatrix("kitten", "sitting") == 3
    assert levenshteinFullMatrix("paypal", "paypal") == 0


@pytest.mark.parametrize("candidate,distance", [
    ("paypal.com", 0),
    ("paypa1.com", 1),
    ("paypal1.com", 1),
    ("paypl.com", 1),
    ("pypa1.com", 2),
])
def test_teammate_edit_distance_cases(candidate, distance):
    """Preserve Megan's a6d30ea identity/substitution/insertion/deletion cases."""
    assert levenshteinFullMatrix("paypal.com", candidate) == distance


@pytest.mark.parametrize("contents,expected", [
    ("google.com\npaypal.com\n", (True, "paypal.com", 1)),
    ("google.com\nyahoo.com\n", (False, None, None)),
])
def test_teammate_file_lookup_cases(tmp_path, contents, expected):
    """Adapt the standalone file-lookup tests to the integrated checker API."""
    path = tmp_path / "protected.txt"
    path.write_text(contents)
    checker = TyposquatChecker()
    assert checker.load_top_file(str(path)) == 2
    assert checker.is_lookalike("paypa1.com") == expected


@pytest.mark.parametrize("domain", ["paypa1.com", "mail.PAYPA1.com.", "paypa1.co.uk"])
def test_lookalike_registrable_label(domain):
    checker = TyposquatChecker(["paypal.com"])
    assert checker.is_lookalike(domain) == (True, "paypal.com", 1)


@pytest.mark.parametrize("domain", ["paypal.com", "mail.paypal.com", "paypal.co.uk", "google.com", "a.com", ""])
def test_legitimate_and_short_names(domain):
    checker = TyposquatChecker(["paypal.com", "google.com", "b.com"])
    assert checker.is_lookalike(domain) == (False, None, None)


def test_loader_replaces_and_normalizes(tmp_path):
    path = tmp_path / "top.txt"
    path.write_text("PAYPAL.COM.\npaypal.com\n# comment\ngoogle.com # trusted\n")
    checker = TyposquatChecker(["old.example.com"])
    assert checker.load_top_file(str(path)) == 2
    assert checker.top == ["google.com", "paypal.com"]
    assert checker.is_lookalike("gooogle.com")[0]


def test_no_match_and_threshold():
    checker = TyposquatChecker(["paypal.com"], max_distance=0)
    assert not checker.is_lookalike("paypa1.com")[0]
    assert not TyposquatChecker(["paypal.com"]).is_lookalike("unrelated.org")[0]
