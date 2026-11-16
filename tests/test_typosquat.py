"""Lookalike contract, legitimate-name exclusions, and suffix handling."""
import pytest

from src.typosquat import TyposquatChecker, levenshteinFullMatrix


def test_distance():
    assert levenshteinFullMatrix("", "abc") == 3
    assert levenshteinFullMatrix("kitten", "sitting") == 3
    assert levenshteinFullMatrix("paypal", "paypal") == 0


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
