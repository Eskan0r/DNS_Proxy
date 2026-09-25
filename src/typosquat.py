"""Layer 2 - Typosquat / lookalike checker, Megan Tran.

Contract for proxy.py:
    checker = TyposquatChecker(top_domains=["paypal.com", ...])  # top 200 real list
    hit, target, dist = checker.is_lookalike("paypa1.com")
    # hit=True, target="paypal.com", dist=1 -> sinkhole/flag

Requirements:
- Build data/top200.txt (Tranco/manual top real domains).
- Implement edit (Levenshtein) distance, tune threshold (config.TYPO_MAX_DISTANCE).
- Must handle subdomains: check registrable label, not full 'mail.paypa1.com' naively.
- TODO: FP test on benign Tranco sample, report threshold tradeoff.
"""
# TODO: implement levenshtein(a, b) helper (no heavy deps).


class TyposquatChecker:
    """TODO: implement"""

    def __init__(self, top_domains: list[str] | None = None):
        # TODO: self.top = [normalize...] or load data/top200.txt
        raise NotImplementedError

    def load_top_file(self, path: str) -> int:
        """Load top-200 file, return count."""
        raise NotImplementedError

    def is_lookalike(self, domain: str) -> tuple[bool, str | None, int | None]:
        """Return (True, 'paypal.com', 1) if within threshold, else (False, None, None).
        TODO: compare base domain vs each top domain with early-exit if len diff > threshold.
        """
        raise NotImplementedError
