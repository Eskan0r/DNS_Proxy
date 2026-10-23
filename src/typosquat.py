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

import config
import top200Domains as Domains

def levenshteinFullMatrix(str1, str2):
    m = len(str1)
    n = len(str2)

    # Initialize a matrix to store the edit distances
    dp = [[0 for _ in range(n + 1)] for _ in range(m + 1)]

    # Initialize the first row and column with values from 0 to m and 0 to n respectively
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    # Fill the matrix using dynamic programming to compute edit distances
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if str1[i - 1] == str2[j - 1]:
                # Characters match, no operation needed
                dp[i][j] = dp[i - 1][j - 1]
            else:
                # Characters don't match, choose minimum cost among insertion, deletion, or substitution
                dp[i][j] = 1 + min(dp[i][j - 1], dp[i - 1][j], dp[i - 1][j - 1])

    # Return the edit distance between the strings
    return dp[m][n]

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
        distance = levenshteinFullMatrix(str1, str2)
        if distance <= config.TYPO_MAX_DISTANCE:
            return True, str2, distance
        return False, None, None
