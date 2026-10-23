"""Layer 3 - DGA / gibberish checker (entropy + length), Chaiyun Suhr
"""
import math
from collections import Counter

import tldextract

from src import config

# Offline: uses the bundled Public Suffix List snapshot
_extract = tldextract.TLDExtract(suffix_list_urls=())


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char)"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _scored_label(domain: str) -> str:
    """Registered label, using the Public Suffix List
    'www.x9q.com' -> 'x9q', 'evil.co.uk' -> 'evil'
    """
    return _extract(domain.strip().lower().rstrip(".")).domain


class DGADetector:
    """Flags names whose label is both long enough and high-entropy."""

    def __init__(
        self,
        threshold: float = config.ENTROPY_THRESHOLD,
        min_len: int = config.DGA_MIN_LABEL_LEN,
    ):
        self.threshold = threshold
        self.min_len = min_len

    def score(self, domain: str) -> tuple[bool, float, str]:
        """Returns: (is_suspicious, entropy_value, reason_str)."""
        label = _scored_label(domain)
        if label.startswith("xn--"):  # punycode
            return False, 0.0, "punycode label, skipped"
        entropy = shannon_entropy(label)
        reason = f"entropy={entropy:.2f} len={len(label)}"
        suspicious = len(label) >= self.min_len and entropy > self.threshold
        return suspicious, entropy, reason
