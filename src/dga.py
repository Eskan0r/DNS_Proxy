"""Layer 3 - DGA / gibberish checker (entropy + length), Chaiyun Suhr

Contract for proxy.py:
    det = DGADetector(threshold=4.0)
    bad, entropy, reason = det.score("xkq9zq2m8f.com")
    # bad=True if entropy > threshold and label long/random -> sinkhole/flag

Requirements:
- Shannon entropy over the left-most label (strip TLD), plus length check.
- Pick threshold by evaluating benign (Tranco) vs malicious (DGA samples).
- Return reason string for logger, e.g. "entropy=4.6 len=12".
"""
import math
from collections import Counter

from src import config


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char)"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _scored_label(domain: str) -> str:
    """Label to score: the one just left of the TLD"""
    labels = [l for l in domain.strip().lower().rstrip(".").split(".") if l]
    if not labels:
        return ""
    return labels[-2] if len(labels) > 1 else labels[0]


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
        entropy = shannon_entropy(label)
        reason = f"entropy={entropy:.2f} len={len(label)}"
        suspicious = len(label) >= self.min_len and entropy > self.threshold
        return suspicious, entropy, reason
