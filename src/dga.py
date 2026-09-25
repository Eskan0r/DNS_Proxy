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


def shannon_entropy(s: str) -> float:
    """TODO: implement -p*log2(p) over char freq. Test: 'aaaa'->0.0."""
    raise NotImplementedError


class DGADetector:
    """TODO: implement score()."""

    def __init__(self, threshold: float = 4.0, min_len: int = 12):
        # TODO: store threshold/min_len
        raise NotImplementedError

    def score(self, domain: str) -> tuple[bool, float, str]:
        """Returns (is_suspicious, entropy_value, reason_str).
        TODO: extract first label, compute entropy + len, compare to threshold.
        """
        raise NotImplementedError
