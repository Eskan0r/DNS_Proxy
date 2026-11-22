"""Lookalike detection using registrable labels and edit distance (Megan Tran)."""
from pathlib import Path

import tldextract

from . import config
from .utils import normalize_domain

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def levenshteinFullMatrix(str1: str, str2: str) -> int:
    """Levenshtein distance with two rows of working memory."""
    previous = list(range(len(str2) + 1))
    for i, first in enumerate(str1, 1):
        current = [i]
        for j, second in enumerate(str2, 1):
            current.append(min(current[-1] + 1, previous[j] + 1,
                               previous[j - 1] + (first != second)))
        previous = current
    return previous[-1]


def _registered(domain: str) -> tuple[str, str]:
    extracted = _extract(normalize_domain(domain).encode("idna").decode("ascii"))
    return extracted.top_domain_under_public_suffix, extracted.domain


class TyposquatChecker:
    """Compare queries against a reusable set of protected registrable domains.

    Exact protected names and their children are clean. Identical labels on
    another suffix are not treated as spelling mistakes. Short labels are
    skipped to reduce accidental matches. This is a heuristic, not ownership
    verification, and thresholds still need representative evaluation.
    """

    def __init__(self, top_domains: list[str] | None = None, *,
                 max_distance: int = config.TYPO_MAX_DISTANCE,
                 min_label_len: int = 5):
        if max_distance < 0 or min_label_len < 1:
            raise ValueError("Invalid typosquat thresholds")
        self.max_distance = max_distance
        self.min_label_len = min_label_len
        self._load(top_domains or [])

    def _load(self, domains):
        self.top = sorted({registered for raw in domains if raw
                           if (registered := _registered(raw)[0])})
        self._protected = frozenset(self.top)
        self._targets = {target: _registered(target)[1] for target in self.top}
        self._labels = frozenset(self._targets.values())

    def load_top_file(self, path: str) -> int:
        """Replace protected domains from a file and return the unique count."""
        domains = [line.split("#", 1)[0].strip()
                   for line in Path(path).read_text(encoding="utf-8-sig").splitlines()]
        self._load(domains)
        return len(self.top)

    def is_lookalike(self, domain: str) -> tuple[bool, str | None, int | None]:
        registered, label = _registered(domain)
        if (not registered or registered in self._protected or label in self._labels
                or len(label) < self.min_label_len):
            return False, None, None
        best = None
        for target, target_label in self._targets.items():
            if len(target_label) < self.min_label_len or abs(len(label) - len(target_label)) > self.max_distance:
                continue
            distance = levenshteinFullMatrix(label, target_label)
            if 0 < distance <= self.max_distance and (best is None or distance < best[0]):
                best = (distance, target)
        if best is None:
            return False, None, None
        return True, best[1], best[0]
