"""Chaiyun: DGA detector tests - entropy, length, and Tranco vs malicious samples."""
import random
import unittest

from src import config
from src.dga import DGADetector, shannon_entropy

BENIGN = [
    "google.com", "facebook.com", "wikipedia.org", "cloudflare.com",
    "amazonaws.com", "instagram.com", "netflix.com", "mozilla.org",
    "bloomberg.com", "www.google.com",
]
MALICIOUS = [
    "qwzxjv8k2plm9.net", "a8f3k2m9x1q7.com", "vhtnbzqpwlkd.org",
    "zx9f3kq7m2v8c1.com", "pxmqzvbtrlwk.net", "jf83kd9alq2mz.com",
    "x7vb2nq9dk4w1ps.biz", "h3k9s8d2fj7alw0.info", "q1w2e3r4t5y6u7i8.com",
    "lkj2h4g5f6d7s8a9.net",
]


def load_sample(name):
    """Domains from data/<name>, one per line; None if the file is missing."""
    path = config.DATA_DIR / name
    if not path.exists():
        return None
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def rates(detector, benign, malicious):
    """Return (false_positive_rate, detection_rate)."""
    fp = sum(detector.score(d)[0] for d in benign) / len(benign)
    tp = sum(detector.score(d)[0] for d in malicious) / len(malicious)
    return fp, tp


class TestEntropy(unittest.TestCase):
    def test_same_char_is_zero(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_empty_is_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_four_distinct_chars(self):
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)


class TestDGADetector(unittest.TestCase):
    def setUp(self):
        self.det = DGADetector()

    def test_entropy_low_benign(self):
        bad, entropy, _ = self.det.score("google.com")
        self.assertFalse(bad)
        self.assertLess(entropy, 2.5)

    def test_entropy_high_dga(self):
        bad, entropy, _ = self.det.score("zx9f3kq7m2v8c1.com")
        self.assertTrue(bad)
        self.assertGreater(entropy, config.ENTROPY_THRESHOLD)

    def test_reason_string(self):
        self.assertEqual(self.det.score("google.com")[2], "entropy=1.92 len=6")

    def test_short_label_not_flagged(self):
        self.assertFalse(DGADetector(threshold=0.0).score("xq9z.com")[0])

    def test_case_subdomain_trailing_dot(self):
        self.assertFalse(self.det.score("WWW.Google.com.")[0])
        self.assertTrue(self.det.score("www.ZX9F3KQ7M2V8C1.com.")[0])

    def test_multi_part_suffix(self):
        self.assertTrue(self.det.score("zx9f3kq7m2v8c1.co.uk")[0])
        self.assertTrue(self.det.score("www.zx9f3kq7m2v8c1.com.au")[0])
        self.assertFalse(self.det.score("bbc.co.uk")[0])

    def test_punycode_skipped(self):
        self.assertEqual(
            self.det.score("xn--mnchen-3ya.de"),
            (False, 0.0, "punycode label, skipped"),
        )
        self.assertFalse(self.det.score("xn--zx9f3kq7m2v8c1.com")[0])

    def test_empty_domain(self):
        self.assertEqual(self.det.score(""), (False, 0.0, "entropy=0.00 len=0"))

    def test_small_sample(self):
        fp, tp = rates(self.det, BENIGN, MALICIOUS)
        self.assertLessEqual(fp, 0.05)
        self.assertGreaterEqual(tp, 0.9)


class TestRealData(unittest.TestCase):
    """Tranco sample (benign) vs 360 Netlab DGA sample (malicious) in data/."""

    @classmethod
    def setUpClass(cls):
        cls.benign = load_sample("tranco_sample.txt")
        cls.malicious = load_sample("dga_sample.txt")
        if cls.benign is None or cls.malicious is None:
            raise unittest.SkipTest("data/ samples not found")

    def test_full_sample(self):
        fp, tp = rates(DGADetector(), self.benign, self.malicious)
        print(f"\nFP {fp:.1%}, detection {tp:.1%} "
              f"({len(self.benign)} benign, {len(self.malicious)} DGA)")
        self.assertLessEqual(fp, 0.05)
        self.assertGreater(tp, fp)

    def test_both_halves_agree(self):
        """Each half of the samples should give a similar result."""
        b, m = len(self.benign) // 2, len(self.malicious) // 2
        first = rates(DGADetector(), self.benign[:b], self.malicious[:m])
        second = rates(DGADetector(), self.benign[b:], self.malicious[m:])
        self.assertLessEqual(max(first[0], second[0]), 0.05)
        self.assertAlmostEqual(first[1], second[1], delta=0.1)

    @unittest.skip("Remove this line to re-run the threshold search")
    def test_holdout_tuning(self):
        """Tune on one half, report on the other, so the number isn't optimistic."""
        def halves(items):
            items = items[:]
            random.Random(0).shuffle(items)
            mid = len(items) // 2
            return items[:mid], items[mid:]

        benign_tune, benign_hold = halves(self.benign)
        mal_tune, mal_hold = halves(self.malicious)

        # thresholds 2.8 - 3.85 in steps of 0.05, with a few min lengths
        candidates = [(t / 20, n) for t in range(56, 78) for n in (8, 10, 12)]
        tuned = {c: rates(DGADetector(*c), benign_tune, mal_tune) for c in candidates}
        # best detection among settings with at most 2% false positives
        best = max((c for c in candidates if tuned[c][0] <= 0.02),
                   key=lambda c: tuned[c][1])

        fp, tp = rates(DGADetector(*best), benign_hold, mal_hold)
        print(f"\ntuned on half: threshold={best[0]} min_len={best[1]}; "
              f"held-out FP {fp:.1%}, detection {tp:.1%}")
        self.assertLessEqual(fp, 0.05)


if __name__ == "__main__":
    unittest.main()
