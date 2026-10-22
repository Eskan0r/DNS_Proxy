"""Chaiyun : Tranco vs malicious threshold
    TODO: test_entropy_low_benign (google.com), test_entropy_high_dga, test_threshold_eval()
"""

import unittest

from src import config
from src.dga import DGADetector, shannon_entropy

# Sample of popular (Tranco-style) benign names
BENIGN = [
    "google.com", "facebook.com", "wikipedia.org", "microsoftonline.com",
    "cloudflare.com", "amazonaws.com", "stackoverflow.com",
    "githubusercontent.com", "googleusercontent.com", "doubleclick.net",
    "instagram.com", "netflix.com", "openstreetmap.org", "washingtonpost.com",
    "huffingtonpost.com", "nytimes.com", "cloudfront.net", "akamaiedge.net",
    "salesforce.com", "wordpress.com", "mozilla.org", "alibabacloud.com",
    "tripadvisor.com", "bloomberg.com", "theguardian.com",
    "businessinsider.com", "techcrunch.com", "www.google.com",
]

# DGA-style random names
MALICIOUS = [
    "xkq9zq2m8f.com", "qwzxjv8k2plm9.net", "a8f3k2m9x1q7.com",
    "vhtnbzqpwlkd.org", "zx9f3kq7m2v8c1.com", "pxmqzvbtrlwk.net",
    "jf83kd9alq2mz.com", "x7vb2nq9dk4w1ps.biz", "h3k9s8d2fj7alw0.info",
    "q1w2e3r4t5y6u7i8.com", "mzkpxqwvnbtl.com", "lkj2h4g5f6d7s8a9.net",
]


def evaluate(detector, benign, malicious):
    """Return (false_positive_rate, detection_rate)."""
    fp = sum(detector.score(d)[0] for d in benign)
    tp = sum(detector.score(d)[0] for d in malicious)
    return fp / len(benign), tp / len(malicious)


class TestEntropy(unittest.TestCase):
    def test_uniform_string_is_zero(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_empty_string_is_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_known_value(self):
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)


class TestDGADetector(unittest.TestCase):
    def setUp(self):
        self.det = DGADetector()

    def test_defaults_come_from_config(self):
        self.assertEqual(self.det.threshold, config.ENTROPY_THRESHOLD)
        self.assertEqual(self.det.min_len, config.DGA_MIN_LABEL_LEN)

    def test_entropy_low_benign(self):
        bad, entropy, _ = self.det.score("google.com")
        self.assertFalse(bad)
        self.assertLess(entropy, 2.5)

    def test_entropy_high_dga(self):
        bad, entropy, _ = self.det.score("zx9f3kq7m2v8c1.com")
        self.assertTrue(bad)
        self.assertGreater(entropy, config.ENTROPY_THRESHOLD)

    def test_reason_format(self):
        _, _, reason = self.det.score("google.com")
        self.assertEqual(reason, "entropy=1.92 len=6")

    def test_short_label_never_flagged(self):
        self.assertFalse(DGADetector(threshold=0.0).score("xq9z.com")[0])

    def test_subdomain_and_case_and_trailing_dot(self):
        self.assertFalse(self.det.score("WWW.Google.com.")[0])
        self.assertTrue(self.det.score("www.ZX9F3KQ7M2V8C1.com.")[0])

    def test_empty_domain(self):
        self.assertEqual(self.det.score(""), (False, 0.0, "entropy=0.00 len=0"))

    def test_threshold_eval(self):
        """Chosen threshold: few false positives, most DGA names caught."""
        fp_rate, detection = evaluate(self.det, BENIGN, MALICIOUS)
        self.assertLessEqual(fp_rate, 0.05)
        self.assertGreaterEqual(detection, 0.9)

    def test_threshold_tradeoff(self):
        """Raising the threshold trades detection for fewer false positives."""
        loose = evaluate(DGADetector(threshold=3.0), BENIGN, MALICIOUS)
        strict = evaluate(DGADetector(threshold=3.6), BENIGN, MALICIOUS)
        self.assertGreaterEqual(loose[0], strict[0])
        self.assertGreaterEqual(loose[1], strict[1])


if __name__ == "__main__":
    unittest.main()
