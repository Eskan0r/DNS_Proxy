import unittest
from unittest.mock import patch, mock_open

# Assuming your provided code is saved in a file named typosquat.py
import typosquat

class test_typosquat(unittest.TestCase):

    # ==========================================
    # Tests for levenshteinFullMatrix
    # ==========================================
    def test_levenshtein_identical(self):
        """Test strings that are exactly the same (distance 0)."""
        dist = typosquat.levenshteinFullMatrix("paypal.com", "paypal.com")
        self.assertEqual(dist, 0)

    def test_levenshtein_substitution(self):
        """Test strings with a 1-character substitution."""
        dist = typosquat.levenshteinFullMatrix("paypal.com", "paypa1.com")
        self.assertEqual(dist, 1)

    def test_levenshtein_insertion(self):
        """Test strings requiring a 1-character insertion."""
        dist = typosquat.levenshteinFullMatrix("paypal.com", "paypal1.com")
        self.assertEqual(dist, 1)

    def test_levenshtein_deletion(self):
        """Test strings requiring a 1-character deletion."""
        dist = typosquat.levenshteinFullMatrix("paypal.com", "paypl.com")
        self.assertEqual(dist, 1)

    def test_levenshtein_multiple_differences(self):
        """Test strings that exceed the threshold."""
        dist = typosquat.levenshteinFullMatrix("paypal.com", "pypa1.com")
        self.assertEqual(dist, 2)

    # ==========================================
    # Tests for TyposquatChecker
    # ==========================================
    @patch('builtins.open', new_callable=mock_open, read_data="google.com\npaypal.com\n")
    def test_checker_init(self, mock_file):
        """Test initialization sets URL and attempts to load the file."""
        checker = typosquat.TyposquatChecker("paypa1.com")
        self.assertEqual(checker.URL, "paypa1.com")
        mock_file.assert_called_once_with("data/top200Domains.txt", "r")

    @patch('builtins.open', new_callable=mock_open, read_data="google.com\npaypal.com\n")
    def test_load_top_file_lookalike_found(self, mock_file):
        """Test reading a file where a lookalike is matched (early exit)."""
        checker = typosquat.TyposquatChecker("paypa1.com")
        # Re-run load_top_file to capture the specific return value
        result = checker.load_top_file("dummy_path.txt")
        
        # 'google.com' (dist 9) is skipped, 'paypal.com' (dist 1) matches and returns the distance
        self.assertEqual(result, 1) 

    @patch('builtins.open', new_callable=mock_open, read_data="google.com\nyahoo.com\n")
    def test_load_top_file_no_lookalike(self, mock_file):
        """Test reading a file where no lookalike is found (returns None)."""
        checker = typosquat.TyposquatChecker("paypa1.com")
        result = checker.load_top_file("dummy_path.txt")
        
        self.assertIsNone(result)

    @patch('builtins.open', new_callable=mock_open, read_data="dummy.com\n")
    def test_is_lookalike_true(self, mock_file):
        """Test the is_lookalike helper returning True with target and distance."""
        checker = typosquat.TyposquatChecker("paypa1.com")
        
        hit, target, dist = checker.is_lookalike("paypal.com")
        self.assertTrue(hit)
        self.assertEqual(target, "paypal.com")
        self.assertEqual(dist, 1)

    @patch('builtins.open', new_callable=mock_open, read_data="dummy.com\n")
    def test_is_lookalike_false(self, mock_file):
        """Test the is_lookalike helper returning False with Nones."""
        checker = typosquat.TyposquatChecker("google.com")
        
        hit, target, dist = checker.is_lookalike("paypal.com")
        self.assertFalse(hit)
        self.assertIsNone(target)
        self.assertIsNone(dist)

if __name__ == '__main__':
    unittest.main()