"""Tests for util functions."""

import unittest

from criminalip.util import _build_full_url, _convert_bool

class UtilTest(unittest.TestCase):
    def test_build_full_url(self):
        expected_url = "https://api.criminalip.io/v1/ip/test/path"
        got_url = _build_full_url("/ip/test/path")
        self.assertEqual(expected_url, got_url)

    def test_convert_bool(self):
        self.assertEqual("false", _convert_bool(False))
        self.assertEqual("true", _convert_bool(True))

if __name__ == "__main__":
    unittest.main()
