"""Strict, offline unit tests: CI never replaces missing real data with fixtures."""
import hashlib
import unittest
import pinned_hagezi as h

GOOD = b"# official test fixture only\n*.casino.example\nsports.example\nbet.example\n"
def blob(b: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()

class PinnedCatalogTests(unittest.TestCase):
    def inspect(self, data: bytes):
        return h.inspect_catalog(data, expected_blob=blob(data), expected_size=len(data), minimum=3)

    def test_exact_git_blob_and_distinct_valid_domains(self):
        e = self.inspect(GOOD)
        self.assertEqual(e["domain_count"], 3)
        self.assertEqual(e["comment_lines"], 1)
        self.assertEqual(e["sha256"], hashlib.sha256(GOOD).hexdigest())
        self.assertFalse(e["compatible_with_dns_motor_verified"])
        self.assertFalse(e["production_install_authorized"])
        self.assertFalse(e["publish_release_authorized"])

    def test_must_match_official_git_blob(self):
        with self.assertRaisesRegex(ValueError, "Git blob"):
            h.inspect_catalog(GOOD, expected_blob="0"*40, expected_size=len(GOOD), minimum=3)

    def test_must_match_official_length(self):
        with self.assertRaisesRegex(ValueError, "length"):
            h.inspect_catalog(GOOD, expected_blob=blob(GOOD), expected_size=len(GOOD)+1, minimum=3)

    def test_rejects_corruption_and_duplicates(self):
        for suffix in [
            b"\0", b"\r", b"example", b"*.bad..example\n",
            b"*.casino.example\n", b"0.0.0.0 not-a-domain\n",
            b"localhost\n", b"*.bad_domain.example\n",
            b"UPPER.EXAMPLE\n", b"*.bad-.example\n",
        ]:
            with self.subTest(suffix=suffix):
                with self.assertRaises(ValueError):
                    self.inspect(GOOD + suffix)

    def test_rejects_partial_source_even_if_blob_matches(self):
        data = b"casino.example\n"
        with self.assertRaisesRegex(ValueError, "incomplete"):
            h.inspect_catalog(data, blob(data), len(data), minimum=3)

    def test_rejects_million_scale_overbound(self):
        data = b"example.org\n" * 10
        with self.assertRaises(ValueError):
            h.inspect_catalog(data, blob(data), len(data), minimum=3)

if __name__ == "__main__":
    unittest.main()
