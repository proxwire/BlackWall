import unittest

from blackwall_lab import intel


class IntelValidationTests(unittest.TestCase):
    def test_hash_validation(self):
        value = "A" * 64
        self.assertEqual(intel._validate_hash(value), value.lower())
        for invalid in ("abc", "g" * 64, "a" * 64 + "\nsecret", "a" * 65):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    intel._validate_hash(invalid)

    def test_family_is_short_and_structured(self):
        self.assertEqual(intel._validate_family("Agent Tesla"), "Agent Tesla")
        for invalid in ("", "x" * 65, "family/../../secret", "family\nsecret"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    intel._validate_family(invalid)

    def test_host_normalization(self):
        self.assertEqual(intel._normalize_host("Example.COM.", False), "example.com")
        self.assertEqual(intel._normalize_host("example.com:443", True), "example.com:443")
        self.assertEqual(intel._normalize_host("[2001:db8::1]:443", True), "[2001:db8::1]:443")
        for invalid in ("not-a-fqdn", "example.com/path", "example.com:70000"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    intel._normalize_host(invalid, True)

    def test_ioc_validation_rejects_arbitrary_text(self):
        self.assertEqual(intel._validate_ioc("example.com:443"), "example.com:443")
        self.assertEqual(intel._validate_ioc("https://example.com/a?b=c"), "https://example.com/a?b=c")
        for invalid in ("send this secret", "https://user:pass@example.com/", "https://example.com/\nsecret"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    intel._validate_ioc(invalid)


if __name__ == "__main__":
    unittest.main()
