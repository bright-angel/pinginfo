import unittest

from pinginfo.validator import (
    canonical_literal,
    dedupe_key,
    is_hostname,
    is_ipv4,
    is_ipv6,
    is_valid_host,
    literal_family,
)


class ValidatorTest(unittest.TestCase):
    def test_ipv4(self):
        self.assertTrue(is_ipv4("8.8.8.8"))
        self.assertTrue(is_ipv4("0.0.0.0"))
        self.assertFalse(is_ipv4("1.1.01.1"))
        self.assertFalse(is_ipv4("1.1.1.1222"))
        self.assertFalse(is_ipv4("192.168.1"))

    def test_ipv6(self):
        self.assertTrue(is_ipv6("::1"))
        self.assertTrue(is_ipv6("2001:db8::1"))
        self.assertTrue(is_ipv6("fe80::1%en0"))
        self.assertFalse(is_ipv6("2001:db8::1%en0"))
        self.assertFalse(is_ipv6("64:ff9b::192.0.0.1::1"))

    def test_mapped(self):
        self.assertEqual(literal_family("::ffff:192.0.2.1"), "IPv4")
        self.assertEqual(canonical_literal("::ffff:192.0.2.1"), "192.0.2.1")

    def test_hostname(self):
        self.assertTrue(is_hostname("www.apple.com"))
        self.assertTrue(is_hostname("www.baidu.com"))
        self.assertFalse(is_hostname("1.1.1.1"))
        self.assertTrue(is_valid_host("dns.google"))

    def test_dedupe(self):
        self.assertEqual(dedupe_key("2001:0db8::1"), dedupe_key("2001:db8:0:0:0:0:0:1"))
        self.assertEqual(dedupe_key("WWW.Example.COM"), "www.example.com")


if __name__ == "__main__":
    unittest.main()
