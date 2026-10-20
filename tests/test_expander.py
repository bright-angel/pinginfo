import unittest

from pinginfo.expander import (
    ExpandError,
    classify_token,
    count_cidr,
    count_token,
    expand_all,
    expand_cidr,
    expand_ipv4_range,
    expand_ipv4_wildcard,
    format_hosts,
    preview_token,
)


class ExpanderTest(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify_token("8.8.8.8"), "ipv4")
        self.assertEqual(classify_token("::1"), "ipv6")
        self.assertEqual(classify_token("www.baidu.com"), "hostname")
        self.assertEqual(classify_token("192.168.1.0/30"), "cidr")
        self.assertEqual(classify_token("192.168.1.1-20"), "wildcard")
        self.assertEqual(classify_token("10.0.0.1-10.0.0.5"), "v4range")
        self.assertEqual(classify_token("192.168.1.*"), "wildcard")
        self.assertEqual(classify_token("10.0.0.1-10"), "wildcard")
        self.assertEqual(classify_token("1.1.01.1"), "invalid")

    def test_cidr_v4(self):
        hosts = expand_cidr("192.168.1.0/30")
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(expand_cidr("10.0.0.1/32"), ["10.0.0.1"])

    def test_cidr_too_large(self):
        with self.assertRaises(ExpandError):
            expand_cidr("10.0.0.0/8")
        with self.assertRaises(ExpandError):
            expand_cidr("2001:db8::/64")

    def test_range(self):
        self.assertEqual(
            expand_ipv4_range("192.168.1.1-3"),
            ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
        )
        self.assertEqual(
            expand_ipv4_range("10.0.0.1-10.0.0.2"),
            ["10.0.0.1", "10.0.0.2"],
        )

    def test_wildcard(self):
        hosts = expand_ipv4_wildcard("10.0.0.1-2")
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(len(expand_ipv4_wildcard("192.168.1.0-3")), 4)

    def test_expand_all_mixed(self):
        text = """
        8.8.8.8
        1.1.1.1, 1.1.1.1
        192.168.0.0/30
        www.example.com
        1.1.01.1
        """
        hosts, invalid, _warnings = expand_all(text)
        self.assertIn("8.8.8.8", hosts)
        self.assertIn("1.1.1.1", hosts)
        self.assertIn("192.168.0.1", hosts)
        self.assertIn("www.example.com", hosts)
        self.assertEqual(hosts.count("1.1.1.1"), 1)
        self.assertTrue(any("1.1.01.1" in item for item in invalid))

    def test_format_hosts(self):
        formatted = format_hosts("8.8.8.8, 8.8.8.8\n1.1.1.1")
        self.assertEqual(formatted, "8.8.8.8\n1.1.1.1")

    def test_large_wildcard_rejected(self):
        with self.assertRaises(ExpandError):
            expand_ipv4_wildcard("10.*.*.*")

    def test_count_without_materializing(self):
        self.assertEqual(count_cidr("192.168.1.0/24"), 254)
        self.assertEqual(count_token("8.8.8.8"), 1)
        self.assertEqual(count_token("192.168.1.1-20"), 20)
        spec = preview_token("10.0.0.0/30")
        self.assertEqual(spec.count, 2)
        self.assertIsNone(spec.error)
        bad = preview_token("10.0.0.0/8")
        self.assertEqual(bad.count, 0)
        self.assertIsNotNone(bad.error)


if __name__ == "__main__":
    unittest.main()
