import unittest

from pinginfo.icmp import bare_ip, split_zone


class IcmpHelpersTest(unittest.TestCase):
    def test_split_zone_index(self):
        host, zone = split_zone("fe80::1%2")
        self.assertEqual(host, "fe80::1")
        self.assertEqual(zone, 2)

    def test_split_zone_none(self):
        host, zone = split_zone("2001:db8::1")
        self.assertEqual(host, "2001:db8::1")
        self.assertEqual(zone, 0)

    def test_bare_ip(self):
        self.assertEqual(bare_ip("fe80::1%en0"), "fe80::1")
        self.assertEqual(bare_ip("8.8.8.8"), "8.8.8.8")
