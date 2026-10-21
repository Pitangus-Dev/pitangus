"""The public-address check behind every admin-supplied destination: IPv6 forms that carry an IPv4 address are judged
by that IPv4, so NAT64 or a mapped address can't reach an internal network."""

import ipaddress
import os
import socket
import unittest
from unittest.mock import patch

import testenv
from pitangus.modules.integrations import notifications
from pitangus.modules.scanning import egress, image
from pitangus.modules.sources import domains
from pitangus.shared.addresses import is_public


class IsPublicTests(unittest.TestCase):
    def test_plain_addresses(self):
        for address in ("8.8.8.8", "2606:4700::1111", "2606:4700::1111%eth0"):
            with self.subTest(address=address):
                self.assertTrue(is_public(address))
        for address in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "::", "fd00::1", "fe80::1%eth0",
                        "2001:db8::1", "", "not-an-address", "10.0.0.1/8"):
            with self.subTest(address=address):
                self.assertFalse(is_public(address))
        self.assertTrue(is_public(ipaddress.ip_address("8.8.8.8")))

    def test_nat64_well_known_prefix_is_judged_by_its_ipv4(self):
        self.assertTrue(is_public("64:ff9b::808:808"))  # 8.8.8.8
        self.assertTrue(is_public("64:ff9b::8.8.8.8"))
        for address in ("64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::c0a8:101", "64:ff9b::"):
            with self.subTest(address=address):
                self.assertTrue(ipaddress.ip_address(address).is_global)  # what ipaddress says, and why this exists
                self.assertFalse(is_public(address))

    def test_nat64_local_use_prefix_is_never_public(self):
        # RFC 8215: the operator decides where the IPv4 sits, so there is no reliable way to read it.
        for address in ("64:ff9b:1::808:808", "64:ff9b:1::a00:1", "64:ff9b:1:808:8::"):
            with self.subTest(address=address):
                self.assertFalse(is_public(address))

    def test_ipv4_mapped_is_judged_by_its_ipv4(self):
        self.assertTrue(is_public("::ffff:8.8.8.8"))
        for address in ("::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254"):
            with self.subTest(address=address):
                self.assertFalse(is_public(address))

    def test_ipv4_compatible_is_never_public(self):
        for address in ("::8.8.8.8", "::10.0.0.1", "::a00:1"):
            with self.subTest(address=address):
                self.assertFalse(is_public(address))

    def test_6to4_and_teredo_stay_refused_whatever_they_embed(self):
        # ipaddress already refuses both ranges; the embedded IPv4 is checked too in case a Python version stops.
        cases = {"2002:808:808::1": "8.8.8.8", "2002:a00:1::1": "10.0.0.1",
                 "2001:0:4136:e378:8000:63bf:f7f7:f7f7": "8.8.8.8", "2001:0:4136:e378:8000:63bf:f5ff:fffe": "10.0.0.1"}
        for address, embedded in cases.items():
            ip = ipaddress.ip_address(address)
            with self.subTest(address=address):
                self.assertEqual(str(ip.sixtofour or ip.teredo[1]), embedded)
                self.assertFalse(is_public(address))
        with patch.object(ipaddress.IPv6Address, "is_global", True):
            self.assertFalse(is_public("2002:a00:1::1"))
            self.assertFalse(is_public("2001:0:4136:e378:8000:63bf:f5ff:fffe"))
            self.assertTrue(is_public("2002:808:808::1"))


def resolving(address):
    return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 443, 0, 0))]


class CallersTests(unittest.TestCase):
    """Every SSRF check refuses a name that DNS64 answers with an internal IPv4."""

    def test_each_check_refuses_a_nat64_address_of_an_internal_network(self):
        internal, outside = resolving("64:ff9b::a00:1"), resolving("64:ff9b::808:808")
        with patch.dict(os.environ, testenv.base(), clear=True):
            with patch("socket.getaddrinfo", return_value=internal):
                with self.assertRaises(domains.DomainError):
                    domains.public_address("intranet.example.com")
                with self.assertRaises(image.ImageError):
                    image.check_registry_address("registry.example.com")
                with self.assertRaises(notifications.NotificationError):
                    notifications.check_url("webhook", "https://hooks.example.com/x")
            with patch("socket.getaddrinfo", return_value=outside):
                self.assertEqual(domains.public_address("example.com"), "64:ff9b::808:808")
                self.assertEqual(image.check_registry_address("registry.example.com"), {"registry.example.com": "64:ff9b::808:808"})
                self.assertEqual(notifications.check_url("webhook", "https://hooks.example.com/x"), "https://hooks.example.com/x")

    def test_the_egress_echo_must_answer_a_public_address(self):
        with patch.dict(os.environ, testenv.base(), clear=True), patch.object(egress, "_fetch", return_value=b"64:ff9b::a00:1"), \
                self.assertRaises(egress.EgressError):
            egress.detect(None, by="admin")  # refused before anything is stored


if __name__ == "__main__":
    unittest.main()
