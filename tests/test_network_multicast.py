import struct
import unittest
from unittest.mock import patch

from scanner import network_discovery as discovery


def dns_name(value):
    return b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in value.rstrip(".").split(".")
    ) + b"\x00"


def mdns_ptr_response(service):
    owner = dns_name("_services._dns-sd._udp.local")
    target = dns_name(service)
    record = (
        owner
        + struct.pack("!HHIH", 12, 1, 120, len(target))
        + target
    )
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + record


class FakeSocket:
    def __init__(self, response):
        self.response = response
        self.sent = False

    def setsockopt(self, *args):
        pass

    def bind(self, *args):
        pass

    def settimeout(self, *args):
        pass

    def sendto(self, *args):
        pass

    def recvfrom(self, *args):
        if not self.sent:
            self.sent = True
            return self.response, ("192.168.1.20", 5353)
        raise OSError("end mocked response stream")

    def close(self):
        pass


class TestMulticastParsers(unittest.TestCase):

    def test_parses_mdns_dns_sd_ptr_service(self):
        result = discovery.parse_mdns_response(
            mdns_ptr_response("_googlecast._tcp.local")
        )
        self.assertIn("_googlecast._tcp.local", result["services"])

    def test_rejects_truncated_mdns_packet_safely(self):
        result = discovery.parse_mdns_response(b"\x00\x00")
        self.assertEqual(result, {"services": [], "hostnames": []})

    def test_parses_ssdp_headers_case_insensitively(self):
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            b"SERVER: Example UPnP/1.0\r\n\r\n"
        )
        headers = discovery.parse_ssdp_response(response)
        self.assertIn("mediarenderer", headers["st"].lower())
        self.assertEqual(headers["server"], "Example UPnP/1.0")

    def test_maps_ssdp_device_types(self):
        self.assertEqual(
            discovery._ssdp_role_for_headers({
                "st": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
            }),
            "router",
        )
        self.assertEqual(
            discovery._ssdp_role_for_headers({
                "st": "urn:schemas-upnp-org:device:MediaRenderer:1"
            }),
            "smart_tv",
        )
        self.assertEqual(
            discovery._ssdp_role_for_headers({
                "st": "urn:schemas-upnp-org:device:MediaServer:1"
            }),
            "server_nas",
        )


class TestMulticastClassification(unittest.TestCase):

    def test_mdns_smart_tv_hint_is_estimated(self):
        result = discovery.classify_device({
            "hostnames": [],
            "vendor": None,
            "open_ports": [],
            "multicast_hints": [{
                "role": "smart_tv",
                "source": "mdns",
                "description": "Google Cast service",
            }],
        })
        self.assertEqual(result["device_type"], "smart_tv")
        self.assertEqual(result["classification_confidence"], "low")

    def test_independent_mdns_and_ssdp_agreement_is_medium(self):
        result = discovery.classify_device({
            "hostnames": [],
            "vendor": None,
            "open_ports": [],
            "multicast_hints": [
                {
                    "role": "smart_tv",
                    "source": "mdns",
                    "description": "Google Cast service",
                },
                {
                    "role": "smart_tv",
                    "source": "ssdp",
                    "description": "UPnP MediaRenderer",
                },
            ],
        })
        self.assertEqual(result["device_type"], "smart_tv")
        self.assertEqual(result["classification_confidence"], "medium")

    def test_conflicting_multicast_hints_remain_unknown(self):
        result = discovery.classify_device({
            "hostnames": [],
            "vendor": None,
            "open_ports": [],
            "multicast_hints": [
                {
                    "role": "smart_tv",
                    "source": "mdns",
                    "description": "TV service",
                },
                {
                    "role": "router",
                    "source": "ssdp",
                    "description": "Gateway service",
                },
            ],
        })
        self.assertEqual(result["device_type"], "unknown")
        self.assertEqual(result["classification_confidence"], "low")


class TestMulticastCollection(unittest.TestCase):

    @patch("scanner.network_discovery.socket.socket")
    def test_collects_only_responses_from_discovered_devices(self, mock_socket):
        mdns = FakeSocket(mdns_ptr_response("_googlecast._tcp.local"))
        ssdp = FakeSocket(
            b"HTTP/1.1 200 OK\r\n"
            b"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n"
        )
        mock_socket.side_effect = [mdns, ssdp]

        devices = [
            {
                "ip_address": "192.168.1.20",
                "hostnames": [],
                "vendor": None,
                "open_ports": [],
            }
        ]

        counts = discovery.discover_multicast_evidence(
            devices, "192.168.1.10"
        )

        self.assertEqual(counts["mdns"], 1)
        self.assertEqual(counts["ssdp"], 1)
        self.assertEqual(len(devices[0]["multicast_hints"]), 2)
        self.assertTrue(
            any(
                hint["role"] == "smart_tv"
                for hint in devices[0]["multicast_hints"]
            )
        )
        # mDNS must bind and join its multicast group.
        self.assertTrue(any(call.args[0] == 5353 for call in mdns.__dict__.get("bind_calls", [])) is False)
