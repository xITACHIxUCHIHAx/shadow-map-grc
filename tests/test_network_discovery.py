import json
import subprocess
import socket
import unittest
from unittest.mock import patch, Mock

from scanner import network_discovery as discovery


SAMPLE_INTERFACES = [
    {
        "name": "eth0",
        "address": "192.168.1.10",
        "prefix_length": 24,
        "network": "192.168.1.0/24",
    }
]


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <address addr="AA:BB:CC:DD:EE:01"
                 addrtype="mac"
                 vendor="Example Router Vendor"/>
        <hostnames>
            <hostname name="router.local" type="PTR"/>
        </hostnames>
    </host>
    <host>
        <status state="up"/>
        <address addr="192.168.1.20" addrtype="ipv4"/>
        <hostnames>
            <hostname name="workstation.local" type="PTR"/>
        </hostnames>
    </host>
    <host>
        <status state="down"/>
        <address addr="192.168.1.30" addrtype="ipv4"/>
    </host>
    <host>
        <status state="up"/>
        <address addr="192.168.1.40" addrtype="ipv4"/>
    </host>
</nmaprun>
"""


class TestNetworkInterfaceEnumeration(unittest.TestCase):

    @patch(
        "scanner.network_discovery._get_default_gateways",
        return_value={"eth0": "192.168.1.1"},
    )
    @patch("scanner.network_discovery.psutil.net_if_stats")
    @patch("scanner.network_discovery.psutil.net_if_addrs")
    def test_returns_active_non_loopback_ipv4_interfaces(
        self, mock_addresses, mock_stats, mock_gateways
    ):
        mock_addresses.return_value = {
            "lo": [
                Mock(
                    family=socket.AF_INET,
                    address="127.0.0.1",
                    netmask="255.0.0.0",
                )
            ],
            "eth0": [
                Mock(
                    family=socket.AF_INET,
                    address="192.168.1.10",
                    netmask="255.255.255.0",
                )
            ],
            "eth1": [
                Mock(
                    family=socket.AF_INET,
                    address="10.0.0.10",
                    netmask="255.255.255.0",
                )
            ],
        }
        mock_stats.return_value = {
            "lo": Mock(isup=True),
            "eth0": Mock(isup=True),
            "eth1": Mock(isup=False),
        }

        result = discovery.get_network_interfaces()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "eth0")
        self.assertEqual(result[0]["address"], "192.168.1.10")
        self.assertEqual(result[0]["prefix_length"], 24)
        self.assertEqual(result[0]["network"], "192.168.1.0/24")
        self.assertEqual(result[0]["gateway"], "192.168.1.1")
        mock_addresses.assert_called_once()
        mock_stats.assert_called_once()
        mock_gateways.assert_called_once()

    @patch(
        "scanner.network_discovery._get_default_gateways",
        return_value={},
    )
    @patch("scanner.network_discovery.psutil.net_if_stats")
    @patch("scanner.network_discovery.psutil.net_if_addrs")
    @patch("scanner.network_discovery.shutil.which", return_value=None)
    def test_interface_discovery_does_not_require_ip_command(
        self, mock_which, mock_addresses, mock_stats, mock_gateways
    ):
        mock_addresses.return_value = {
            "eth0": [
                Mock(
                    family=socket.AF_INET,
                    address="192.168.1.10",
                    netmask="255.255.255.0",
                )
            ]
        }
        mock_stats.return_value = {"eth0": Mock(isup=True)}

        result = discovery.get_network_interfaces()

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "eth0")
        self.assertEqual(result[0]["network"], "192.168.1.0/24")

    @patch("scanner.network_discovery.subprocess.run")
    @patch("scanner.network_discovery.shutil.which", return_value="powershell")
    @patch("scanner.network_discovery.platform.system", return_value="Windows")
    def test_windows_default_gateway_discovery(
        self, mock_system, mock_which, mock_run
    ):
        mock_run.return_value = Mock(
            returncode=0,
            stdout=json.dumps({
                "name": "Ethernet",
                "gateway": "192.168.1.1",
            }),
            stderr="",
        )

        result = discovery._get_default_gateways()

        self.assertEqual(result, {"Ethernet": "192.168.1.1"})
        mock_run.assert_called_once()

    @patch("scanner.network_discovery.subprocess.run")
    @patch("scanner.network_discovery.shutil.which", return_value=None)
    @patch("scanner.network_discovery.platform.system", return_value="Darwin")
    def test_macos_default_gateway_discovery(
        self, mock_system, mock_which, mock_run
    ):
        mock_run.return_value = Mock(
            returncode=0,
            stdout=(
                "   route to: default\n"
                "destination: default\n"
                "    gateway: 192.168.1.1\n"
                "  interface: en0\n"
            ),
            stderr="",
        )

        result = discovery._get_default_gateways()

        self.assertEqual(result, {"en0": "192.168.1.1"})
        mock_run.assert_called_once()

class TestSubnetValidation(unittest.TestCase):

    @patch(
        "scanner.network_discovery.get_network_interfaces",
        return_value=SAMPLE_INTERFACES,
    )
    def test_accepts_subnet_inside_selected_interface(self, mock_interfaces):
        result = discovery.validate_discovery_subnet(
            "192.168.1.0/25",
            "eth0",
        )

        self.assertEqual(str(result), "192.168.1.0/25")

    @patch(
        "scanner.network_discovery.get_network_interfaces",
        return_value=SAMPLE_INTERFACES,
    )
    def test_rejects_subnet_outside_selected_interface(self, mock_interfaces):
        with self.assertRaises(discovery.NetworkDiscoveryError):
            discovery.validate_discovery_subnet(
                "192.168.2.0/24",
                "eth0",
            )

    @patch(
        "scanner.network_discovery.get_network_interfaces",
        return_value=SAMPLE_INTERFACES,
    )
    def test_rejects_unknown_interface(self, mock_interfaces):
        with self.assertRaises(discovery.NetworkDiscoveryError):
            discovery.validate_discovery_subnet(
                "192.168.1.0/24",
                "wlan0",
            )

    def test_rejects_invalid_subnet(self):
        with self.assertRaises(discovery.NetworkDiscoveryError):
            discovery.validate_discovery_subnet(
                "not-a-subnet",
                "eth0",
            )

    @patch(
        "scanner.network_discovery.get_network_interfaces",
        return_value=SAMPLE_INTERFACES,
    )
    def test_rejects_ipv6_subnet(self, mock_interfaces):
        with self.assertRaises(discovery.NetworkDiscoveryError):
            discovery.validate_discovery_subnet(
                "2001:db8::/64",
                "eth0",
            )

    @patch(
        "scanner.network_discovery.get_network_interfaces",
        return_value=SAMPLE_INTERFACES,
    )
    def test_rejects_subnet_above_host_limit(self, mock_interfaces):
        with self.assertRaises(discovery.NetworkDiscoveryError):
            discovery.validate_discovery_subnet(
                "192.168.0.0/20",
                "eth0",
            )


class TestDiscoveryXMLParsing(unittest.TestCase):

    def test_parses_multiple_live_hosts(self):
        devices = discovery.parse_discovery_xml(SAMPLE_NMAP_XML)

        self.assertEqual(len(devices), 3)
        self.assertEqual(
            [device["ip_address"] for device in devices],
            ["192.168.1.1", "192.168.1.20", "192.168.1.40"],
        )

    def test_parses_mac_vendor_and_hostname(self):
        devices = discovery.parse_discovery_xml(SAMPLE_NMAP_XML)

        router = devices[0]

        self.assertEqual(
            router["mac_address"],
            "AA:BB:CC:DD:EE:01",
        )
        self.assertEqual(
            router["vendor"],
            "Example Router Vendor",
        )
        self.assertEqual(
            router["hostnames"],
            ["router.local"],
        )

    def test_normalizes_valid_mac_address(self):
        xml = """<nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.25" addrtype="ipv4"/>
                <address addr="aa:bb:cc:dd:ee:ff"
                         addrtype="mac" vendor="Example Vendor"/>
            </host>
        </nmaprun>"""

        devices = discovery.parse_discovery_xml(xml)

        self.assertEqual(len(devices), 1)
        self.assertEqual(
            devices[0]["mac_address"],
            "AA:BB:CC:DD:EE:FF",
        )
        self.assertEqual(devices[0]["vendor"], "Example Vendor")

    def test_discards_invalid_mac_and_vendor(self):
        xml = """<nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.26" addrtype="ipv4"/>
                <address addr="not-a-mac"
                         addrtype="mac" vendor="Untrusted Vendor"/>
            </host>
        </nmaprun>"""

        devices = discovery.parse_discovery_xml(xml)

        self.assertEqual(len(devices), 1)
        self.assertIsNone(devices[0]["mac_address"])
        self.assertIsNone(devices[0]["vendor"])

    def test_handles_missing_mac_and_hostname(self):
        devices = discovery.parse_discovery_xml(SAMPLE_NMAP_XML)

        device = devices[2]

        self.assertIsNone(device["mac_address"])
        self.assertIsNone(device["vendor"])
        self.assertEqual(device["hostnames"], [])

    def test_skips_invalid_ipv4_addresses(self):
        xml = """<nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.25" addrtype="ipv4"/>
            </host>
            <host>
                <status state="up"/>
                <address addr="999.168.1.25" addrtype="ipv4"/>
            </host>
            <host>
                <status state="up"/>
                <address addr="not-an-ip" addrtype="ipv4"/>
            </host>
            <host>
                <status state="up"/>
                <address addr="2001:db8::1" addrtype="ipv4"/>
            </host>
        </nmaprun>"""

        devices = discovery.parse_discovery_xml(xml)

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip_address"], "192.168.1.25")

    def test_classifies_clear_hostname_indicators(self):
        devices = discovery.parse_discovery_xml(SAMPLE_NMAP_XML)

        self.assertEqual(devices[0]["device_type"], "router")
        self.assertEqual(
            devices[0]["classification_confidence"],
            "medium",
        )
        self.assertIn("router", devices[0]["classification_evidence"][0])

        self.assertEqual(devices[1]["device_type"], "computer")
        self.assertEqual(
            devices[1]["classification_confidence"],
            "medium",
        )
        self.assertIn(
            "workstation",
            devices[1]["classification_evidence"][0],
        )

    def test_no_hostname_defaults_to_unknown(self):
        devices = discovery.parse_discovery_xml(SAMPLE_NMAP_XML)

        device = devices[2]
        self.assertEqual(device["device_type"], "unknown")
        self.assertEqual(device["classification_confidence"], "low")
        self.assertTrue(device["classification_evidence"])

    def test_classifies_additional_device_roles(self):
        cases = {
            "printer.office.local": "printer",
            "cctv-01.local": "camera",
            "webcam.local": "camera",
            "server01.local": "server_nas",
            "srv01.local": "server_nas",
            "laptop-john.local": "computer",
            "desktop.office.local": "computer",
            "pc-01.local": "computer",
        }

        for hostname, expected_type in cases.items():
            with self.subTest(hostname=hostname):
                result = discovery.classify_device({
                    "hostnames": [hostname],
                })
                self.assertEqual(result["device_type"], expected_type)
                self.assertEqual(
                    result["classification_confidence"],
                    "medium",
                )

    def test_ambiguous_hostname_substrings_are_not_classified(self):
        result = discovery.classify_device({
            "hostnames": ["cambridge.local", "printable.local"],
        })

        self.assertEqual(result["device_type"], "unknown")
        self.assertEqual(result["classification_confidence"], "low")

    def test_conflicting_hostname_indicators_remain_unknown(self):
        result = discovery.classify_device({
            "hostnames": ["router-server.local"],
        })

        self.assertEqual(result["device_type"], "unknown")
        self.assertEqual(result["classification_confidence"], "low")
        self.assertTrue(
            any("Conflicting" in item
                for item in result["classification_evidence"])
        )

    def test_vendor_and_service_evidence_identifies_router(self):
        result = discovery.classify_device({
            "hostnames": ["reliance.reliance"],
            "vendor": "Arcadyan",
            "open_ports": [
                {"port": 53, "service": "domain"},
                {"port": 80, "service": "http"},
                {"port": 443, "service": "http"},
                {"port": 8080, "service": "http-proxy"},
                {"port": 8443, "service": "https-alt"},
            ],
        })

        self.assertEqual(result["device_type"], "router")
        self.assertEqual(result["classification_confidence"], "high")

    def test_vendor_only_identification_is_estimated(self):
        cases = {
            "Shenzhen Sdmc Technology": "set_top_box",
            "Intel Corporate": "computer",
        }

        for vendor, expected_type in cases.items():
            with self.subTest(vendor=vendor):
                result = discovery.classify_device({
                    "hostnames": [],
                    "vendor": vendor,
                    "open_ports": [],
                })
                self.assertEqual(result["device_type"], expected_type)
                self.assertEqual(result["classification_confidence"], "low")

    def test_insufficient_evidence_remains_unknown(self):
        result = discovery.classify_device({
            "hostnames": [],
            "vendor": None,
            "open_ports": [],
        })

        self.assertEqual(result["device_type"], "unknown")
        self.assertEqual(result["classification_confidence"], "low")


    def test_vendor_and_generic_services_do_not_prove_device_type(self):
        result = discovery.classify_device({
            "hostnames": [],
            "vendor": "Intel Corporate",
            "open_ports": [
                {"port": 80, "service": "http"},
            ],
        })

        self.assertEqual(result["device_type"], "computer")
        self.assertEqual(result["classification_confidence"], "low")

    def test_vendor_only_evidence_is_never_high_confidence(self):
        for vendor, expected in (
            ("Arcadyan", "router"),
            ("Intel Corporate", "computer"),
            ("Shenzhen SDMC Technology", "set_top_box"),
        ):
            with self.subTest(vendor=vendor):
                result = discovery.classify_device({
                    "hostnames": [],
                    "vendor": vendor,
                    "open_ports": [],
                })

                self.assertEqual(result["device_type"], expected)
                self.assertEqual(
                    result["classification_confidence"], "low"
                )


    def test_rejects_invalid_xml(self):
        with self.assertRaises(discovery.NetworkDiscoveryError):
            discovery.parse_discovery_xml("<nmaprun>")


class TestDiscoveryExecution(unittest.TestCase):

    def setUp(self):
        patcher = patch(
            "scanner.network_discovery.discover_multicast_evidence",
            return_value={"mdns": 0, "ssdp": 0},
        )
        patcher.start()
        self.addCleanup(patcher.stop)


    @patch("scanner.network_discovery.subprocess.run")
    @patch("scanner.network_discovery.validate_discovery_subnet")
    @patch("scanner.network_discovery.find_nmap_executable", return_value="/usr/bin/nmap")
    def test_uses_two_stage_discovery_and_service_scan(
        self,
        mock_which,
        mock_validate,
        mock_run,
    ):
        mock_validate.return_value = (
            __import__("ipaddress").ip_network("192.168.1.0/24"),
            {"name": "eth0", "address": "192.168.1.10"},
        )

        service_xml = '''<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="Example HTTP"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="closed"/>
                        <service name="https"/>
                    </port>
                    <port protocol="udp" portid="53">
                        <state state="open"/>
                        <service name="domain"/>
                    </port>
                </ports>
            </host>
        </nmaprun>'''

        mock_run.side_effect = [
            Mock(returncode=0, stdout=SAMPLE_NMAP_XML, stderr=""),
            Mock(returncode=0, stdout=service_xml, stderr=""),
        ]

        result = discovery.discover_hosts(
            "192.168.1.0/24",
            "eth0",
            authorized=True,
        )

        self.assertEqual(mock_run.call_count, 2)

        discovery_command = mock_run.call_args_list[0].args[0]
        service_command = mock_run.call_args_list[1].args[0]

        self.assertIn("-e", discovery_command)
        self.assertEqual(
            discovery_command[discovery_command.index("-e") + 1],
            "eth0",
        )
        self.assertIn("-sn", discovery_command)

        self.assertIn("-e", service_command)
        self.assertEqual(
            service_command[service_command.index("-e") + 1],
            "eth0",
        )
        self.assertIn("-sT", service_command)
        self.assertIn("--top-ports", service_command)
        self.assertEqual(
            service_command[service_command.index("--top-ports") + 1],
            "100",
        )
        self.assertIn("-sV", service_command)
        self.assertIn("--version-light", service_command)
        self.assertNotIn("-p-", service_command)

        self.assertEqual(
            service_command[-3:],
            ["192.168.1.1", "192.168.1.20", "192.168.1.40"],
        )
        self.assertEqual(result["devices_found"], 3)
        self.assertEqual(result["interface"], "eth0")
        self.assertEqual(
            result["scan_type"],
            "host_discovery_and_top_100_tcp_service_scan",
        )
        self.assertEqual(result["devices"][0]["open_ports"][0]["port"], 80)
        self.assertEqual(
            result["devices"][0]["open_ports"][0]["service"],
            "http",
        )
        self.assertEqual(len(result["devices"][0]["open_ports"]), 1)


    def test_rejects_discovery_without_explicit_authorization(self):
        with patch(
            "scanner.network_discovery.find_nmap_executable"
        ) as mock_which:
            with self.assertRaises(discovery.NetworkDiscoveryError):
                discovery.discover_hosts(
                    "192.168.1.0/24",
                    "eth0",
                )

            mock_which.assert_not_called()

    @patch("scanner.network_discovery.validate_discovery_subnet")
    @patch("scanner.network_discovery.find_nmap_executable", return_value="/usr/bin/nmap")
    @patch("scanner.network_discovery.subprocess.run")
    def test_accepts_valid_timeout_boundaries(
        self,
        mock_run,
        mock_which,
        mock_validate,
    ):
        mock_validate.return_value = (
            __import__("ipaddress").ip_network("192.168.1.0/24"),
            {"name": "eth0", "address": "192.168.1.10"},
        )
        mock_run.return_value = Mock(
            returncode=0,
            stdout=SAMPLE_NMAP_XML,
            stderr="",
        )

        for timeout in (1, 600, 1800):
            with self.subTest(timeout=timeout):
                mock_run.reset_mock()

                discovery.discover_hosts(
                    "192.168.1.0/24",
                    "eth0",
                    authorized=True,
                    timeout=timeout,
                )

                self.assertEqual(
                    mock_run.call_args.kwargs["timeout"],
                    timeout,
                )

    def test_rejects_invalid_timeouts_before_nmap_lookup(self):
        invalid_timeouts = (
            0,
            -1,
            1801,
            True,
            False,
            "10",
            None,
            float("nan"),
            float("inf"),
            float("-inf"),
        )

        for timeout in invalid_timeouts:
            with self.subTest(timeout=repr(timeout)):
                with patch(
                    "scanner.network_discovery.find_nmap_executable"
                ) as mock_which:
                    with patch(
                        "scanner.network_discovery.subprocess.run"
                    ) as mock_run:
                        with self.assertRaisesRegex(
                            discovery.NetworkDiscoveryError,
                            "Timeout must be a number",
                        ):
                            discovery.discover_hosts(
                                "192.168.1.0/24",
                                "eth0",
                                authorized=True,
                                timeout=timeout,
                            )

                        mock_which.assert_not_called()
                        mock_run.assert_not_called()

    @patch("scanner.network_discovery.validate_discovery_subnet")
    @patch("scanner.network_discovery.find_nmap_executable", return_value="/usr/bin/nmap")
    @patch("scanner.network_discovery.subprocess.run")
    def test_handles_nmap_timeout(
        self,
        mock_run,
        mock_which,
        mock_validate,
    ):
        mock_validate.return_value = (
            __import__("ipaddress").ip_network("192.168.1.0/24"),
            {"name": "eth0", "address": "192.168.1.10"},
        )
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="nmap",
            timeout=10,
        )

        with self.assertRaisesRegex(
            discovery.NetworkDiscoveryError,
            "timed out",
        ):
            discovery.discover_hosts(
                "192.168.1.0/24",
                "eth0",
                authorized=True,
                timeout=10,
            )

    @patch("scanner.network_discovery.validate_discovery_subnet")
    @patch("scanner.network_discovery.find_nmap_executable", return_value="/usr/bin/nmap")
    @patch("scanner.network_discovery.subprocess.run")
    def test_handles_nmap_nonzero_exit(
        self,
        mock_run,
        mock_which,
        mock_validate,
    ):
        mock_validate.return_value = (
            __import__("ipaddress").ip_network("192.168.1.0/24"),
            {"name": "eth0", "address": "192.168.1.10"},
        )
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Nmap permission error",
        )

        with self.assertRaisesRegex(
            discovery.NetworkDiscoveryError,
            "Nmap permission error",
        ):
            discovery.discover_hosts(
                "192.168.1.0/24",
                "eth0",
                authorized=True,
            )


if __name__ == "__main__":
    unittest.main()
