import inspect
import unittest

from reporting.pdf_generator import build_firewall_pdf


class FirewallPDFTests(unittest.TestCase):
    def setUp(self):
        self.scan = {
            "id": 7,
            "target": "192.0.2.10",
            "status": "completed",
            "started_at": "2026-11-04 10:00:00",
            "finished_at": "2026-11-04 10:00:03",
            "duration_seconds": 3.0,
            "error": None,
        }

    def test_generates_valid_pdf_with_firewall_observations(self):
        result = {
            "target": "192.0.2.10",
            "host": "192.0.2.10",
            "resolved_addresses": ["192.0.2.10"],
            "duration_seconds": 2.8,
            "tcp": {
                "ports": [
                    {
                        "address": "192.0.2.10",
                        "port": 80,
                        "state": "open",
                        "duration_seconds": 0.02,
                        "reason": "syn-ack",
                    }
                ],
                "counts": {
                    "open": 1,
                    "closed": 0,
                    "no_response": 0,
                    "indeterminate": 0,
                },
                "interpretation": "Mock TCP interpretation.",
            },
            "services": {
                "items": [
                    {
                        "address": "192.0.2.10",
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "product": "Apache HTTP Server",
                        "version": None,
                        "confidence": "medium",
                        "evidence": ["Explicit Server header: Apache"],
                        "banner": "DO NOT INCLUDE THIS RAW BANNER",
                    }
                ],
                "interpretation": "Mock service interpretation.",
            },
            "https": {
                "checked": True,
                "url": "http://192.0.2.10/",
                "scheme": "http",
                "port": 80,
                "status_code": 200,
                "server": "Apache",
                "headers": {"server": "Apache"},
                "set_cookie": "",
                "error": None,
                "connected_address": "192.0.2.10",
                "application": {
                    "product": "Apache HTTP Server",
                    "version": None,
                },
            },
            "tls": {
                "available": False,
                "error": "TLS not requested for HTTP.",
            },
            "waf": {
                "detected": False,
                "vendor_identification": [],
                "confidence": "unknown",
                "limitation": "Mock WAF limitation.",
            },
            "limitations": ["Mock assessment limitation."],
        }

        pdf = build_firewall_pdf(scan=self.scan, result=result)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)

    def test_generates_pdf_when_observations_are_empty(self):
        result = {
            "target": "192.0.2.10",
            "resolved_addresses": [],
            "tcp": {"ports": [], "counts": {}},
            "services": {"items": []},
            "https": {"checked": False, "headers": {}},
            "tls": {"available": False},
            "waf": {
                "detected": False,
                "vendor_identification": [],
            },
            "limitations": [],
        }

        pdf = build_firewall_pdf(scan=self.scan, result=result)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)

    def test_builder_does_not_read_raw_tcp_banner(self):
        source = inspect.getsource(build_firewall_pdf)

        self.assertNotIn('get("banner")', source)
        self.assertNotIn("get('banner')", source)

    def test_builder_includes_local_firewall_section(self):
        source = inspect.getsource(build_firewall_pdf)

        self.assertIn('result.get("local_firewall")', source)
        self.assertIn("Local Machine Firewall Detection", source)
        self.assertIn("packet filtering or enforcement", source)


    def test_generates_pdf_with_local_firewall_detection(self):
        result = {
            "target": "192.0.2.10",
            "resolved_addresses": ["192.0.2.10"],
            "tcp": {"ports": [], "counts": {}},
            "services": {"items": []},
            "https": {"checked": False, "headers": {}},
            "tls": {"available": False},
            "waf": {"detected": False, "vendor_identification": []},
            "limitations": [],
            "local_firewall": {
                "scope": "Local machine running Shadow Map GRC",
                "platform": "Kali GNU/Linux",
                "operating_system": "Linux",
                "status": "unknown",
                "technologies": [
                    {
                        "name": "nftables",
                        "category": "host firewall",
                        "status": "unknown",
                        "available": True,
                        "evidence": [],
                        "error": "Permission denied",
                    },
                    {
                        "name": "Little Snitch",
                        "category": "third-party host firewall",
                        "status": "not_installed",
                        "available": False,
                        "evidence": [],
                        "error": None,
                    },
                ],
                "service_observations": [
                    {
                        "name": "nftables.service",
                        "source": "systemd",
                        "status": "unknown",
                        "error": "Permission denied",
                    }
                ],
                "limitations": ["Some firewall details require elevated permissions."],
            },
        }

        pdf = build_firewall_pdf(scan=self.scan, result=result)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 1000)


if __name__ == "__main__":
    unittest.main()
