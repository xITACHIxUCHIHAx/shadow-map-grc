import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scanner import wapiti_integration as wapiti


class FakeBudget:
    def __init__(self, maximum=20):
        self.maximum = maximum
        self.used = 0

    @property
    def remaining(self):
        return self.maximum - self.used

    def consume(self):
        if self.remaining <= 0:
            raise RuntimeError("Request budget exhausted")
        self.used += 1


class WapitiOriginTests(unittest.TestCase):
    def test_http_origin(self):
        self.assertEqual(
            wapiti._origin("http://192.168.1.10:8080/path"),
            ("http", "192.168.1.10", 8080),
        )

    def test_https_default_port(self):
        self.assertEqual(
            wapiti._origin("https://example.com/path"),
            ("https", "example.com", 443),
        )

    def test_origin_ignores_path_and_query(self):
        self.assertEqual(
            wapiti._origin("https://example.com/a?b=1"),
            wapiti._origin("https://example.com/another"),
        )

    def test_credentials_are_rejected(self):
        with self.assertRaises(wapiti.WapitiIntegrationError):
            wapiti._origin("https://user:pass@example.com/")

    def test_unsupported_scheme_is_rejected(self):
        with self.assertRaises(wapiti.WapitiIntegrationError):
            wapiti._origin("ftp://example.com/")


class WapitiFindingTests(unittest.TestCase):
    def test_finding_is_sanitized_and_unverified(self):
        payload = SimpleNamespace(
            type="vulnerability",
            category="SQL Injection",
            level=2,
            module="sql",
            parameter="id",
            info="  Possible SQL injection\x00 indicator ",
            wstg="WSTG-INPV-05",
            evil_request=SimpleNamespace(
                url="https://example.com/item?id=123&secret=value",
                method="GET",
            ),
        )

        finding = wapiti._payload_to_finding(payload)

        self.assertEqual(finding["category"], "SQL Injection")
        self.assertEqual(finding["severity"], 2)
        self.assertEqual(finding["path"], "/item")
        self.assertEqual(finding["method"], "GET")
        self.assertEqual(finding["parameter"], "id")
        self.assertNotIn("secret", finding["path"])
        self.assertNotIn("\\x00", finding["information"])
        self.assertEqual(finding["evidence_status"], "unverified")


class WapitiConfigurationTests(unittest.TestCase):
    def test_only_sql_and_xss_get_modules_are_enabled(self):
        self.assertEqual(
            wapiti.ALLOWED_ACTIVE_MODULES,
            {"sql": {"GET"}, "xss": {"GET"}},
        )

    def test_scan_limits_are_bounded(self):
        self.assertEqual(wapiti.MAX_DEPTH, 2)
        self.assertEqual(wapiti.MAX_LINKS_PER_PAGE, 10)
        self.assertEqual(wapiti.MAX_SCAN_SECONDS, 45)


class WapitiAssessmentTests(unittest.TestCase):
    def test_missing_shared_budget_is_rejected(self):
        with self.assertRaises(wapiti.WapitiIntegrationError):
            wapiti.run_wapiti_assessment("https://example.com/", None)

    @patch("scanner.wapiti_integration._run_wapiti")
    def test_success_returns_findings_and_budget_usage(self, mock_run):
        budget = FakeBudget()

        async def fake_run(target, request_budget):
            self.assertEqual(target, "https://example.com/")
            self.assertIs(request_budget, budget)
            request_budget.consume()
            request_budget.consume()
            return [{"category": "XSS", "evidence_status": "unverified"}]

        mock_run.side_effect = fake_run

        result = wapiti.run_wapiti_assessment(
            "https://example.com/",
            budget,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["requests_used"], 2)
        self.assertEqual(result["requests_remaining"], 18)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["verified_vulnerabilities"], 0)

    @patch("scanner.wapiti_integration._run_wapiti")
    def test_failure_after_request_is_partial(self, mock_run):
        budget = FakeBudget()

        async def fake_run(target, request_budget):
            request_budget.consume()
            raise RuntimeError("Mocked scanner failure")

        mock_run.side_effect = fake_run

        result = wapiti.run_wapiti_assessment(
            "https://example.com/",
            budget,
        )

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["requests_used"], 1)
        self.assertEqual(result["requests_remaining"], 19)
        self.assertEqual(result["findings"], [])

    @patch("scanner.wapiti_integration._run_wapiti")
    def test_failure_before_request_is_failed(self, mock_run):
        budget = FakeBudget()

        async def fake_run(target, request_budget):
            raise RuntimeError("Mocked initialization failure")

        mock_run.side_effect = fake_run

        result = wapiti.run_wapiti_assessment(
            "https://example.com/",
            budget,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["requests_used"], 0)
        self.assertEqual(result["requests_remaining"], 20)


if __name__ == "__main__":
    unittest.main()
