from reporting.pdf_generator import build_unified_scan_pdf


def _run():
    return {
        "id": 7,
        "status": "Completed",
        "created_at": "2026-11-18T10:00:00+00:00",
        "finished_at": "2026-11-18T10:01:00+00:00",
    }


def test_unified_pdf_includes_saved_technical_result_sections():
    items = [
        {
            "module": "nmap",
            "target": "192.0.2.10",
            "status": "Completed",
            "result_type": "nmap",
            "result_record_id": 1,
            "technical_result": {
                "scan": {"host_state": "up", "os_match": "Linux"},
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "9.x",
                        "reason": "syn-ack",
                    }
                ],
            },
        },
        {
            "module": "web_security",
            "target": "https://example.test",
            "status": "Completed",
            "result_type": "web_security",
            "result_record_id": 2,
            "technical_result": {
                "status_code": 200,
                "missing_headers": 1,
                "headers": [
                    {
                        "name": "Content-Security-Policy",
                        "present": False,
                        "assessment": "missing",
                        "issue": "Header not returned",
                        "value": "must not be included",
                    }
                ],
                "cookies": [
                    {"secure": True, "httponly": True, "samesite": False}
                ],
                "discovery": {
                    "pages": ["/"],
                    "discovered_urls": ["/", "/login"],
                    "api_endpoints": ["/api"],
                    "forms": [],
                    "limits": {"requests_used": 4},
                },
                "reflected_input_assessment": {
                    "status": "not_run",
                    "checks": [],
                    "requests_used": 0,
                    "verified_vulnerabilities": 0,
                },
                "sql_injection_assessment": {
                    "status": "not_run",
                    "checks": [],
                    "requests_used": 0,
                    "verified_vulnerabilities": 0,
                },
                "request_budget": {
                    "maximum": 20,
                    "used": 4,
                    "remaining": 16,
                },
                "zap_alerts": [{"alert": "must not be rendered"}],
            },
        },
        {
            "module": "threat_intel",
            "target": "203.0.113.10",
            "status": "Completed",
            "result_type": "threat_intel",
            "result_record_id": 3,
            "technical_result": {
                "ip": "203.0.113.10",
                "found": True,
                "ports": [22, 443],
                "hostnames": ["example.test"],
                "tags": ["web"],
                "vulns": ["CVE-2024-12345", "not-a-cve"],
            },
        },
        {
            "module": "firewall",
            "target": "example.test",
            "status": "Completed",
            "result_type": "firewall",
            "result_record_id": 4,
            "technical_result": {
                "tcp": {
                    "counts": {"open": 1, "closed": 1},
                    "ports": [
                        {
                            "address": "192.0.2.20",
                            "port": 443,
                            "state": "open",
                            "protocol": "tcp",
                        }
                    ],
                },
                "services": {"items": []},
                "https": {"checked": True, "scheme": "https", "status_code": 200},
                "tls": {"available": True, "version": "TLSv1.3"},
                "waf": {"detected": False, "confidence": "unknown"},
            },
        },
    ]

    pdf = build_unified_scan_pdf(
        run=_run(),
        targets=["192.0.2.10", "https://example.test"],
        modules=["nmap", "web_security", "threat_intel", "firewall"],
        batches=[],
        items=items,
    )

    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_unified_pdf_handles_missing_and_malformed_technical_results():
    items = [
        {
            "module": "web_security",
            "target": "https://example.test",
            "status": "Partial",
            "technical_result": None,
        },
        {
            "module": "firewall",
            "target": "example.test",
            "status": "Completed",
            "technical_result": {
                "tcp": {"ports": "invalid", "counts": None},
                "services": None,
                "https": "invalid",
                "tls": None,
                "waf": None,
            },
        },
    ]

    pdf = build_unified_scan_pdf(
        run=_run(),
        targets=["https://example.test"],
        modules=["web_security", "firewall"],
        batches=[],
        items=items,
    )

    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 500
