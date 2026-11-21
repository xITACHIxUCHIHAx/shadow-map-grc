import io
import subprocess
import signal
import unittest
from unittest.mock import patch

from scanner import nmap_scanner


VALID_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

PARTIAL_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"
"""


class RecordingInput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.captured_value = ""

    def close(self):
        self.captured_value = self.getvalue()
        super().close()


class FakeProcess:
    def __init__(self, stdout="", stderr="", returncode=0, timeout=False):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self.stdin = RecordingInput()
        self.returncode = returncode
        self.timeout = timeout
        self.wait_calls = 0
        self.killed = False
        self.pid = 424242

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.timeout and self.wait_calls == 1:
            raise subprocess.TimeoutExpired("nmap", timeout)
        return self.returncode

    def kill(self):
        self.killed = True


class NmapScannerOfflineTests(unittest.TestCase):
    @unittest.skipUnless(nmap_scanner.os.name == "posix", "POSIX process groups required")
    @patch("scanner.nmap_scanner.os.killpg")
    def test_process_group_termination_escalates_after_grace_period(
        self, mock_killpg
    ):
        process = FakeProcess(timeout=True)

        return_code = nmap_scanner._terminate_process_group(
            process,
            grace_seconds=2,
        )

        mock_killpg.assert_any_call(process.pid, signal.SIGTERM)
        mock_killpg.assert_any_call(process.pid, signal.SIGKILL)
        self.assertEqual(mock_killpg.call_count, 2)
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(return_code, 0)

    @patch("scanner.nmap_scanner.subprocess.run")
    @patch("scanner.nmap_scanner.os.name", "nt")
    def test_windows_termination_escalates_to_taskkill(self, mock_run):
        class WindowsProcess:
            pid = 424242

            def __init__(self):
                self.wait_calls = 0
                self.terminated = False

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired("nmap", timeout)
                return 0

        process = WindowsProcess()

        return_code = nmap_scanner._terminate_process_group(
            process,
            grace_seconds=2,
        )

        self.assertTrue(process.terminated)
        mock_run.assert_called_once()
        self.assertEqual(
            mock_run.call_args.args[0],
            ["taskkill", "/PID", "424242", "/T", "/F"],
        )
        self.assertEqual(mock_run.call_args.kwargs["timeout"], 10)
        self.assertEqual(return_code, 0)

    def test_shutdown_stops_only_registered_nmap_processes(self):
        from unittest.mock import MagicMock

        process = MagicMock()
        process.pid = 424243
        process.poll.return_value = None

        unrelated_process = MagicMock()
        unrelated_process.pid = 424244
        unrelated_process.poll.return_value = None

        nmap_scanner._register_nmap_process(process)

        with patch(
            "scanner.nmap_scanner._terminate_process_group"
        ) as terminate:
            stopped = nmap_scanner.shutdown_active_nmap_processes()

        self.assertEqual(stopped, 1)
        terminate.assert_called_once_with(process, grace_seconds=2)
        self.assertNotIn(
            unrelated_process.pid,
            nmap_scanner._ACTIVE_NMAP_PROCESSES,
        )
        self.assertNotIn(
            process.pid,
            nmap_scanner._ACTIVE_NMAP_PROCESSES,
        )

    def test_shutdown_does_not_terminate_exited_registered_process(self):
        from unittest.mock import MagicMock

        process = MagicMock()
        process.pid = 424245
        process.poll.return_value = 0

        nmap_scanner._register_nmap_process(process)

        with patch(
            "scanner.nmap_scanner._terminate_process_group"
        ) as terminate:
            stopped = nmap_scanner.shutdown_active_nmap_processes()

        self.assertEqual(stopped, 0)
        terminate.assert_not_called()
        self.assertNotIn(
            process.pid,
            nmap_scanner._ACTIVE_NMAP_PROCESSES,
        )

    def test_scan_profiles_define_expected_ports_and_timeouts(self):
        expected = {
            "quick": (["--top-ports", "100"], 180),
            "standard": (["--top-ports", "1000"], 300),
            "full_tcp": (["-p-"], 1200),
        }

        self.assertEqual(set(nmap_scanner.SCAN_PROFILES), set(expected))

        for profile, (port_args, timeout_seconds) in expected.items():
            with self.subTest(profile=profile):
                self.assertEqual(
                    nmap_scanner.SCAN_PROFILES[profile]["port_args"],
                    port_args,
                )
                self.assertEqual(
                    nmap_scanner.SCAN_PROFILES[profile]["timeout_seconds"],
                    timeout_seconds,
                )

    def setUp(self):
        self.which_patcher = patch(
            "scanner.nmap_scanner.find_nmap_executable",
            return_value="/usr/bin/nmap",
        )
        self.which_patcher.start()
        self.addCleanup(self.which_patcher.stop)

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_completed_scan_parses_xml(self, mock_popen):
        mock_popen.return_value = FakeProcess(stdout=VALID_XML)

        result = nmap_scanner.run_nmap("192.0.2.10", "quick")

        self.assertEqual(result["status"], "Completed")
        self.assertIsNone(result["error"])
        self.assertEqual(result["host_state"], "up")
        self.assertEqual(
            [(p["port"], p["state"]) for p in result["ports"]],
            [(80, "open"), (443, "open")],
        )
        self.assertEqual(result["counts"]["open"], 2)
        mock_popen.assert_called_once()

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_command_includes_live_progress_reporting(self, mock_popen):
        mock_popen.return_value = FakeProcess(stdout=VALID_XML)

        nmap_scanner.run_nmap("192.0.2.10", "standard")

        command = mock_popen.call_args.args[0]
        self.assertIn("--stats-every", command)
        self.assertEqual(command[command.index("--stats-every") + 1], "1s")

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_progress_callback_receives_real_task_progress(self, mock_popen):
        progress_xml = (
            '<taskprogress task="Service scan" time="123" '
            'percent="47.83" remaining="6" etc="129"/>\n'
        )
        mock_popen.return_value = FakeProcess(
            stdout=VALID_XML.replace("<nmaprun>", "<nmaprun>\\n" + progress_xml, 1)
        )
        events = []

        result = nmap_scanner.run_nmap(
            "192.0.2.10",
            "quick",
            progress_callback=events.append,
        )

        self.assertEqual(result["status"], "Completed")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["task"], "Service scan")
        self.assertEqual(events[0]["percent"], 47.83)
        self.assertIsNone(events[0]["remaining_seconds"])
        self.assertIsNone(events[0]["estimated_completion"])

    def test_progress_parser_rejects_invalid_percentages_and_preserves_phases(self):
        xml = (
            '<taskprogress task="Service scan" percent="50.0" remaining="8"/>\n'
            '<taskprogress task="Service scan" percent="101"/>\n'
            '<taskprogress task="Service scan" percent="-1"/>\n'
            '<taskprogress task="Service scan" percent="nan"/>\n'
            '<taskprogress task="NSE" percent="75.0"/>\n'
            '<taskprogress task="NSE" percent="invalid"/>\n'
        )
        events = []
        output = []

        nmap_scanner._read_nmap_stream(
            io.StringIO(xml),
            output,
            events.append,
        )

        self.assertEqual(
            [(event["task"], event["percent"]) for event in events],
            [("Service scan", 50.0), ("NSE", 75.0)],
        )
        self.assertTrue(all(event["remaining_seconds"] is None for event in events))
        self.assertTrue(all(event["estimated_completion"] is None for event in events))

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_progress_callback_exception_does_not_interrupt_scan(self, mock_popen):
        progress_xml = (
            '<taskprogress task="Service scan" percent="50" '
            'remaining="5" etc="129"/>\n'
        )
        mock_popen.return_value = FakeProcess(
            stdout=VALID_XML.replace("<nmaprun>", "<nmaprun>\\n" + progress_xml, 1)
        )

        def broken_callback(event):
            raise RuntimeError("UI callback failed")

        result = nmap_scanner.run_nmap(
            "192.0.2.10",
            "quick",
            progress_callback=broken_callback,
        )

        self.assertEqual(result["status"], "Completed")
        self.assertEqual(result["counts"]["open"], 2)

    @patch("scanner.nmap_scanner.os.killpg")
    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_timeout_recovers_only_complete_port_records(self, mock_popen, mock_killpg):
        process = FakeProcess(
            stdout=PARTIAL_XML,
            stderr="scan timed out",
            timeout=True,
        )
        mock_popen.return_value = process

        result = nmap_scanner.run_nmap(
            "192.0.2.10", "quick", timeout_seconds=1
        )

        self.assertEqual(result["status"], "Partial")
        self.assertIn("time limit", result["error"])
        self.assertEqual(result["host_state"], "up")
        self.assertEqual(
            [p["port"] for p in result["ports"]],
            [80, 443],
        )
        self.assertNotIn(8080, [p["port"] for p in result["ports"]])
        mock_killpg.assert_any_call(process.pid, signal.SIGTERM)
        mock_killpg.assert_any_call(process.pid, signal.SIGKILL)
        self.assertEqual(mock_killpg.call_count, 2)

    @patch("scanner.nmap_scanner.os.killpg")
    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_timeout_without_output_returns_empty_partial_result(self, mock_popen, mock_killpg):
        process = FakeProcess(timeout=True)
        mock_popen.return_value = process

        result = nmap_scanner.run_nmap(
            "192.0.2.10", "quick", timeout_seconds=1
        )

        self.assertEqual(result["status"], "Partial")
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["counts"]["open"], 0)
        self.assertTrue(result["error"])
        mock_killpg.assert_any_call(process.pid, signal.SIGTERM)
        mock_killpg.assert_any_call(process.pid, signal.SIGKILL)
        self.assertEqual(mock_killpg.call_count, 2)

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_nonzero_exit_is_reported_as_scanner_error(self, mock_popen):
        mock_popen.return_value = FakeProcess(
            returncode=2,
            stderr="mock scanner failure",
        )

        with self.assertRaises(nmap_scanner.NmapError) as context:
            nmap_scanner.run_nmap("192.0.2.10", "quick")

        self.assertIn("code 2", str(context.exception))
        self.assertIn("mock scanner failure", str(context.exception))

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_invalid_profile_does_not_launch_subprocess(self, mock_popen):
        with self.assertRaises(nmap_scanner.NmapError):
            nmap_scanner.run_nmap("192.0.2.10", "not-a-profile")

        mock_popen.assert_not_called()

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_timeout_cannot_exceed_profile_limit(self, mock_popen):
        for profile, settings in nmap_scanner.SCAN_PROFILES.items():
            excessive_timeout = settings["timeout_seconds"] + 1

            with self.subTest(profile=profile):
                with self.assertRaises(nmap_scanner.NmapError):
                    nmap_scanner.run_nmap(
                        "192.0.2.10",
                        profile,
                        timeout_seconds=excessive_timeout,
                    )

        mock_popen.assert_not_called()

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_invalid_timeout_does_not_launch_subprocess(self, mock_popen):
        for invalid_timeout in (0, -1, True, "10", float("nan"), float("inf"), float("-inf")):
            with self.subTest(timeout=invalid_timeout):
                with self.assertRaises(nmap_scanner.NmapError):
                    nmap_scanner.run_nmap(
                        "192.0.2.10",
                        "quick",
                        timeout_seconds=invalid_timeout,
                    )

        mock_popen.assert_not_called()

    def test_xml_parser_rejects_multiple_hosts(self):
        xml = """<nmaprun>
          <host>
            <status state="up"/>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
              </port>
            </ports>
          </host>
          <host>
            <status state="up"/>
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""

        with self.assertRaisesRegex(
            nmap_scanner.NmapError,
            "multiple hosts",
        ):
            nmap_scanner.parse_nmap_xml(xml)

    def test_xml_parser_rejects_invalid_port_identifier(self):
        xml = """<nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="abc">
                <state state="open" reason="syn-ack"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""

        with self.assertRaisesRegex(
            nmap_scanner.NmapError,
            "invalid port identifier",
        ):
            nmap_scanner.parse_nmap_xml(xml)

    def test_xml_parser_rejects_out_of_range_port_identifiers(self):
        for port_id in ("0", "65536", ""):
            with self.subTest(port_id=port_id):
                xml = f"""<nmaprun>
                  <host>
                    <ports>
                      <port protocol="tcp" portid="{port_id}">
                        <state state="open"/>
                      </port>
                    </ports>
                  </host>
                </nmaprun>"""

                with self.assertRaisesRegex(
                    nmap_scanner.NmapError,
                    "invalid port identifier",
                ):
                    nmap_scanner.parse_nmap_xml(xml)

    def test_xml_parser_preserves_non_tcp_protocols(self):
        for protocol in ("udp", "sctp"):
            with self.subTest(protocol=protocol):
                xml = f"""<nmaprun>
                  <host>
                    <ports>
                      <port protocol="{protocol}" portid="53">
                        <state state="open"/>
                      </port>
                    </ports>
                  </host>
                </nmaprun>"""

                result = nmap_scanner.parse_nmap_xml(xml)
                self.assertEqual(result["ports"][0]["protocol"], protocol)

    def test_xml_parser_rejects_missing_or_empty_protocol(self):
        for protocol_attribute in ("", 'protocol=""'):
            with self.subTest(protocol_attribute=protocol_attribute):
                xml = f"""<nmaprun>
                  <host>
                    <ports>
                      <port {protocol_attribute} portid="53">
                        <state state="open"/>
                      </port>
                    </ports>
                  </host>
                </nmaprun>"""

                with self.assertRaisesRegex(
                    nmap_scanner.NmapError,
                    "invalid port protocol",
                ):
                    nmap_scanner.parse_nmap_xml(xml)


    def test_xml_parser_accepts_highest_valid_port(self):
        xml = """<nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="65535">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""

        result = nmap_scanner.parse_nmap_xml(xml)
        self.assertEqual(result["ports"][0]["port"], 65535)

    def test_xml_parser_rejects_malformed_xml(self):
        malformed_xml = "<nmaprun><host><status state='up'></host>"

        with self.assertRaisesRegex(
            nmap_scanner.NmapError,
            "unreadable XML",
        ):
            nmap_scanner.parse_nmap_xml(malformed_xml)

    def test_xml_parser_extracts_mac_and_os_metadata(self):
        xml = """<nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.0.2.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF"
                     addrtype="mac" vendor="Example Vendor"/>
            <os>
              <osmatch name="Example Linux 6.x" accuracy="98">
                <osclass type="general" vendor="Linux"
                         osfamily="Linux" osgen="6" accuracy="98">
                  <cpe>cpe:/o:linux:linux_kernel:6</cpe>
                </osclass>
              </osmatch>
            </os>
            <ports/>
          </host>
        </nmaprun>"""

        result = nmap_scanner.parse_nmap_xml(xml)

        self.assertEqual(result["mac_address"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result["mac_vendor"], "Example Vendor")
        self.assertEqual(result["os_match"], "Example Linux 6.x")
        self.assertEqual(result["os_accuracy"], "98")
        self.assertEqual(result["os_matches"][0]["vendor"], "Linux")
        self.assertEqual(
            result["os_matches"][0]["cpe"],
            ["cpe:/o:linux:linux_kernel:6"],
        )

    def test_xml_parser_preserves_port_and_service_metadata(self):
        xml = """<nmaprun>
          <host>
            <status state="up"/>
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack"/>
                <service name="https" product="Example Server"
                         version="2.4" extrainfo="TLS enabled"
                         method="probed" conf="10" tunnel="ssl">
                  <cpe>cpe:/a:example:server:2.4</cpe>
                </service>
              </port>
              <port protocol="tcp" portid="22">
                <state state="filtered" reason="no-response"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""

        result = nmap_scanner.parse_nmap_xml(xml)

        self.assertEqual(
            [item["port"] for item in result["ports"]],
            [22, 443],
        )

        https = result["ports"][1]
        self.assertEqual(https["protocol"], "tcp")
        self.assertEqual(https["state"], "open")
        self.assertEqual(https["reason"], "syn-ack")
        self.assertEqual(https["service"], "https")
        self.assertEqual(https["product"], "Example Server")
        self.assertEqual(https["version"], "2.4")
        self.assertEqual(https["extra_info"], "TLS enabled")
        self.assertEqual(https["service_method"], "probed")
        self.assertEqual(https["service_confidence"], "10")
        self.assertEqual(https["service_tunnel"], "ssl")
        self.assertEqual(
            https["service_cpe"],
            ["cpe:/a:example:server:2.4"],
        )

        filtered = result["ports"][0]
        self.assertEqual(filtered["state"], "filtered")
        self.assertEqual(filtered["reason"], "no-response")
        self.assertEqual(filtered["service"], "")
        self.assertEqual(filtered["service_method"], "")
        self.assertEqual(filtered["service_confidence"], "")
        self.assertEqual(filtered["service_tunnel"], "")
        self.assertEqual(filtered["service_cpe"], [])

    def test_xml_without_mac_or_os_returns_empty_metadata(self):
        result = nmap_scanner.parse_nmap_xml(VALID_XML)

        self.assertEqual(result["mac_address"], "")
        self.assertEqual(result["mac_vendor"], "")
        self.assertEqual(result["os_matches"], [])
        self.assertEqual(result["os_match"], "")
        self.assertEqual(result["os_accuracy"], "")

    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_os_detection_uses_restricted_helper(self, mock_popen):
        os_xml = VALID_XML.replace(
            "<ports>",
            """<os>
              <osmatch name="Example Linux" accuracy="95">
                <osclass type="general" vendor="Linux"
                         osfamily="Linux" osgen="6" accuracy="95"/>
              </osmatch>
            </os>
            <ports>""",
            1,
        )
        process = FakeProcess(stdout=os_xml)
        mock_popen.return_value = process

        result = nmap_scanner.run_nmap(
            "192.0.2.10",
            "quick",
            detect_os=True,
        )

        command = mock_popen.call_args.args[0]
        self.assertEqual(
            command,
            ["sudo", "-n", "/usr/local/sbin/shadow-map-nmap-os-helper"],
        )
        self.assertEqual(
            process.stdin.captured_value,
            '{"target": "192.0.2.10", "profile": "quick"}',
        )
        self.assertTrue(process.stdin.closed)
        self.assertTrue(result["os_detection_requested"])
        self.assertEqual(result["os_detection_status"], "detected")
        self.assertEqual(result["os_match"], "Example Linux")

    @patch("scanner.nmap_scanner.platform.system", return_value="Darwin")
    @patch("scanner.nmap_scanner.os.geteuid", return_value=1000)
    def test_macos_os_detection_requires_root(self, mock_uid, mock_system):
        with self.assertRaisesRegex(nmap_scanner.NmapError, "requires root"):
            nmap_scanner.run_nmap(
                "192.0.2.10", "quick", detect_os=True
            )

    @patch("scanner.nmap_scanner.platform.system", return_value="Darwin")
    @patch("scanner.nmap_scanner.os.geteuid", return_value=0)
    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_macos_root_uses_native_nmap_without_helper_stdin(
        self, mock_popen, mock_uid, mock_system
    ):
        mock_popen.return_value = FakeProcess(stdout=VALID_XML)

        result = nmap_scanner.run_nmap(
            "192.0.2.10", "quick", detect_os=True
        )

        command = mock_popen.call_args.args[0]
        self.assertIn("-sS", command)
        self.assertIn("-O", command)
        self.assertEqual(command[-1], "192.0.2.10")
        self.assertIs(
            mock_popen.call_args.kwargs["stdin"],
            subprocess.DEVNULL,
        )
        self.assertEqual(mock_popen.return_value.stdin.captured_value, "")
        self.assertEqual(result["os_detection_status"], "not_detected")

    @patch("scanner.nmap_scanner.platform.system", return_value="Windows")
    @patch("scanner.nmap_scanner._is_windows_administrator", return_value=False)
    def test_windows_os_detection_requires_administrator(
        self, mock_admin, mock_system
    ):
        with self.assertRaisesRegex(
            nmap_scanner.NmapError, "elevated Administrator"
        ):
            nmap_scanner.run_nmap(
                "192.0.2.10", "quick", detect_os=True
            )

    @patch("scanner.nmap_scanner.platform.system", return_value="Windows")
    @patch("scanner.nmap_scanner._is_windows_administrator", return_value=True)
    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_windows_admin_uses_native_nmap_without_helper_stdin(
        self, mock_popen, mock_admin, mock_system
    ):
        mock_popen.return_value = FakeProcess(stdout=VALID_XML)

        result = nmap_scanner.run_nmap(
            "192.0.2.10", "quick", detect_os=True
        )

        command = mock_popen.call_args.args[0]
        self.assertIn("-sS", command)
        self.assertIn("-O", command)
        self.assertEqual(command[-1], "192.0.2.10")
        self.assertIs(
            mock_popen.call_args.kwargs["stdin"],
            subprocess.DEVNULL,
        )
        self.assertEqual(mock_popen.return_value.stdin.captured_value, "")
        self.assertEqual(result["os_detection_status"], "not_detected")


    @patch("scanner.nmap_scanner.os.geteuid", return_value=1000)
    @patch("scanner.nmap_scanner.subprocess.Popen")
    def test_unprivileged_scan_skips_os_detection(self, mock_popen, mock_uid):
        mock_popen.return_value = FakeProcess(stdout=VALID_XML)

        result = nmap_scanner.run_nmap("192.0.2.10", "quick")

        command = mock_popen.call_args.args[0]
        self.assertNotIn("-O", command)
        self.assertFalse(result["os_detection_requested"])
        self.assertEqual(
            result["os_detection_status"], "disabled"
        )


    def test_port_counts_preserve_combined_nmap_states_as_other(self):
        ports = [
            {"state": "open"},
            {"state": "closed"},
            {"state": "filtered"},
            {"state": "open|filtered"},
            {"state": "closed|filtered"},
            {"state": "unfiltered"},
            {"state": "unknown"},
        ]

        counts = nmap_scanner._port_counts(ports)

        self.assertEqual(counts["open"], 1)
        self.assertEqual(counts["closed"], 1)
        self.assertEqual(counts["filtered"], 1)
        self.assertEqual(counts["other"], 4)
        self.assertEqual(sum(counts.values()), len(ports))


if __name__ == "__main__":
    unittest.main()
