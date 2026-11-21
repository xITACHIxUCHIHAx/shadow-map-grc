import unittest
from unittest.mock import patch

from scanner import local_firewall_detector as detector


class LocalFirewallDetectorTests(unittest.TestCase):
    def test_linux_netfilter_observations_capture_rulesets(self):
        rulesets = {
            "nft": "table inet filter {}",
            "iptables-save": "*filter\\n:INPUT ACCEPT [0:0]\\nCOMMIT",
            "ip6tables-save": "*filter\\n:INPUT DROP [0:0]\\nCOMMIT",
        }

        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            name = argv[0]
            return {
                "available": True,
                "returncode": 0,
                "stdout": rulesets[name],
                "stderr": "",
                "error": None,
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            observations = detector._linux_netfilter_observations()

        self.assertEqual(len(observations), 3)
        self.assertTrue(all(item["status"] == "observed" for item in observations))
        self.assertIn("table inet filter", observations[0]["evidence"])

    def test_linux_netfilter_permission_denied_is_unknown(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "Operation not permitted",
                "error": None,
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            observations = detector._linux_netfilter_observations()

        self.assertEqual(len(observations), 3)
        self.assertTrue(all(item["status"] == "unknown" for item in observations))
        self.assertTrue(all("Permission denied" in item["error"] for item in observations))

    def test_linux_netfilter_missing_commands_are_unknown(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "error": "Command not installed or not found.",
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            observations = detector._linux_netfilter_observations()

        self.assertTrue(all(item["status"] == "unknown" for item in observations))

    def test_linux_netfilter_empty_ruleset_is_unknown(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": True,
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            observations = detector._linux_netfilter_observations()

        self.assertTrue(all(item["status"] == "unknown" for item in observations))


    def test_linux_detects_nftables_rules(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if argv[:3] == ["nft", "list", "ruleset"]:
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": (
                        "table inet filter {\n"
                        " chain input {\n"
                        "  type filter hook input priority filter; policy drop;\n"
                        "  ct state established,related accept\n"
                        " }\n"
                        "}\n"
                    ),
                    "stderr": "",
                    "error": None,
                }
            return {
                "available": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        with (
            patch.object(detector.platform, "system", return_value="Linux"),
            patch.object(detector, "_run", side_effect=fake_run),
            patch.object(detector.shutil, "which", return_value=None),
        ):
            result = detector.detect_local_firewall()

        nft = next(
            item for item in result["technologies"]
            if item["name"] == "nftables"
        )
        self.assertEqual(nft["status"], "active")
        self.assertEqual(result["status"], "active")

    def test_nftables_restrictive_base_chain_is_active(self):
        ruleset = """
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
    }
}
"""
        self.assertEqual(detector._nftables_status(ruleset), "active")

    def test_nftables_actual_rule_is_active(self):
        ruleset = """
table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport 22 drop
    }
}
"""
        self.assertEqual(detector._nftables_status(ruleset), "active")

    def test_nftables_empty_ruleset_is_inactive(self):
        self.assertEqual(detector._nftables_status(""), "inactive")
        self.assertEqual(detector._nftables_status("table inet filter {}"), "inactive")

    def test_nftables_chain_declaration_alone_is_unknown(self):
        ruleset = """
table inet filter {
    chain input {
        type filter hook input priority filter; policy accept;
    }
}
"""
        self.assertEqual(detector._nftables_status(ruleset), "unknown")


    def test_iptables_drop_policy_is_active(self):
        output = """
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
"""
        self.assertEqual(detector._iptables_status(output), "active")

    def test_iptables_actual_rule_is_active(self):
        output = """
-P INPUT ACCEPT
-A INPUT -p tcp --dport 22 -j DROP
"""
        self.assertEqual(detector._iptables_status(output), "active")

    def test_iptables_accept_only_policies_are_inactive(self):
        output = """
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
"""
        self.assertEqual(detector._iptables_status(output), "inactive")

    def test_iptables_empty_output_is_inactive(self):
        self.assertEqual(detector._iptables_status(""), "inactive")

    def test_iptables_incomplete_filter_output_is_unknown(self):
        self.assertEqual(
            detector._iptables_status("*filter\n"),
            "unknown",
        )

    def test_ufw_status_parser(self):
        self.assertEqual(detector._ufw_status("Status: active"), "active")
        self.assertEqual(detector._ufw_status("Status: inactive"), "inactive")
        self.assertEqual(detector._ufw_status("UFW is running"), "unknown")
        self.assertEqual(detector._ufw_status(""), "unknown")

    def test_firewalld_status_parser(self):
        self.assertEqual(detector._firewalld_status("running"), "active")
        self.assertEqual(detector._firewalld_status("not running"), "inactive")
        self.assertEqual(
            detector._firewalld_status("service is running normally"),
            "unknown",
        )
        self.assertEqual(detector._firewalld_status(""), "unknown")

    def test_permission_denied_is_unknown_not_disabled(self):
        result = {
            "available": True,
            "returncode": 1,
            "stdout": "",
            "stderr": "Operation not permitted",
            "error": None,
        }

        item = detector._technology("nftables", "packet_filter", result)

        self.assertEqual(item["status"], "unknown")
        self.assertIn("Permission denied", item["error"])

    def test_successful_generic_command_does_not_prove_active(self):
        result = {
            "available": True,
            "returncode": 0,
            "stdout": "Inspection completed successfully.",
            "stderr": "",
            "error": None,
        }

        item = detector._technology(
            "generic firewall",
            "packet_filter",
            result,
        )

        self.assertEqual(item["status"], "unknown")

    def test_empty_successful_ruleset_is_not_assumed_inactive(self):
        result = {
            "available": True,
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "error": None,
        }

        item = detector._technology(
            "generic firewall",
            "packet_filter",
            result,
        )

        self.assertEqual(item["status"], "unknown")

    def test_missing_tool_is_not_installed(self):
        result = {
            "available": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "Command not installed or not found.",
        }

        item = detector._technology("ufw", "host_firewall", result)

        self.assertEqual(item["status"], "not_installed")

    def test_ufw_active_status_is_recognized(self):
        result = {
            "available": True,
            "returncode": 0,
            "stdout": "Status: active\nLogging: on",
            "stderr": "",
            "error": None,
        }

        item = detector._technology(
            "UFW",
            "host_firewall",
            result,
            status="active",
        )

        self.assertEqual(item["status"], "active")

    def test_windows_profiles_are_parsed(self):
        payload = (
            '[{"Name":"Domain","Enabled":true,'
            '"DefaultInboundAction":"Block",'
            '"DefaultOutboundAction":"Allow"},'
            '{"Name":"Private","Enabled":false,'
            '"DefaultInboundAction":"Allow",'
            '"DefaultOutboundAction":"Allow"}]'
        )

        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if "-Command" in argv:
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": payload,
                    "stderr": "",
                    "error": None,
                }
            return {
                "available": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        with (
            patch.object(detector, "_run", side_effect=fake_run),
            patch.object(detector.shutil, "which", return_value="powershell"),
        ):
            technologies, observations = detector._windows_detection()

        self.assertEqual(
            technologies[0]["status"],
            "partially_active",
        )
        profile_observations = [
            item for item in observations
            if item.get("source") == "Windows Defender Firewall"
        ]
        wfp_observations = [
            item for item in observations
            if item.get("source") == "Windows Filtering Platform"
        ]

        self.assertEqual(len(profile_observations), 2)
        self.assertEqual(len(wfp_observations), 2)
        self.assertEqual(
            profile_observations[0]["default_inbound"], "Block"
        )

    def test_macos_application_firewall_enabled(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if "socketfilterfw" in argv[0]:
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": "Firewall is enabled. (State = 1)",
                    "stderr": "",
                    "error": None,
                }
            return {
                "available": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            technologies, _ = detector._macos_detection()

        self.assertEqual(technologies[0]["name"], "macOS Application Firewall")
        self.assertEqual(technologies[0]["status"], "active")

    def test_unknown_platform_returns_unknown(self):
        with patch.object(detector.platform, "system", return_value="FreeBSD"):
            result = detector.detect_local_firewall()

        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["technologies"], [])

    def test_multiple_firewall_technologies_are_preserved(self):
        technologies = [
            {"status": "active"},
            {"status": "unknown"},
            {"status": "inactive"},
        ]

        with (
            patch.object(detector.platform, "system", return_value="Linux"),
            patch.object(
                detector,
                "_linux_detection",
                return_value=(technologies, []),
            ),
        ):
            result = detector.detect_local_firewall()

        self.assertEqual(result["status"], "active")
        self.assertEqual(len(result["technologies"]), 3)


    def test_systemd_service_states_are_classified(self):
        cases = (
            ("active", 0, "active"),
            ("inactive", 3, "inactive"),
            ("not-found", 4, "not_found"),
            ("unknown", 4, "unknown"),
        )

        for output, returncode, expected in cases:
            with self.subTest(output=output):
                result = {
                    "available": True,
                    "returncode": returncode,
                    "stdout": output,
                    "stderr": "",
                    "error": None,
                }
                with (
                    patch.object(detector.shutil, "which", return_value="/usr/bin/systemctl"),
                    patch.object(detector, "_run", return_value=result),
                ):
                    observations = detector._systemd_service_observations()

                self.assertEqual(len(observations), 8)
                self.assertTrue(
                    all(item["status"] == expected for item in observations)
                )

    def test_systemd_permission_error_is_unknown(self):
        result = {
            "available": True,
            "returncode": 1,
            "stdout": "",
            "stderr": "Permission denied",
            "error": None,
        }

        with (
            patch.object(detector.shutil, "which", return_value="/usr/bin/systemctl"),
            patch.object(detector, "_run", return_value=result),
        ):
            observations = detector._systemd_service_observations()

        self.assertTrue(
            all(item["status"] == "unknown" for item in observations)
        )
        self.assertTrue(
            all(item["error"] == "Permission denied during service inspection."
                for item in observations)
        )

    def test_systemd_missing_command_returns_no_observations(self):
        with patch.object(detector.shutil, "which", return_value=None):
            observations = detector._systemd_service_observations()

        self.assertEqual(observations, [])


if __name__ == "__main__":
    unittest.main()


class ThirdPartyLinuxFirewallTests(unittest.TestCase):
    def test_third_party_package_presence_does_not_mean_active(self):
        package_output = (
            "opensnitch\n"
            "opensnitch-ui\n"
            "shorewall\n"
        )

        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if argv[0] == "dpkg-query":
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": package_output,
                    "stderr": "",
                    "error": None,
                }
            return {
                "available": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        with (
            patch.object(detector, "_run", side_effect=fake_run),
            patch.object(detector.shutil, "which", return_value=None),
        ):
            result = detector._linux_third_party_discovery()

        self.assertEqual(
            {item["name"] for item in result},
            {"OpenSnitch", "Shorewall"},
        )
        self.assertTrue(all(item["installed"] for item in result))
        self.assertTrue(all(item["firewall_state"] == "unknown" for item in result))


    def test_active_third_party_service_is_reported_running(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if argv[0] == "dpkg-query":
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": "opensnitch\n",
                    "stderr": "",
                    "error": None,
                }

            if argv[:3] == ["systemctl", "is-active", "opensnitch.service"]:
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": "active\n",
                    "stderr": "",
                    "error": None,
                }

            if argv[:2] == ["pgrep", "-x"]:
                return {
                    "available": True,
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "",
                    "error": None,
                }

            return {
                "available": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        with (
            patch.object(detector, "_run", side_effect=fake_run),
            patch.object(detector.shutil, "which", return_value=None),
        ):
            result = detector._linux_third_party_discovery()

        opensnitch = next(
            item for item in result if item["name"] == "OpenSnitch"
        )
        self.assertTrue(opensnitch["installed"])
        self.assertTrue(opensnitch["running"])
        self.assertEqual(opensnitch["status"], "unknown")
        self.assertEqual(opensnitch["firewall_state"], "unknown")


    def test_process_detection_works_without_systemd(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if argv[0] == "systemctl":
                return {
                    "available": False,
                    "returncode": None,
                    "stdout": "",
                    "stderr": "",
                    "error": "systemctl unavailable",
                }

            if argv[:2] == ["pgrep", "-x"] and argv[2] == "opensnitchd":
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": "1234\n",
                    "stderr": "",
                    "error": None,
                }

            return {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            running, evidence, observations = (
                detector._linux_third_party_runtime("OpenSnitch")
            )

        self.assertTrue(running)
        self.assertIn("Running process: opensnitchd", evidence)
        self.assertEqual(len(observations), 2)


    def test_permission_denied_does_not_mean_not_running(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if argv[0] == "systemctl":
                return {
                    "available": True,
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "Permission denied",
                    "error": None,
                }

            return {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            running, evidence, observations = (
                detector._linux_third_party_runtime("OpenSnitch")
            )

        self.assertIsNone(running)
        self.assertEqual(evidence, [])
        self.assertTrue(
            all(item["status"] == "unknown" for item in observations)
        )
        self.assertTrue(
            all(item["error"] for item in observations)
        )


    def test_shorewall_status_requires_explicit_state(self):
        self.assertEqual(
            detector._shorewall_status("Shorewall is running"),
            "active",
        )
        self.assertEqual(
            detector._shorewall_status("Shorewall is stopped"),
            "inactive",
        )
        self.assertIsNone(
            detector._shorewall_status("Shorewall status information"),
        )

    def test_opensnitch_requires_product_specific_queue_rule(self):
        observations = [
            {
                "name": "IPv4 iptables ruleset",
                "status": "observed",
                "evidence": (
                    "*filter\\n"
                    ":INPUT ACCEPT [0:0]\\n"
                    "-A INPUT -j NFQUEUE --queue-num 5\\n"
                    "COMMIT"
                ),
            }
        ]

        result = detector._opensnitch_rule_observation(observations)

        self.assertEqual(result["status"], "not_observed")
        self.assertIn("no identifiable OpenSnitch", result["evidence"][0])

    def test_opensnitch_identifiable_iptables_queue_rule(self):
        observations = [
            {
                "name": "IPv4 iptables ruleset",
                "status": "observed",
                "evidence": (
                    "*filter\\n"
                    ":opensnitch-output - [0:0]\\n"
                    "-A opensnitch-output -j NFQUEUE --queue-num 5\\n"
                    "COMMIT"
                ),
            }
        ]

        result = detector._opensnitch_rule_observation(observations)

        self.assertEqual(result["status"], "observed")
        self.assertIn("queue target", result["evidence"][0])
        self.assertIn("not verified", result["limitation"])

    def test_opensnitch_unreadable_rulesets_are_unknown(self):
        result = detector._opensnitch_rule_observation([
            {
                "name": "IPv4 iptables ruleset",
                "status": "unknown",
                "evidence": "",
                "error": "Permission denied",
            }
        ])

        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["error"])

    def test_douane_module_loaded(self):
        with patch(
            "builtins.open",
            unittest.mock.mock_open(
                read_data="douane 12345 0 - Live 0x00000000\\n"
            ),
        ):
            result = detector._linux_douane_module_observations()

        self.assertEqual(result[0]["status"], "loaded")
        self.assertIn("Douane", result[0]["evidence"])

    def test_douane_module_not_loaded(self):
        with patch(
            "builtins.open",
            unittest.mock.mock_open(read_data="nf_tables 12345 1 - Live 0x0\\n"),
        ):
            result = detector._linux_douane_module_observations()

        self.assertEqual(result[0]["status"], "not_loaded")
        self.assertEqual(result[0]["evidence"], "")

    def test_douane_module_inspection_failure_is_unknown(self):
        with patch("builtins.open", side_effect=PermissionError):
            result = detector._linux_douane_module_observations()

        self.assertEqual(result[0]["status"], "unknown")
        self.assertEqual(result[0]["error"], "PermissionError")

    def test_douane_module_does_not_claim_enforcement(self):
        with patch(
            "builtins.open",
            unittest.mock.mock_open(
                read_data="douane 12345 0 - Live 0x00000000\\n"
            ),
        ):
            observation = detector._linux_douane_module_observations()[0]

        self.assertEqual(observation["status"], "loaded")
        self.assertNotIn("firewall_state", observation)


class WindowsWFPObservationTests(unittest.TestCase):
    def test_successful_wfp_diagnostics_are_observed(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": True,
                "returncode": 0,
                "stdout": "WFP diagnostic output",
                "stderr": "",
                "error": None,
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            observations = detector._windows_wfp_observations()

        self.assertEqual(len(observations), 2)
        self.assertTrue(
            all(item["status"] == "observed" for item in observations)
        )
        self.assertTrue(
            all(item["source"] == "Windows Filtering Platform"
                for item in observations)
        )

    def test_permission_denied_wfp_diagnostics_remain_unknown(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "Access is denied",
                "error": None,
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            observations = detector._windows_wfp_observations()

        self.assertEqual(len(observations), 2)
        self.assertTrue(
            all(item["status"] == "unknown" for item in observations)
        )
        self.assertTrue(
            all(item["error"] for item in observations)
        )

    def test_unavailable_wfp_commands_remain_unknown(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "error": "Command not installed or not found.",
            }

        with patch.object(detector, "_run", side_effect=fake_run):
            observations = detector._windows_wfp_observations()

        self.assertEqual(len(observations), 2)
        self.assertTrue(
            all(item["status"] == "unknown" for item in observations)
        )


class ThirdPartyWindowsFirewallTests(unittest.TestCase):
    def test_running_service_is_detected(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if "-Command" in argv:
                return {
                    "available": True,
                    "returncode": 0,
                    "stdout": "Running\n",
                    "stderr": "",
                    "error": None,
                }

        with (
            patch.object(detector.shutil, "which", return_value="powershell"),
            patch.object(detector, "_run", side_effect=fake_run),
        ):
            running, evidence, observations = (
                detector._windows_third_party_runtime("ESET")
            )

        self.assertTrue(running)
        self.assertTrue(evidence)
        self.assertEqual(observations[0]["status"], "running")

    def test_stopped_service_and_process_are_not_running(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": True,
                "returncode": 0,
                "stdout": "Stopped\n" if "Get-Service" in argv[-1] else "",
                "stderr": "",
                "error": None,
            }

        with (
            patch.object(detector.shutil, "which", return_value="powershell"),
            patch.object(detector, "_run", side_effect=fake_run),
        ):
            running, _, observations = (
                detector._windows_third_party_runtime("ESET")
            )

        self.assertFalse(running)
        self.assertEqual(observations[0]["status"], "not_running")

    def test_permission_denied_remains_unknown(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "Access is denied",
                "error": None,
            }

        with (
            patch.object(detector.shutil, "which", return_value="powershell"),
            patch.object(detector, "_run", side_effect=fake_run),
        ):
            running, _, observations = (
                detector._windows_third_party_runtime("ESET")
            )

        self.assertIsNone(running)
        self.assertEqual(observations[0]["status"], "unknown")

    def test_missing_powershell_remains_unknown(self):
        with patch.object(detector.shutil, "which", return_value=None):
            running, _, observations = (
                detector._windows_third_party_runtime("ESET")
            )

        self.assertIsNone(running)
        self.assertEqual(observations[0]["status"], "unknown")


class WindowsFortiClientRuntimeTests(unittest.TestCase):
    def test_forticlient_checks_firewall_service_process(self):
        commands = []

        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            script = argv[-1]
            commands.append(script)
            return {
                "available": True,
                "returncode": 0,
                "stdout": "fortifws\n",
                "stderr": "",
                "error": None,
            }

        with (
            patch.object(detector.shutil, "which", return_value="powershell"),
            patch.object(detector, "_run", side_effect=fake_run),
        ):
            running, evidence, _ = (
                detector._windows_third_party_runtime("FortiClient")
            )

        self.assertTrue(running)
        self.assertTrue(any("fortifws" in command for command in commands))
        self.assertTrue(any("fortifws" in item for item in evidence))
        self.assertFalse(any("FortiClient.exe" in command for command in commands))


class ThirdPartyMacOSFirewallTests(unittest.TestCase):
    def test_running_process_is_detected(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": True,
                "returncode": 0,
                "stdout": "1234\n",
                "stderr": "",
                "error": None,
            }

        with (
            patch.object(detector.shutil, "which", return_value="/usr/bin/pgrep"),
            patch.object(detector, "_run", side_effect=fake_run),
        ):
            running, evidence, observations = (
                detector._macos_third_party_runtime("LuLu")
            )

        self.assertTrue(running)
        self.assertTrue(any("Running process" in item for item in evidence))
        self.assertTrue(observations)

    def test_listed_extension_alone_does_not_mean_process_running(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            if argv[1] == "-x":
                return {
                    "available": True,
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "",
                    "error": None,
                }
            return {
                "available": True,
                "returncode": 0,
                "stdout": "* com.objective-see.lulu",
                "stderr": "",
                "error": None,
            }

        def fake_which(command):
            return f"/usr/bin/{command}"

        with (
            patch.object(detector.shutil, "which", side_effect=fake_which),
            patch.object(detector, "_run", side_effect=fake_run),
        ):
            running, evidence, observations = (
                detector._macos_third_party_runtime("LuLu")
            )

        self.assertFalse(running)
        self.assertTrue(
            any("System extension listed" in item for item in evidence)
        )
        extension = next(
            item for item in observations
            if item["source"] == "macOS system extension"
        )
        self.assertEqual(extension["status"], "listed")


    def test_stopped_process_and_missing_extension_are_not_running(self):
        def fake_run(argv, timeout=detector.COMMAND_TIMEOUT):
            return {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "",
                "error": None,
            }

        def fake_which(command):
            return f"/usr/bin/{command}"

        with (
            patch.object(detector.shutil, "which", side_effect=fake_which),
            patch.object(detector, "_run", side_effect=fake_run),
        ):
            running, evidence, observations = (
                detector._macos_third_party_runtime("LuLu")
            )

        self.assertFalse(running)
        self.assertEqual(evidence, [])
        self.assertTrue(
            all(
                item["status"] == "not_running"
                for item in observations
                if item["source"] == "macOS process"
            )
        )
        extension_observations = [
            item for item in observations
            if item["source"] == "macOS system extension"
        ]
        self.assertEqual(extension_observations[0]["status"], "unknown")

    def test_unavailable_inspection_remains_unknown(self):
        with (
            patch.object(detector.shutil, "which", return_value=None),
            patch.object(detector, "_run") as run,
        ):
            running, evidence, observations = (
                detector._macos_third_party_runtime("Little Snitch")
            )

        self.assertIsNone(running)
        self.assertEqual(evidence, [])
        self.assertTrue(observations)
        run.assert_not_called()

    def test_runtime_discovery_does_not_claim_firewall_active(self):
        products = ({
            "name": "LuLu",
            "category": "application_network_monitor",
            "packages": {"com.objective-see.lulu"},
            "executables": (),
        },)

        package_result = {
            "available": True,
            "returncode": 0,
            "stdout": "com.objective-see.lulu\n",
            "stderr": "",
            "error": None,
        }

        with (
            patch.object(detector, "_run", return_value=package_result),
            patch.object(
                detector,
                "_macos_third_party_runtime",
                return_value=(True, ["Running process: LuLu"], []),
            ),
        ):
            discovered = detector._third_party_product_discovery(
                products,
                (("pkgutil", ["pkgutil", "--pkgs"]),),
                runtime_detector=detector._macos_third_party_runtime,
            )

        self.assertEqual(len(discovered), 1)
        self.assertTrue(discovered[0]["running"])
        self.assertEqual(discovered[0]["status"], "unknown")
        self.assertEqual(discovered[0]["firewall_state"], "unknown")
