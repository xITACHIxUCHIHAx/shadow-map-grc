import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from scanner.zap_proxy import (
    _find_java_executable,
    _zap_launch_command,
    _require_java_17,
    ZapProxyError,
    test_connection as check_zap_connection,
    fetch_alerts,
    trigger_zap_active_scan,
    load_endpoint,
    validate_endpoint,
    ensure_zap_running,
    get_api_key,
    _process_matches_managed_zap,
    _write_managed_process_record,
    _read_managed_process_record,
    shutdown_managed_zap,
    _prepare_managed_zap_session,
    _write_managed_session_manifest,
    _read_managed_session_manifest,
    _managed_session_artifacts_exist,
    ZapProxyError,
)


class JavaDiscoveryTests(unittest.TestCase):
    def test_java_home_takes_priority_over_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            java_home = Path(temporary)
            java_bin = java_home / "bin"
            java_bin.mkdir()
            java_executable = java_bin / "java"
            java_executable.touch()

            with patch.dict(
                "os.environ", {"JAVA_HOME": str(java_home)}, clear=True
            ), patch(
                "scanner.zap_proxy.shutil.which",
                return_value="/usr/bin/java",
            ) as which:
                self.assertEqual(
                    _find_java_executable(), str(java_executable)
                )
                which.assert_not_called()

    def test_falls_back_to_path(self):
        with patch.dict("os.environ", {}, clear=True), patch(
            "scanner.zap_proxy.shutil.which",
            return_value="/usr/bin/java",
        ):
            self.assertEqual(
                _find_java_executable(), "/usr/bin/java"
            )

    def test_accepts_java_17_and_21(self):
        for version in ("17.0.1", "21.0.1"):
            with self.subTest(version=version), patch(
                "scanner.zap_proxy._find_java_executable",
                return_value="/usr/bin/java",
            ), patch(
                "scanner.zap_proxy.subprocess.run",
                return_value=Mock(
                    returncode=0,
                    stdout="",
                    stderr=f'openjdk version "{version}"',
                ),
            ):
                self.assertEqual(
                    _require_java_17(), "/usr/bin/java"
                )

    def test_rejects_java_11(self):
        with patch(
            "scanner.zap_proxy._find_java_executable",
            return_value="/usr/bin/java",
        ), patch(
            "scanner.zap_proxy.subprocess.run",
            return_value=Mock(
                returncode=0,
                stdout="",
                stderr='openjdk version "11.0.22"',
            ),
        ):
            with self.assertRaisesRegex(ZapProxyError, "Java 17 or newer"):
                _require_java_17()

    def test_reports_missing_java(self):
        with patch(
            "scanner.zap_proxy._find_java_executable",
            return_value=None,
        ):
            with self.assertRaisesRegex(ZapProxyError, "Java 17 or newer"):
                _require_java_17()

    def test_finds_java_in_macos_jvm_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            java_executable = (
                Path(temporary) / "Contents" / "Home" / "bin" / "java"
            )
            java_executable.parent.mkdir(parents=True)
            java_executable.touch()

            with patch.dict("os.environ", {}, clear=True), patch(
                "scanner.zap_proxy.platform.system",
                return_value="Darwin",
            ), patch(
                "scanner.zap_proxy.shutil.which",
                return_value=None,
            ), patch(
                "scanner.zap_proxy.Path.glob",
                return_value=[java_executable],
            ):
                self.assertEqual(
                    _find_java_executable(),
                    str(java_executable),
                )


class ZapLaunchCommandJavaTests(unittest.TestCase):
    def test_managed_jar_launch_rejects_java_11(self):
        zap_info = {"path": "/managed/zap/zap.jar"}

        with patch(
            "scanner.zap_proxy._find_java_executable",
            return_value="/usr/bin/java",
        ), patch(
            "scanner.zap_proxy.subprocess.run",
            return_value=Mock(
                returncode=0,
                stdout="",
                stderr='openjdk version "11.0.22"',
            ),
        ):
            with self.assertRaisesRegex(
                ZapProxyError, "Java 17 or newer"
            ):
                _zap_launch_command(
                    zap_info,
                    "127.0.0.1",
                    8090,
                    "test-key",
                    Path("/tmp/zap-home"),
                )

    def test_managed_jar_launch_uses_validated_java_17(self):
        zap_info = {"path": "/managed/zap/zap.jar"}

        with patch(
            "scanner.zap_proxy._find_java_executable",
            return_value="/usr/bin/java",
        ), patch(
            "scanner.zap_proxy.subprocess.run",
            return_value=Mock(
                returncode=0,
                stdout="",
                stderr='openjdk version "17.0.21"',
            ),
        ):
            command = _zap_launch_command(
                zap_info,
                "127.0.0.1",
                8090,
                "test-key",
                Path("/tmp/zap-home"),
            )

        self.assertEqual(command[0], "/usr/bin/java")
        self.assertIn("-jar", command)
        self.assertIn("/managed/zap/zap.jar", command)


class ZapEndpointValidationTests(unittest.TestCase):
    def test_load_endpoint_always_returns_managed_endpoint(self):
        self.assertEqual(load_endpoint(), "http://127.0.0.1:8090")

    def test_accepts_local_endpoints(self):
        self.assertEqual(
            validate_endpoint("http://127.0.0.1:8090/"),
            "http://127.0.0.1:8090",
        )

    def test_rejects_non_loopback_hosts(self):
        for endpoint in (
            "http://example.com:8080",
            "http://192.168.1.10:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8090/other",
            "http://user:pass@127.0.0.1:8080",
            "ftp://127.0.0.1:8080",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ZapProxyError):
                    validate_endpoint(endpoint)

    @patch("scanner.zap_proxy.requests.Session")
    def test_connection_success_is_mocked(self, session_class):
        session = session_class.return_value
        response = Mock()
        response.is_redirect = False
        response.json.return_value = {"version": "2.17.0"}
        session.get.return_value = response

        with patch(
            "scanner.zap_proxy.get_api_key",
            return_value="test-only-key",
        ):
            result = check_zap_connection("http://127.0.0.1:8090")

        self.assertEqual(
            result,
            {"connected": True, "version": "2.17.0"},
        )
        session.get.assert_called_once()
        self.assertFalse(session.trust_env)
        session.close.assert_called_once()

    @patch("scanner.zap_proxy.requests.Session")
    def test_rejects_unexpected_api_response(self, session_class):
        session = session_class.return_value
        response = Mock()
        response.is_redirect = False
        response.json.return_value = {"message": "not ZAP"}
        session.get.return_value = response

        with patch(
            "scanner.zap_proxy.get_api_key",
            return_value="test-only-key",
        ):
            with self.assertRaises(ZapProxyError):
                check_zap_connection("http://127.0.0.1:8090")

    def test_missing_api_key_fails_without_network(self):
        with patch("scanner.zap_proxy.get_api_key", return_value=None):
            with patch("scanner.zap_proxy.requests.Session") as session_class:
                with self.assertRaises(ZapProxyError):
                    check_zap_connection("http://127.0.0.1:8090")
                session_class.assert_not_called()


    @patch("scanner.zap_proxy.requests.Session")
    def test_fetch_alerts_returns_existing_alerts(self, session_class):
        session = session_class.return_value
        response = Mock()
        response.is_redirect = False
        response.json.return_value = {
            "alerts": [{
                "name": "Example alert",
                "risk": "Medium",
                "url": "http://127.0.0.1/example",
                "description": "Mock description",
                "solution": "Mock remediation",
                "alert": "Mock evidence",
                "confidence": "High",
                "pluginId": "10001",
            }]
        }
        session.get.return_value = response

        with patch(
            "scanner.zap_proxy.get_api_key",
            return_value="test-only-key",
        ):
            result = fetch_alerts("http://127.0.0.1:8090")

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["alerts"][0]["name"], "Example alert")
        self.assertEqual(result["alerts"][0]["risk"], "Medium")
        self.assertFalse(session.trust_env)
        self.assertIn("/JSON/core/view/alerts/", session.get.call_args.args[0])
        session.close.assert_called_once()

    @patch("scanner.zap_proxy.requests.Session")
    def test_fetch_alerts_rejects_malformed_response(self, session_class):
        session = session_class.return_value
        response = Mock()
        response.is_redirect = False
        response.json.return_value = {"unexpected": []}
        session.get.return_value = response

        with patch(
            "scanner.zap_proxy.get_api_key",
            return_value="test-only-key",
        ):
            with self.assertRaises(ZapProxyError):
                fetch_alerts("http://127.0.0.1:8090")

    def test_fetch_alerts_rejects_invalid_limit_without_network(self):
        with patch(
            "scanner.zap_proxy.get_api_key",
            return_value="test-only-key",
        ):
            with patch("scanner.zap_proxy.requests.Session") as session_class:
                with self.assertRaises(ZapProxyError):
                    fetch_alerts(
                        "http://127.0.0.1:8090",
                        limit=10000,
                    )
                session_class.assert_not_called()


class ZapManagedKeyTests(unittest.TestCase):
    def test_generates_and_secures_managed_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "data"
            key_file = data_dir / ".zap_auto_key"

            with patch("scanner.zap_proxy.DATA_DIR", data_dir), patch(
                "scanner.zap_proxy.AUTO_KEY_FILE", key_file
            ), patch(
                "scanner.zap_proxy.secrets.token_hex",
                return_value="a" * 64,
            ) as token_generator:
                from scanner.zap_proxy import _ensure_zap_api_key

                key = _ensure_zap_api_key()

            self.assertEqual(key, "a" * 64)
            self.assertEqual(key_file.read_text(encoding="utf-8").strip(), key)
            self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)
            token_generator.assert_called_once_with(32)

    def test_reuses_existing_managed_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "data"
            key_file = data_dir / ".zap_auto_key"
            data_dir.mkdir(parents=True)
            key_file.write_text("existing-managed-key\n", encoding="utf-8")

            with patch("scanner.zap_proxy.DATA_DIR", data_dir), patch(
                "scanner.zap_proxy.AUTO_KEY_FILE", key_file
            ), patch(
                "scanner.zap_proxy.secrets.token_hex"
            ) as token_generator:
                from scanner.zap_proxy import _ensure_zap_api_key

                key = _ensure_zap_api_key()

            self.assertEqual(key, "existing-managed-key")
            token_generator.assert_not_called()

    def test_ignores_environment_api_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing_key_file = Path(temporary) / ".zap_auto_key"

            with patch(
                "scanner.zap_proxy.AUTO_KEY_FILE", missing_key_file
            ), patch.dict(
                "os.environ",
                {"SHADOW_MAP_ZAP_API_KEY": "manually-supplied-key"},
            ):
                self.assertIsNone(get_api_key())


if __name__ == "__main__":
    unittest.main()

class ZapScanLifecycleTests(unittest.TestCase):
    @staticmethod
    def make_response(data):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = data
        return response

    @patch("scanner.zap_proxy.time.sleep")
    @patch("scanner.zap_proxy.time.time", side_effect=[0, 0, 31])
    @patch("scanner.zap_proxy.requests.Session")
    def test_spider_timeout_does_not_start_active_scan(
        self, session_class, mocked_time, mocked_sleep
    ):
        session = session_class.return_value
        session.get.side_effect = [
            self.make_response({"scan": "1"}),
            self.make_response({"status": "50"}),
        ]

        with patch(
            "scanner.zap_proxy.get_api_key",
            return_value="test-only-key",
        ):
            result = trigger_zap_active_scan(
                "http://127.0.0.1:5000",
                endpoint="http://127.0.0.1:8090",
                timeout=30,
            )

        self.assertEqual(result["status"], "spider_timeout")
        self.assertEqual(result["spider_scan_id"], "1")
        self.assertIsNone(result["ascan_scan_id"])
        self.assertEqual(session.get.call_count, 2)
        session.close.assert_called_once()

    @patch("scanner.zap_proxy.time.sleep")
    @patch("scanner.zap_proxy.requests.Session")
    def test_active_scan_finished_returns_finished(
        self, session_class, mocked_sleep
    ):
        session = session_class.return_value
        session.get.side_effect = [
            self.make_response({"scan": "1"}),
            self.make_response({"status": "100"}),
            self.make_response({}),
            self.make_response({}),
            self.make_response({"scan": "2"}),
            self.make_response({
                "scans": [{
                    "id": "2",
                    "state": "FINISHED",
                    "progress": "100",
                }]
            }),
        ]

        with patch(
            "scanner.zap_proxy.get_api_key",
            return_value="test-only-key",
        ):
            result = trigger_zap_active_scan(
                "http://127.0.0.1:5000",
                endpoint="http://127.0.0.1:8090",
                timeout=30,
            )

        self.assertEqual(result["status"], "finished")
        self.assertEqual(result["spider_scan_id"], "1")
        self.assertEqual(result["ascan_scan_id"], "2")
        session.close.assert_called_once()




class ZapManagedProcessIdentityTests(unittest.TestCase):
    def test_accepts_matching_managed_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            command = [
                "java",
                "-jar",
                "/opt/zap/zap.jar",
                "-daemon",
                "-host", "127.0.0.1",
                "-port", "8090",
                "-dir", str(zap_home),
            ]

            with patch(
                "scanner.zap_proxy._get_process_command_line",
                return_value=command,
            ):
                self.assertTrue(
                    _process_matches_managed_zap(
                        1234, "http://127.0.0.1:8090", zap_home
                    )
                )

    def test_rejects_process_using_different_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "managed-zap-home"
            personal_home = Path(temporary) / "personal-zap-home"
            command = [
                "java", "-jar", "/opt/zap/zap.jar",
                "-daemon", "-host", "127.0.0.1",
                "-port", "8090", "-dir", str(personal_home),
            ]

            with patch(
                "scanner.zap_proxy._get_process_command_line",
                return_value=command,
            ):
                self.assertFalse(
                    _process_matches_managed_zap(
                        1234, "http://127.0.0.1:8090", zap_home
                    )
                )

    def test_rejects_process_using_different_endpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            command = [
                "java", "-jar", "/opt/zap/zap.jar",
                "-daemon", "-host", "127.0.0.1",
                "-port", "8080", "-dir", str(zap_home),
            ]

            with patch(
                "scanner.zap_proxy._get_process_command_line",
                return_value=command,
            ):
                self.assertFalse(
                    _process_matches_managed_zap(
                        1234, "http://127.0.0.1:8090", zap_home
                    )
                )

    def test_process_record_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "data"
            record_file = data_dir / ".zap_managed_process.json"
            process = Mock()
            process.pid = 4321

            with patch("scanner.zap_proxy.DATA_DIR", data_dir), patch(
                "scanner.zap_proxy.PROCESS_RECORD_FILE", record_file
            ):
                zap_home = root / "zap-home"
                _write_managed_process_record(
                    process, "http://127.0.0.1:8090", zap_home
                )
                record = _read_managed_process_record()

            self.assertEqual(record["pid"], 4321)
            self.assertEqual(record["endpoint"], "http://127.0.0.1:8090")
            self.assertEqual(
                record["zap_home"], str(zap_home.resolve())
            )
            self.assertFalse(record_file.with_suffix(".tmp").exists())

    def test_malformed_process_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            record_file = Path(temporary) / "invalid.json"
            record_file.write_text("{not valid json", encoding="utf-8")

            with patch(
                "scanner.zap_proxy.PROCESS_RECORD_FILE", record_file
            ):
                self.assertIsNone(_read_managed_process_record())



    def test_shutdown_stops_verified_managed_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "data"
            record_file = data_dir / ".zap_managed_process.json"
            zap_home = root / "tools" / "zap-home"
            process = Mock(pid=4321)

            _ = zap_home

            group_checks = {"count": 0}

            def fake_killpg(pgid, sig):
                if sig == 0:
                    group_checks["count"] += 1
                    if group_checks["count"] >= 3:
                        raise ProcessLookupError
                return None

            with patch("scanner.zap_proxy.DATA_DIR", data_dir), patch(
                "scanner.zap_proxy.PROCESS_RECORD_FILE", record_file
            ), patch(
                "scanner.zap_proxy.managed_zap_root",
                return_value=root / "tools" / "zap",
            ), patch(
                "scanner.zap_proxy._process_matches_managed_zap",
                return_value=True,
            ), patch(
                "scanner.zap_proxy.os.getpgid", return_value=4321
            ), patch(
                "scanner.zap_proxy.os.killpg",
                side_effect=fake_killpg,
            ) as killpg:
                _write_managed_process_record(
                    process, "http://127.0.0.1:8090", zap_home
                )

                result = shutdown_managed_zap(grace_seconds=0)

                self.assertTrue(result)
                self.assertFalse(record_file.exists())

            self.assertEqual(killpg.call_args_list[0].args, (4321, 15))
            self.assertIn(((4321, 9), {}), [call for call in killpg.call_args_list])

    def test_shutdown_does_nothing_without_process_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            record_file = Path(temporary) / "missing.json"

            with patch(
                "scanner.zap_proxy.PROCESS_RECORD_FILE", record_file
            ), patch(
                "scanner.zap_proxy.os.killpg"
            ) as killpg:
                self.assertFalse(shutdown_managed_zap())
                killpg.assert_not_called()

    def test_shutdown_does_not_touch_unverified_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "data"
            record_file = data_dir / ".zap_managed_process.json"
            zap_home = root / "tools" / "zap-home"

            with patch("scanner.zap_proxy.DATA_DIR", data_dir), patch(
                "scanner.zap_proxy.PROCESS_RECORD_FILE", record_file
            ), patch(
                "scanner.zap_proxy.managed_zap_root",
                return_value=root / "tools" / "zap",
            ), patch(
                "scanner.zap_proxy._process_matches_managed_zap",
                return_value=False,
            ), patch(
                "scanner.zap_proxy.os.killpg"
            ) as killpg:
                _write_managed_process_record(
                    Mock(pid=4321),
                    "http://127.0.0.1:8090",
                    zap_home,
                )

                self.assertFalse(shutdown_managed_zap())
                killpg.assert_not_called()
                self.assertTrue(record_file.exists())


class ZapManagedSessionLifecycleTests(unittest.TestCase):
    def _create_session_files(self, zap_home):
        session_dir = zap_home / "session"
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "shadow-map-grc.session.data").write_bytes(b"test-data")
        (session_dir / "shadow-map-grc.session.properties").write_text(
            "version=2.0\n", encoding="utf-8"
        )

    def test_first_start_creates_new_session_and_initializing_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"

            command_args = _prepare_managed_zap_session(zap_home)

            self.assertEqual(
                command_args,
                ["-newsession", "shadow-map-grc.session"],
            )
            manifest = _read_managed_session_manifest(zap_home)
            self.assertEqual(manifest["status"], "initializing")
            self.assertFalse(_managed_session_artifacts_exist(zap_home))

    def test_existing_ready_session_is_reopened(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            self._create_session_files(zap_home)
            _write_managed_session_manifest(zap_home, "ready")

            command_args = _prepare_managed_zap_session(zap_home)

            self.assertEqual(
                command_args,
                ["-session", "shadow-map-grc.session"],
            )

    def test_incomplete_initialization_is_not_recreated(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            _write_managed_session_manifest(zap_home, "initializing")

            with self.assertRaisesRegex(
                ZapProxyError, "incomplete initialization"
            ):
                _prepare_managed_zap_session(zap_home)

    def test_missing_session_database_is_not_recreated(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            _write_managed_session_manifest(zap_home, "ready")

            with self.assertRaisesRegex(
                ZapProxyError, "missing or incomplete"
            ):
                _prepare_managed_zap_session(zap_home)

    def test_untracked_session_files_are_not_adopted_or_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            self._create_session_files(zap_home)

            with self.assertRaisesRegex(
                ZapProxyError, "no Shadow Map session manifest"
            ):
                _prepare_managed_zap_session(zap_home)

            self.assertTrue(_managed_session_artifacts_exist(zap_home))

    def test_corrupt_manifest_is_rejected_without_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            zap_home.mkdir(parents=True)
            manifest_path = zap_home / ".shadow-map-session.json"
            original = "{broken json"
            manifest_path.write_text(original, encoding="utf-8")

            with self.assertRaisesRegex(
                ZapProxyError, "corrupted"
            ):
                _prepare_managed_zap_session(zap_home)

            self.assertEqual(
                manifest_path.read_text(encoding="utf-8"), original
            )

    def test_inconsistent_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            _write_managed_session_manifest(zap_home, "ready")
            manifest_path = zap_home / ".shadow-map-session.json"
            record = _read_managed_session_manifest(zap_home)
            record["session_name"] = "different.session"
            import json
            manifest_path.write_text(json.dumps(record), encoding="utf-8")

            with self.assertRaisesRegex(
                ZapProxyError, "inconsistent"
            ):
                _prepare_managed_zap_session(zap_home)

    def test_ready_marker_requires_session_database_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "zap-home"
            self._create_session_files(zap_home)
            _write_managed_session_manifest(zap_home, "initializing")

            from scanner.zap_proxy import _mark_managed_zap_session_ready
            _mark_managed_zap_session_ready(zap_home)

            manifest = _read_managed_session_manifest(zap_home)
            self.assertEqual(manifest["status"], "ready")


class ZapAutomaticStartupTests(unittest.TestCase):

    @patch("scanner.zap_proxy.platform.system", return_value="Linux")
    @patch("scanner.zap_proxy.subprocess.Popen")
    @patch("scanner.zap_proxy._require_java_17")
    @patch("scanner.zap_proxy.detect_zap", return_value={
        "installed": True,
        "path": "/usr/bin/zaproxy",
        "method": "PATH",
    })
    @patch("scanner.zap_proxy._ensure_zap_api_key", return_value="test-api-key")
    @patch(
        "scanner.zap_proxy.test_connection",
        side_effect=[
            ZapProxyError("Not authenticated"),
            {"connected": True, "version": "2.17.0"},
        ],
    )
    def test_linux_startup_uses_application_managed_zap_home(
        self, connection, key, detect, java_check, popen, system
    ):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            data_home = home / ".local" / "share"
            managed_root = data_home / "shadow-map-grc" / "tools" / "zap"

            test_data = Path(temporary) / "shadow-map-data"
            with patch("scanner.zap_proxy.Path.home", return_value=home):
                with patch.dict(
                    "os.environ",
                    {"XDG_DATA_HOME": str(data_home)},
                ), patch("scanner.zap_proxy.DATA_DIR", test_data), patch(
                    "scanner.zap_proxy.PROCESS_RECORD_FILE",
                    test_data / ".zap_managed_process.json",
                ), patch(
                    "scanner.zap_proxy._is_managed_zap_process",
                    return_value=True,
                ):
                    popen.return_value.pid = 12345

                    def api_check(*args, **kwargs):
                        if connection.call_count == 1:
                            raise ZapProxyError("Not authenticated")
                        session_base = (
                            managed_root.parent
                            / "zap-home"
                            / "session"
                            / "shadow-map-grc.session"
                        )
                        session_base.parent.mkdir(parents=True, exist_ok=True)
                        session_base.with_name(session_base.name + ".data").touch()
                        session_base.with_name(
                            session_base.name + ".properties"
                        ).touch()
                        return {"connected": True, "version": "2.17.0"}

                    connection.side_effect = api_check
                    result = ensure_zap_running("http://127.0.0.1:8090")

            self.assertEqual(
                result,
                {"connected": True, "version": "2.17.0"},
            )

            command = popen.call_args.args[0]
            self.assertIn("-dir", command)
            self.assertEqual(
                Path(command[command.index("-dir") + 1]),
                managed_root.parent / "zap-home",
            )
            self.assertNotEqual(
                Path(command[command.index("-dir") + 1]),
                home / ".ZAP",
            )


    @patch("scanner.zap_proxy.subprocess.Popen")
    @patch("scanner.zap_proxy._require_java_17")
    @patch("scanner.zap_proxy._ensure_zap_api_key", return_value="test-api-key")
    @patch(
        "scanner.zap_proxy.test_connection",
        return_value={"connected": True, "version": "2.17.0"},
    )
    def test_rejects_existing_zap_without_verified_process_ownership(
        self, connection, key, java_check, popen
    ):
        with patch(
            "scanner.zap_proxy._is_managed_zap_process",
            return_value=False,
        ):
            with self.assertRaisesRegex(
                ZapProxyError, "cannot verify that the process uses its managed profile"
            ):
                ensure_zap_running("http://127.0.0.1:8090")

        connection.assert_called_once_with("http://127.0.0.1:8090")
        java_check.assert_not_called()
        popen.assert_not_called()

    def _assert_existing_process_rejects_session(self, manifest_status=None):
        with tempfile.TemporaryDirectory() as temporary:
            managed_root = Path(temporary) / "tools" / "zap"
            zap_home = managed_root.parent / "zap-home"

            if manifest_status is not None:
                _write_managed_session_manifest(zap_home, manifest_status)

            with patch(
                "scanner.zap_proxy._ensure_zap_api_key",
                return_value="test-api-key",
            ), patch(
                "scanner.zap_proxy.test_connection",
                return_value={"connected": True, "version": "2.17.0"},
            ), patch(
                "scanner.zap_proxy.managed_zap_root",
                return_value=managed_root,
            ), patch(
                "scanner.zap_proxy._is_managed_zap_process",
                return_value=True,
            ), patch(
                "scanner.zap_proxy.subprocess.Popen"
            ) as popen:
                with self.assertRaises(ZapProxyError):
                    ensure_zap_running("http://127.0.0.1:8090")

                popen.assert_not_called()

    def test_existing_process_rejects_missing_session_manifest(self):
        self._assert_existing_process_rejects_session()

    def test_existing_process_rejects_initializing_session(self):
        self._assert_existing_process_rejects_session("initializing")

    def test_existing_process_rejects_missing_session_database(self):
        self._assert_existing_process_rejects_session("ready")

    @patch("scanner.zap_proxy.subprocess.Popen")
    @patch("scanner.zap_proxy._require_java_17")
    @patch("scanner.zap_proxy._ensure_zap_api_key", return_value="test-api-key")
    @patch(
        "scanner.zap_proxy.test_connection",
        return_value={"connected": True, "version": "2.17.0"},
    )
    def test_reuses_existing_zap_only_after_process_ownership_verification(
        self, connection, key, java_check, popen
    ):
        with tempfile.TemporaryDirectory() as temporary:
            zap_home = Path(temporary) / "tools" / "zap-home"
            session_dir = zap_home / "session"
            session_dir.mkdir(parents=True)

            session_base = session_dir / "shadow-map-grc.session"
            session_base.with_name(session_base.name + ".data").touch()
            session_base.with_name(
                session_base.name + ".properties"
            ).touch()

            _write_managed_session_manifest(zap_home, "ready")

            with patch(
                "scanner.zap_proxy.managed_zap_root",
                return_value=Path(temporary) / "tools" / "zap",
            ), patch(
                "scanner.zap_proxy._is_managed_zap_process",
                return_value=True,
            ):
                result = ensure_zap_running("http://127.0.0.1:8090")

        self.assertEqual(
            result,
            {"connected": True, "version": "2.17.0"},
        )
        connection.assert_called_once_with("http://127.0.0.1:8090")
        java_check.assert_not_called()
        popen.assert_not_called()

    @patch("scanner.zap_proxy.time.sleep")
    @patch("scanner.zap_proxy.time.monotonic", side_effect=[0, 100, 101])
    @patch("scanner.zap_proxy.subprocess.Popen")
    @patch("scanner.zap_proxy.shutil.which", return_value="/usr/bin/java")
    @patch("scanner.zap_proxy.subprocess.run")
    @patch("scanner.zap_proxy.detect_zap", return_value={"installed": False})
    @patch(
        "scanner.zap_proxy.install_zap",
        return_value={
            "installed": True,
            "path": "/managed/zap/zap-2.17.0.jar",
            "method": "Shadow Map managed installation",
        },
    )
    @patch("scanner.zap_proxy._ensure_zap_api_key", return_value="test-api-key")
    @patch(
        "scanner.zap_proxy.test_connection",
        side_effect=[
            ZapProxyError("ZAP is not running"),
            {"connected": True, "version": "2.17.0"},
        ],
    )
    def test_starts_managed_jar_and_waits_for_api(
        self,
        connection,
        key,
        install,
        detect,
        java_run,
        java_which,
        popen,
        monotonic,
        sleep,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_dir = root / "data"
            managed_root = root / "tools" / "zap"

            java_run.return_value = Mock(
                returncode=0,
                stdout="",
                stderr='openjdk version "21.0.1"',
            )

            process = Mock()
            process.pid = 12346
            process.poll.return_value = None
            popen.return_value = process

            with patch("scanner.zap_proxy.DATA_DIR", data_dir), patch(
                "scanner.zap_proxy.PROCESS_RECORD_FILE",
                data_dir / ".zap_managed_process.json",
            ), patch(
                "scanner.zap_proxy.managed_zap_root",
                return_value=managed_root,
            ), patch(
                "scanner.zap_proxy._is_managed_zap_process",
                return_value=True,
            ):
                def api_check(*args, **kwargs):
                    if connection.call_count == 1:
                        raise ZapProxyError("ZAP is not running")
                    session_base = (
                        managed_root.parent
                        / "zap-home"
                        / "session"
                        / "shadow-map-grc.session"
                    )
                    session_base.parent.mkdir(parents=True, exist_ok=True)
                    session_base.with_name(session_base.name + ".data").touch()
                    session_base.with_name(
                        session_base.name + ".properties"
                    ).touch()
                    return {"connected": True, "version": "2.17.0"}

                connection.side_effect = api_check
                result = ensure_zap_running(
                    "http://127.0.0.1:8090"
                )

            self.assertEqual(
                result,
                {"connected": True, "version": "2.17.0"},
            )
            detect.assert_called_once()
            install.assert_called_once()
            java_run.assert_called_once()
            popen.assert_called_once()

            command = popen.call_args.args[0]
            self.assertIn("-jar", command)
            self.assertIn("/managed/zap/zap-2.17.0.jar", command)
            self.assertIn("-daemon", command)
            self.assertIn("api.key=test-api-key", command)
            self.assertIn("-dir", command)
            dir_index = command.index("-dir")
            self.assertEqual(
                Path(command[dir_index + 1]),
                managed_root.parent / "zap-home",
            )

            self.assertEqual(connection.call_count, 2)
            process.poll.assert_not_called()
