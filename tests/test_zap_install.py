import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.zap_install import (
    ZAP_VERSION,
    detect_zap,
    install_zap,
)


class ZapInstallTests(unittest.TestCase):
    @patch("scanner.zap_install.platform.system", return_value="Linux")
    @patch("scanner.zap_install.Path.is_file", return_value=False)
    @patch("scanner.zap_install.shutil.which", return_value="/usr/bin/zaproxy")
    def test_detects_zap_on_path(self, _which, _is_file, _system):
        result = detect_zap()
        self.assertTrue(result["installed"])
        self.assertEqual(result["path"], "/usr/bin/zaproxy")
        self.assertEqual(result["method"], "PATH")

    @patch("scanner.zap_install.platform.system", return_value="Linux")
    @patch("scanner.zap_install.Path.is_file", return_value=False)
    @patch("scanner.zap_install.shutil.which", return_value=None)
    @patch("scanner.zap_install.Path.exists", return_value=False)
    def test_reports_missing_zap(self, _exists, _which, _is_file, _system):
        result = detect_zap()
        self.assertFalse(result["installed"])
        self.assertIn("download_url", result)
        self.assertIn("Java 17", result["guidance"])

    @patch("scanner.zap_install.platform.system", return_value="Linux")
    @patch("scanner.zap_install.Path.is_file", return_value=False)
    @patch("scanner.zap_install.shutil.which", return_value=None)
    @patch("scanner.zap_install._managed_zap_jar")
    @patch("scanner.zap_install.Path.exists", return_value=False)
    def test_detects_managed_installation(
        self, _exists, managed_jar, _which, _is_file, _system
    ):
        managed_jar.return_value = Path("/managed/zap/zap.jar")
        result = detect_zap()
        self.assertTrue(result["installed"])
        self.assertEqual(result["method"], "Shadow Map managed installation")
        self.assertEqual(result["path"], "/managed/zap/zap.jar")

    def _make_archive(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                f"ZAP_{ZAP_VERSION}/zap-{ZAP_VERSION}.jar",
                b"test zap jar",
            )
        return buffer.getvalue()

    def test_installs_verified_archive_to_managed_directory(self):
        archive_bytes = self._make_archive()
        expected_hash = hashlib.sha256(archive_bytes).hexdigest()

        response = MagicMock()
        response.headers = {"Content-Length": str(len(archive_bytes))}
        response.iter_content.return_value = [archive_bytes]
        response.raise_for_status.return_value = None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "managed-zap"

            with (
                patch("scanner.zap_install.managed_zap_root", return_value=root),
                patch("scanner.zap_install.requests.get", return_value=response),
                patch("scanner.zap_install.ZAP_ARCHIVE_SHA256", expected_hash),
            ):
                result = install_zap()

            self.assertTrue(result["installed"])
            self.assertEqual(result["version"], ZAP_VERSION)
            self.assertTrue(Path(result["path"]).is_file())
            self.assertEqual(Path(result["path"]).read_bytes(), b"test zap jar")
            response.close.assert_called_once()

    def test_rejects_checksum_mismatch(self):
        archive_bytes = self._make_archive()

        response = MagicMock()
        response.headers = {"Content-Length": str(len(archive_bytes))}
        response.iter_content.return_value = [archive_bytes]
        response.raise_for_status.return_value = None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "managed-zap"

            with (
                patch("scanner.zap_install.managed_zap_root", return_value=root),
                patch("scanner.zap_install.requests.get", return_value=response),
                patch("scanner.zap_install.ZAP_ARCHIVE_SHA256", "0" * 64),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "checksum verification failed"
                ):
                    install_zap()

            self.assertFalse((root / ZAP_VERSION).exists())

    def test_rejects_cross_platform_zip_traversal_paths(self):
        from scanner.zap_install import _safe_extract_zip

        unsafe_names = (
            "../outside.txt",
            r"..\\..\\outside.txt",
            r"C:\\Windows\\outside.txt",
            r"\\\\server\\share\\outside.txt",
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "extract"
            destination.mkdir()

            for index, unsafe_name in enumerate(unsafe_names):
                with self.subTest(path=unsafe_name):
                    archive_path = root / f"unsafe-{index}.zip"

                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr(unsafe_name, "unsafe")

                    with self.assertRaisesRegex(
                        RuntimeError, "unsafe file path"
                    ):
                        _safe_extract_zip(archive_path, destination)


if __name__ == "__main__":
    unittest.main()
