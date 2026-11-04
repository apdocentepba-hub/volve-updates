"""Mandatory adversarial tests of the CI-only release-material inventory."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

import inspect_materials as inspector


def synthetic_pe(path: Path, salt: bytes = b"A") -> None:
    data = bytearray(b"\x00" * (1_048_576 + 16))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x98, 0x20B)
    data[-1:] = salt
    path.write_bytes(data)


class BuildMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.centro = self.folder / "centro.exe"
        self.watchdog = self.folder / "watchdog.exe"
        synthetic_pe(self.centro, b"1")
        synthetic_pe(self.watchdog, b"2")
        self.contract = self.folder / "bundle.go"
        entries = "\n".join(
            ' "%s":"%s",' % pair for pair in inspector.COMPONENTS.items()
        )
        self.contract.write_text(
            'var requiredComponents = map[string]string{\n%s\n}\n' % entries,
            encoding="utf-8",
        )

    def test_two_distinct_ci_materials_never_approve_eight_release_parts(self):
        report = inspector.build_report(self.centro, self.watchdog, self.contract)
        self.assertEqual(report["checked_compiled_roles"], 2)
        self.assertEqual(report["missing_production_release_roles"], 8)
        self.assertEqual(len(report["materials"]), 8)
        for permission in ("production_install_authorized", "can_modify_dns_or_tasks", "can_publish_release", "ed25519_release_manifest_verified", "publisher_authenticode_verified_for_release"):
            self.assertIs(report[permission], False)
        self.assertEqual(sum("sha256" in x for x in report["materials"]), 2)
        self.assertEqual(len(set(x.get("sha256") for x in report["materials"] if "sha256" in x)), 2)
        self.assertTrue(all("INSTALLABLE" not in x["state"] or "NOT_INSTALLABLE" in x["state"] for x in report["materials"]))
        self.assertEqual(report["materials"][-1]["state"], "MISSING_PRODUCTION_RELEASE_INPUT")

    def test_rejects_wrong_pe_architecture_and_truncated_file(self):
        data = bytearray(self.centro.read_bytes())
        for offset, bad in ((0, b"XX"), (0x84, b"\x4c\x01"), (0x98, b"\x0b\x01")):
            changed = bytearray(data)
            changed[offset:offset+len(bad)] = bad
            self.centro.write_bytes(changed)
            with self.assertRaises(ValueError):
                inspector.inspect_windows_amd64_exe(self.centro)
        self.centro.write_bytes(data[:400])
        with self.assertRaises(ValueError):
            inspector.inspect_windows_amd64_exe(self.centro)

    def test_rejects_symlink_and_missing_binary(self):
        pointer = self.folder / "centro-link.exe"
        try:
            pointer.symlink_to(self.centro)
        except OSError:
            self.skipTest("symlink creation unavailable on host")
        with self.assertRaises(ValueError):
            inspector.inspect_windows_amd64_exe(pointer)
        self.watchdog.unlink()
        with self.assertRaises(OSError):
            inspector.build_report(self.centro, self.watchdog, self.contract)

    def test_rejects_duplicate_binary_roles(self):
        self.watchdog.write_bytes(self.centro.read_bytes())
        with self.assertRaises(ValueError):
            inspector.build_report(self.centro, self.watchdog, self.contract)

    def test_go_contract_drift_rejected_before_report(self):
        self.contract.write_text(self.contract.read_text().replace(
            'VOLVE_Full_Catalog.txt', 'VOLVE_Fake_Catalog.txt'), encoding="utf-8")
        with self.assertRaises(ValueError):
            inspector.build_report(self.centro, self.watchdog, self.contract)

    def test_real_repo_contract_if_present(self):
        real = Path(__file__).resolve().parent.parent / "unifiedbundle" / "bundle.go"
        if real.exists():
            inspector.require_matching_go_contract(real)


if __name__ == "__main__":
    unittest.main()
