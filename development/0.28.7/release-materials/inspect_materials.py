#!/usr/bin/env python3
"""Read-only inspection of two compiled Windows binaries and one pinned published DNS motor candidate.

Not a release assembler, signer, installer or publication action. This tool
must never label missing or unsigned assets as suitable for installation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

SCHEMA = 1
COMPONENTS = {
    "centro-updater": "VOLVE_Centro_Updater.exe",
    "dns-motor": "VOLVE_DNS_Motor_0_28_7.exe",
    "motor-manifest": "VOLVE_DNS_Motor_0_28_7.exe.json",
    "motor-signature": "VOLVE_DNS_Motor_0_28_7.exe.sig",
    "system-watchdog": "VOLVE_Managed_Watchdog.exe",
    "uninstaller": "VOLVE_Uninstall.exe",
    "browser-policies": "VOLVE_Browser_Policies.json",
    "full-catalog": "VOLVE_Full_Catalog.txt",
}
BUILT_ROLES = ("centro-updater", "system-watchdog")
MAX_BYTES = 128 * 1024 * 1024
# Historical editor-signed DNS candidate, NOT the production installer motor.
# Verified independently with original Go motorupdate.VerifyStaged in Windows CI.
PUBLISHED_MOTOR_SHA256 = "e451b6289116636986ddd67b39dc15f02e471ebde7be9508b38d7bcb0155b414"
PUBLISHED_MOTOR_BYTES = 18168832


def require_matching_go_contract(contract_path: Path) -> None:
    """Fail if the exact 8-role contract in Go differs from the auditor."""
    data = contract_path.read_text(encoding="utf-8")
    match = re.search(r"var\s+requiredComponents\s*=\s*map\[string\]string\s*\{(.*?)\n\}", data, re.S)
    if not match:
        raise ValueError("cannot inspect the authoritative Go component contract")
    found = dict(re.findall(r'"([a-z][a-z-]*)"\s*:\s*"([^"]+)"', match.group(1)))
    if found != COMPONENTS:
        raise ValueError("component manifest differs from original verified Go contract")


def inspect_windows_amd64_exe(path: Path) -> dict:
    """Inspect DOS/NT/PE32+ header, bound byte count, SHA256, no links."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("compiled candidate path must be absolute")
    stat = path.lstat()
    if not path.is_file() or path.is_symlink() or stat.st_size < 1048576 or stat.st_size > MAX_BYTES:
        raise ValueError("candidate must be real, bounded Windows executable")
    with path.open("rb") as stream:
        hdr = stream.read(0x1000)
        if len(hdr) < 0x100 or hdr[:2] != b"MZ":
            raise ValueError("Windows MZ header missing")
        pe_offset = struct.unpack_from("<I", hdr, 0x3C)[0]
        if pe_offset < 0x40 or pe_offset + 26 > len(hdr):
            raise ValueError("Windows PE offset missing or excessive")
        if hdr[pe_offset:pe_offset+4] != b"PE\x00\x00":
            raise ValueError("not a Windows NT executable")
        machine = struct.unpack_from("<H", hdr, pe_offset+4)[0]
        optional_magic = struct.unpack_from("<H", hdr, pe_offset+24)[0]
        if machine != 0x8664 or optional_magic != 0x20B:
            raise ValueError("expected PE32+ x64 (not x86, ARM or raw bytes)")
        stream.seek(0)
        digest = hashlib.sha256()
        measured = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            measured += len(chunk)
            if measured > MAX_BYTES:
                raise ValueError("candidate file exceeded size bound during hashing")
    after = path.stat()
    if after.st_size != measured or (stat.st_dev, stat.st_ino) != (after.st_dev, after.st_ino):
        raise ValueError("candidate changed during hashing")
    return {"bytes": measured, "sha256": digest.hexdigest(), "pe": "PE32+ x64"}


def build_report(centro: Path, watchdog: Path, go_contract: Path, pinned_motor: Path | None = None) -> dict:
    require_matching_go_contract(go_contract)
    supplied = {
        "centro-updater": inspect_windows_amd64_exe(centro),
        "system-watchdog": inspect_windows_amd64_exe(watchdog),
    }
    if supplied["centro-updater"]["sha256"] == supplied["system-watchdog"]["sha256"]:
        raise ValueError("Centro and independent recovery cannot be the same PE")
    if pinned_motor is not None:
        motor_info = inspect_windows_amd64_exe(pinned_motor)
        if (motor_info["sha256"], motor_info["bytes"]) != (PUBLISHED_MOTOR_SHA256, PUBLISHED_MOTOR_BYTES):
            raise ValueError("published DNS candidate not exact, pinned, previously authenticated bytes")
        if motor_info["sha256"] in {part["sha256"] for part in supplied.values()}:
            raise ValueError("published DNS motor cannot alias Centro or watchdog")
        supplied["dns-motor"] = motor_info
    materials = [
        {
            "id": role,
            "filename": filename,
            "state": (
                "PINNED_HISTORIC_SIGNED_DNS_CANDIDATE_NOT_INSTALLABLE" if role == "dns-motor" and role in supplied
                else "BUILT_CI_UNSIGNED_NOT_INSTALLABLE" if role in supplied
                else "MISSING_PRODUCTION_RELEASE_INPUT"
            ),
            **supplied.get(role, {}),
        }
        for role, filename in COMPONENTS.items()
    ]
    return {
        "schema": SCHEMA,
        "target_release": "0.28.7",
        "platform": "windows-amd64",
        "artifact_type": "CI_BUILD_MATERIALS_AUDIT_NO_RELEASE",
        "materials": materials,
        "checked_compiled_roles": len(BUILT_ROLES),
        "checked_historic_candidate_roles": 1 if pinned_motor is not None else 0,
        "checked_build_material_roles": len(supplied),
        "missing_production_release_roles": len(COMPONENTS),
        "publisher_authenticode_verified_for_release": False,
        "ed25519_release_manifest_verified": False,
        "signed_legacy_migration_permit_verified": False,
        "production_install_authorized": False,
        "can_modify_dns_or_tasks": False,
        "can_publish_release": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--centro", type=Path, required=True)
    parser.add_argument("--watchdog", type=Path, required=True)
    parser.add_argument("--pinned-published-motor", type=Path, help="Historic v0.28.7 exact-pinned motor, verified by Go publisher-signature gate in CI")
    parser.add_argument("--go-contract", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.centro, args.watchdog, args.go_contract, args.pinned_published_motor)
    if not args.report.is_absolute() or args.report.parent.is_symlink():
        raise ValueError("audit destination must be an absolute nonlinked directory")
    if args.report.exists():
        raise ValueError("audit report must be create-only")
    with args.report.open("x", encoding="utf-8", newline="\n") as out:
        json.dump(report, out, sort_keys=True, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    print("PASS VOLVE_0287_REAL_CENTRO_AND_WATCHDOG_CI_BUILDS")
    print("NO_RELEASE NO_AUTHENTICODE_PUBLISHER NO_INSTALL NO_DNS_CHANGE")
    print(f"release-components={len(report['materials'])}; compiled-ci={report['checked_compiled_roles']}; pinned-published-candidate={report['checked_historic_candidate_roles']}; approved-product=0")
    print(json.dumps({m["id"]: m.get("sha256", "MISSING") for m in report["materials"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f"FAIL_CLOSED_VOLVE_MATERIALS: {exc}", file=sys.stderr)
        sys.exit(1)
