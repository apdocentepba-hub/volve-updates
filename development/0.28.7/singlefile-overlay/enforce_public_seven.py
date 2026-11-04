#!/usr/bin/env python3
"""Fail-closed adaptation of pinned historical CI-only Go sources to the seven-file PUBLIC bundle.

The published installer MUST NOT bundle VOLVE_Uninstall.exe. The owner's private
recovery/removal program is separately controlled and never distributed with
VOLVE_Setup, updates, downloadable artifacts or CI release assets.

The signed source archive remains immutable and sha256-pinned in the workflow.
This explicit adaptation is applied only after extraction and before compilation.
"""
from pathlib import Path
import sys

SOURCE = Path(__file__).resolve().parent.parent / "singlefile"


def replace_once(path: Path, before: str, after: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(before)
    if count != 1:
        raise ValueError(f"FAIL_CLOSED {path.name}: expected one source anchor, got {count}: {before!r}")
    path.write_text(text.replace(before, after), encoding="utf-8")


def run() -> None:
    if not SOURCE.is_dir():
        raise ValueError("historical singlefile Go sources have not been authenticated and extracted")
    test_file = SOURCE / "singlefile_test.go"
    staging_test = SOURCE / "staging_test.go"
    replace_once(test_file, "len(m.Components) != 8", "len(m.Components) != 7")
    replace_once(staging_test, "len(m.Components)!=8", "len(m.Components)!=7")
    # Invert the old test: removing an expected eighth file becomes ADDING a
    # forbidden owner-only executable. The signed bundle must reject extras.
    replace_once(
        test_file,
        'os.Remove(filepath.Join(root, "VOLVE_Uninstall.exe"))',
        'os.WriteFile(filepath.Join(root, "VOLVE_Uninstall.exe"), []byte("owner-private-removal-tool-forbidden-in-public-bundle"), 0600)',
    )
    replace_once(test_file, "missing uninstaller accepted", "owner-only uninstaller inside public bundle accepted")
    for path in (test_file, staging_test):
        data = path.read_text(encoding="utf-8")
        if "len(m.Components) != 8" in data or "len(m.Components)!=8" in data:
            raise ValueError("obsolete eight-file acceptance test remains")
    # Original code uses unifiedbundle.RequiredFiles() as its authoritative
    # manifest. Reject accidental reintroduction of the owner-only executable.
    contract = SOURCE.parent / "unifiedbundle" / "bundle.go"
    data = contract.read_text(encoding="utf-8")
    if '"uninstaller":"VOLVE_Uninstall.exe"' in data or '"uninstaller": "VOLVE_Uninstall.exe"' in data:
        raise ValueError("public component contract contains private uninstaller")
    print("PASS: PUBLIC_SEVEN_COMPONENT_SOURCE_MIGRATION; PRIVATE_UNINSTALLER_EXCLUDED; NO_INSTALL NO_DNS_CHANGE")


if __name__ == "__main__":
    try:
        run()
    except (OSError, ValueError) as error:
        print(f"FAIL_CLOSED_PUBLIC_SEVEN: {error}", file=sys.stderr)
        raise SystemExit(1)
