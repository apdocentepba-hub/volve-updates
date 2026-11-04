#!/usr/bin/env python3
"""Restore exact audited historical singlefile source for a CI-only real bundle.

No installation, external keys or distribution are performed by this helper.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import tarfile

ROOT=Path(__file__).resolve().parents[1]
SINGLE_SHA="01294e1d5ce51928098d30bd90f04b7979e1764993d4b419c66489b67676e215"
AUTH_SHA="cdb9cb776552ee9a08668aae71e8031c7b3d4fb3b6fadf6e6690abfb20fc36a0"

def open_pinned(path:Path,digest:str):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
        raise ValueError(f"Untrusted historical source archive: {path.name}")
    return tarfile.open(path,"r:xz")

def main():
    package=ROOT/"singlefile"
    if package.exists():
        raise ValueError("refuse existing singlefile output, must use clean CI checkout")
    with open_pinned(ROOT/"singlefile-src.tar.xz",SINGLE_SHA) as archive:
        members=archive.getmembers()
        if not members or len(members)>120:
            raise ValueError("unexpected historical source count")
        seen=set()
        for item in members:
            parts=Path(item.name).parts
            if not item.isfile() or len(parts)<2 or parts[0]!="singlefile" or ".." in parts or item.name in seen:
                raise ValueError("unsafe signed source item")
            seen.add(item.name)
            target=ROOT/item.name
            if target.exists():raise ValueError(f"existing source entry: {item.name}")
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(archive.extractfile(item).read())
    for rel in ("staging.go","staging_test.go","cmd/stageci/main.go",
                "cmd/stageci/publisher_windows.go","cmd/stageci/publisher_nonwindows.go"):
        source=ROOT/"singlefile-overlay"/rel
        target=package/rel
        if not source.is_file():raise ValueError(f"missing staging overlay: {rel}")
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(source.read_bytes())
    with open_pinned(ROOT/"authenticode-overlay.tar.xz",AUTH_SHA) as archive:
        members=archive.getmembers()
        if {m.name for m in members}!={"authenticode_windows.go","authenticode_windows_test.go"}:
            raise ValueError("unexpected Authenticode historical files")
        for item in members:
            if not item.isfile() or item.size>65536 or "/" in item.name or ".." in item.name:
                raise ValueError("unsafe Authenticode archive member")
            path=package/item.name
            if path.exists():raise ValueError("unexpected existing Authenticode item")
            path.write_bytes(archive.extractfile(item).read())
    verified=ROOT/"authenticode-source"/"authenticode_windows.go"
    if b"EncodedCommand" not in verified.read_bytes():raise ValueError("reviewed Authenticode source marker missing")
    (package/"authenticode_windows.go").write_bytes(verified.read_bytes())
    print("PASS VOLVE_RESTORED_PINNED_SINGLEFILE_BOOTSTRAP_WINDOWS NO_INSTALL NO_RELEASE")

if __name__=="__main__":
    main()
