#!/usr/bin/env python3
"""CI-only evidence capture of the exact upstream HaGeZi gambling domain list.

No install, DNS change, browser policy change, publication or release. The
pinned source is GPL-3.0 licensed; product redistribution needs a separate
license compliance and functional compatibility review.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

UPSTREAM = "hagezi/dns-blocklists"
COMMIT = "81bbd1b9009893d65358146b23282647634c26be"
BLOB_SHA1 = "096ce47515721f7aac2ce8138fb5b421aa6fb1e1"
BYTE_COUNT = 11040215
SOURCE_URL = (
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/"
    f"{COMMIT}/wildcard/gambling-onlydomains.txt"
)
MIN_DOMAIN_COUNT = 400000
MAX_DOMAIN_COUNT = 1500000
MAX_BYTES = 24 * 1024 * 1024
DOMAIN = re.compile(rb"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

def inspect_catalog(
    raw: bytes,
    expected_blob: str = BLOB_SHA1,
    expected_size: int = BYTE_COUNT,
    minimum: int = MIN_DOMAIN_COUNT,
) -> dict:
    if len(raw) != expected_size or len(raw) > MAX_BYTES or len(raw) < 1:
        raise ValueError("unpinned gambling catalog length")
    if git_blob_sha1(raw) != expected_blob:
        raise ValueError("upstream gambling Git blob does not match pinned source")
    if b"\0" in raw or b"\r" in raw:
        raise ValueError("binary or noncanonical line termination")
    seen: set[bytes] = set()
    comments = 0
    for line_num, record in enumerate(raw.split(b"\n"), start=1):
        if not record:
            continue
        if record.startswith(b"#"):
            comments += 1
            continue
        if record.startswith(b"*."):
            record = record[2:]
        if len(record) > 253 or not DOMAIN.fullmatch(record):
            raise ValueError(f"non-domain or malformed entry at line {line_num}")
        if record in seen:
            raise ValueError(f"duplicate domain in pinned upstream catalog at line {line_num}")
        seen.add(record)
        if len(seen) > MAX_DOMAIN_COUNT:
            raise ValueError("overlarge gambling domain count")
    if len(seen) < minimum:
        raise ValueError(f"incomplete gambling catalog; got {len(seen)} valid domains")
    return {
        "schema": 1,
        "component": "full-catalog-upstream-source-only",
        "source": UPSTREAM,
        "commit": COMMIT,
        "git_blob_sha1": expected_blob,
        "source_url": SOURCE_URL,
        "license": "GPL-3.0",
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "domain_count": len(seen),
        "comment_lines": comments,
        "source_verified": True,
        "compatible_with_dns_motor_verified": False,
        "production_install_authorized": False,
        "publish_release_authorized": False,
    }

def download_pinned_catalog() -> bytes:
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "VOLVE-0287-CI-readonly/1.0"})
    with urllib.request.urlopen(req, timeout=90) as response:
        if response.geturl() != SOURCE_URL:
            raise ValueError("unpinned redirect in catalog source")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("upstream source exceeded configured bound")
    return data

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    temporary = os.environ.get("RUNNER_TEMP")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or not temporary
        or not Path(temporary).is_absolute()
        or args.out != Path(temporary) / "VOLVE_Full_Catalog.txt"
        or args.receipt != Path(temporary) / "VOLVE_Full_Catalog_SOURCE_ONLY.json"
        or args.out.exists() or args.receipt.exists()
    ):
        raise ValueError("only fresh GitHub-hosted disposable CI destinations are authorized")
    data = download_pinned_catalog()
    evidence = inspect_catalog(data)
    with args.out.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    with args.receipt.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    print(
        f"PASS VOLVE_HAGEZI_FULL_PINNED_SOURCE size={evidence['size']} "
        f"domains={evidence['domain_count']} sha256={evidence['sha256']} "
        "LICENSE_REVIEW_REQUIRED NO_INSTALL NO_RELEASE NO_DNS_CHANGE"
    )
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"FAIL_CLOSED_VOLVE_HAGEZI_SOURCE: {exc}", file=sys.stderr)
        sys.exit(1)
