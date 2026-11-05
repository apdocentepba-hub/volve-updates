#!/usr/bin/env python3
"""CI-only evidence capture of the exact upstream HaGeZi gambling domain list.

No install, DNS change, browser policy change, publication or release. The
pinned source is GPL-3.0 licensed; product redistribution needs a separate
license compliance and functional compatibility review.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

UPSTREAM = "hagezi/dns-blocklists"
COMMIT = "81bbd1b9009893d65358146b23282647634c26be"
BLOB_SHA1 = "096ce47515721f7aac2ce8138fb5b421aa6fb1e1"
BYTE_COUNT = 11040215
SHA256_PIN = "ec700a88cdaedcc90cd482105ecbdeb7177289029303d61e35365ed1ea9c2347"
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
        # Bare and wildcard records are intentionally distinct: preserve the
        # upstream rule semantics. Do not broaden *.example.com into example.com.
        domain = record[2:] if record.startswith(b"*.") else record
        if len(domain) > 253 or not DOMAIN.fullmatch(domain):
            raise ValueError(f"non-domain or malformed entry at line {line_num}")
        if record in seen:
            raise ValueError(f"duplicate upstream rule at line {line_num}")
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
    # Both independent transports must yield the exact same historic bytes.
    # Fallback is only for transient GitHub CDN/network outages: NEVER
    # fallback to a newer branch, changed commit, truncated or synthetic list.
    endpoints = [
        ("github-raw", SOURCE_URL),
        ("jsdelivr-commit-pinned",
         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@"
         f"{COMMIT}/wildcard/gambling-onlydomains.txt"),
        ("github-git-blob", f"https://api.github.com/repos/hagezi/dns-blocklists/git/blobs/{BLOB_SHA1}"),
    ]
    failures = []
    for kind, url in endpoints:
        try:
            request = urllib.request.Request(url, headers={
                "User-Agent": "VOLVE-0287-CI-readonly/1.0",
                "Accept": "application/vnd.github+json" if kind == "github-git-blob" else "text/plain",
            })
            with urllib.request.urlopen(request, timeout=35) as response:
                if response.geturl() != url:
                    raise ValueError("unpinned source HTTP redirect")
                payload = response.read(MAX_BYTES * 2 + 1 if kind == "github-git-blob" else MAX_BYTES + 1)
            if kind == "github-git-blob":
                obj = json.loads(payload)
                if obj.get("sha") != BLOB_SHA1 or obj.get("encoding") != "base64":
                    raise ValueError("untrusted Git blob metadata")
                data = base64.b64decode(obj["content"], validate=False)
            else:
                data = payload
            if len(data) != BYTE_COUNT or len(data) > MAX_BYTES:
                raise ValueError("downloaded source size differs from pinned Git blob")
            if git_blob_sha1(data) != BLOB_SHA1 or hashlib.sha256(data).hexdigest() != SHA256_PIN:
                raise ValueError("downloaded source does not match BOTH pinned checksums")
            return data
        except (OSError, TimeoutError, ValueError, KeyError, json.JSONDecodeError) as error:
            failures.append(f"{kind}: {type(error).__name__}")
    raise ValueError("all three pinned official-source transports failed closed: " + "; ".join(failures))

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
