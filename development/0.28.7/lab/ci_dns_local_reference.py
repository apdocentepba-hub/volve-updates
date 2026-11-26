"""Disposable runner DNS fixture: no forwarding; exact reserved A/IN challenges only."""
import ipaddress
import json
import os
import re
import socket
import struct
import threading
from pathlib import Path

local = str(ipaddress.IPv4Address(os.environ["VOLVE_LAB_IP"]))
prefix = os.environ["VOLVE_LAB_PREFIX"]
if not re.fullmatch(r"[0-9a-f]{32}", prefix) or local.startswith("127."):
    raise SystemExit("Invalid lab identity")
if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
    raise SystemExit("Hosted runner required")
log = Path(os.environ["VOLVE_LAB_LOG"])
ready = Path(os.environ["VOLVE_LAB_READY"])
lock = threading.Lock()

def record(name, host, transport):
    with lock, log.open("a", encoding="ascii") as f:
        f.write(json.dumps({"name": name, "host": "loopback" if host == "127.0.0.1" else "local", "transport": transport}) + "\n")

def answer(q):
    if not 17 <= len(q) <= 4096:
        return None
    ident, flags, qd, an, ns, ar = struct.unpack("!6H", q[:12])
    if flags & 0xF800 or qd != 1 or an or ns or ar > 1:
        return None
    pos, labels = 12, []
    while pos < len(q):
        size = q[pos]
        pos += 1
        if size == 0:
            break
        if size > 63 or pos + size > len(q):
            return None
        labels.append(q[pos:pos+size].decode("ascii", errors="replace").lower())
        pos += size
    name = ".".join(labels)
    if not re.fullmatch(prefix + r"-[0-9a-f]{16}\.test", name):
        return None
    if pos + 4 > len(q) or q[pos:pos+4] != b"\x00\x01\x00\x01":
        return None
    pos += 4
    return name, struct.pack("!6H", ident, 0x8180, 1, 1, 0, 0) + q[12:pos] + bytes.fromhex("c00c00010001000000000004cb007107")

def exact_read(c, size):
    data = b""
    while len(data) < size:
        part = c.recv(size-len(data))
        if not part:
            raise EOFError
        data += part
    return data

def serve_tcp(s, host):
    while True:
        c, peer = s.accept()
        with c:
            if peer[0] not in ("127.0.0.1", local):
                continue
            c.settimeout(1)
            try:
                size = struct.unpack("!H", exact_read(c, 2))[0]
                if not 17 <= size <= 4096:
                    continue
                result = answer(exact_read(c, size))
                if result:
                    name, response = result
                    c.sendall(struct.pack("!H", len(response)) + response)
                    record(name, host, "tcp")
            except (OSError, EOFError, ValueError):
                continue

def serve_udp(s, host):
    while True:
        q, peer = s.recvfrom(4096)
        if peer[0] not in ("127.0.0.1", local):
            continue
        result = answer(q)
        if result:
            name, response = result
            s.sendto(response, peer)
            record(name, host, "udp")

sockets = []
for host in ("127.0.0.1", local):
    for kind, target in ((socket.SOCK_STREAM, serve_tcp), (socket.SOCK_DGRAM, serve_udp)):
        sock = socket.socket(socket.AF_INET, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((host, 53))
        if kind == socket.SOCK_STREAM:
            sock.listen(8)
        sockets.append(sock)
        threading.Thread(target=target, args=(sock, host), daemon=True).start()
ready.write_text("READY", encoding="ascii")
threading.Event().wait()
