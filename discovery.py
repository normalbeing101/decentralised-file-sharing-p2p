"""LAN peer discovery using UDP broadcast. No file data or secrets are broadcast."""
import json
import socket
import time
import uuid

DISCOVERY_PORT = 5001
MAGIC = b"P2P-DISCOVERY-1"


def discover(port=5000, duration=5):
    token = str(uuid.uuid4())
    found = {}
    deadline = time.monotonic() + duration
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", DISCOVERY_PORT))
        sock.settimeout(0.5)
        payload = MAGIC + b" " + json.dumps({"id": token, "port": port}).encode()
        while time.monotonic() < deadline:
            try:
                sock.sendto(payload, ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                pass
            try:
                data, address = sock.recvfrom(2048)
                if not data.startswith(MAGIC + b" "):
                    continue
                item = json.loads(data[len(MAGIC) + 1:])
                if item.get("id") != token:
                    found[address[0]] = {"host": address[0], "port": int(item.get("port", port))}
            except (socket.timeout, ValueError, KeyError, TypeError):
                pass
    return list(found.values())


def announce(port=5000, stop_event=None):
    import threading
    stop_event = stop_event or threading.Event()
    token = str(uuid.uuid4())
    payload = MAGIC + b" " + json.dumps({"id": token, "port": port}).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while not stop_event.is_set():
            try:
                sock.sendto(payload, ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                pass
            stop_event.wait(3)
