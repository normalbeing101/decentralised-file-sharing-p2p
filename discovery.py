"""LAN peer discovery using UDP broadcast. No file data or secrets are broadcast."""
import json
import socket
import time
import uuid

DISCOVERY_PORT = 5001
MAGIC = b"P2P-DISCOVERY-1"
MAX_PACKET = 2048


def _payload(peer_id, port):
    return MAGIC + b" " + json.dumps({"id": peer_id, "port": int(port)}, separators=(",", ":")).encode()


def discover(port=5000, duration=5):
    if not 1 <= int(port) <= 65535:
        raise ValueError("TCP port must be between 1 and 65535.")
    if duration <= 0:
        return []
    token = str(uuid.uuid4())
    found = {}
    deadline = time.monotonic() + duration
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", DISCOVERY_PORT))
        sock.settimeout(0.5)
        payload = _payload(token, port)
        while time.monotonic() < deadline:
            try:
                sock.sendto(payload, ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                pass
            try:
                data, address = sock.recvfrom(MAX_PACKET)
                if not data.startswith(MAGIC + b" "):
                    continue
                item = json.loads(data[len(MAGIC) + 1:])
                peer_id = str(item["id"])
                peer_port = int(item["port"])
                if peer_id == token or not 1 <= peer_port <= 65535:
                    continue
                found[address[0]] = {"host": address[0], "port": peer_port}
            except (socket.timeout, ValueError, KeyError, TypeError, json.JSONDecodeError):
                pass
    return list(found.values())


def announce(port=5000, stop_event=None):
    import threading
    if not 1 <= int(port) <= 65535:
        raise ValueError("TCP port must be between 1 and 65535.")
    stop_event = stop_event or threading.Event()
    token = str(uuid.uuid4())
    payload = _payload(token, port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while not stop_event.is_set():
            try:
                sock.sendto(payload, ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                pass
            stop_event.wait(3)
