import hashlib
import socket
import threading
from pathlib import Path

import pytest

from p2p import AESGCM, NONCE_SIZE, aad, decrypt_frame, encrypt_frame, receive_file, send_file, validate_metadata


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_authenticated_frame_round_trip():
    aes = AESGCM(b"0" * 32)
    payload = b"hello p2p"
    frame = encrypt_frame(aes, payload, b"DATA", 0)
    assert decrypt_frame(aes, frame, b"DATA", 0) == payload


def test_authenticated_frame_rejects_wrong_aad():
    aes = AESGCM(b"0" * 32)
    frame = encrypt_frame(aes, b"hello", b"DATA", 0)
    with pytest.raises(ValueError, match="Authentication failed"):
        decrypt_frame(aes, frame, b"DATA", 1)


def test_metadata_validation():
    digest = hashlib.sha256(b"x").hexdigest()
    assert validate_metadata({"filename": "x.bin", "size": 1, "sha256": digest}) == ("x.bin", 1, digest)
    with pytest.raises(ValueError):
        validate_metadata({"filename": "../evil", "size": 1, "sha256": digest})
    with pytest.raises(ValueError):
        validate_metadata({"filename": "x", "size": -1, "sha256": digest})
    with pytest.raises(ValueError):
        validate_metadata({"filename": "x", "size": 1, "sha256": "not-a-hash"})


def test_end_to_end_file_transfer(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes((b"secure-p2p-data-" * 10000) + b"end")
    output = tmp_path / "received"
    port = free_port()
    errors = []

    def receiver():
        try:
            receive_file("127.0.0.1", port, output, "correct horse battery staple")
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    thread = threading.Thread(target=receiver, daemon=True)
    thread.start()

    # Give the listener a moment to bind before connecting.
    import time
    time.sleep(0.1)
    send_file("127.0.0.1", port, source, "correct horse battery staple")
    thread.join(timeout=10)

    assert not errors
    received = output / source.name
    assert received.exists()
    assert received.read_bytes() == source.read_bytes()
    assert hashlib.sha256(received.read_bytes()).hexdigest() == hashlib.sha256(source.read_bytes()).hexdigest()
