#!/usr/bin/env python3
"""Encrypted direct P2P file transfer over TCP.

This is the first CLI protocol for the project. It is intentionally LAN-focused.
The file is encrypted end-to-end with AES-256-GCM. SHA-256 is used for
post-transfer integrity verification; SHA-256 itself is not encryption.
"""

import argparse
import getpass
import hashlib
import json
import os
import socket
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BUFFER_SIZE = 1024 * 1024  # 1 MiB plaintext chunks
DEFAULT_PORT = 5000
MAGIC = b"P2P1"
SALT_SIZE = 16
NONCE_SIZE = 12
MAX_FRAME = BUFFER_SIZE + 16  # AES-GCM authentication tag


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the shared password using scrypt."""
    if not password:
        raise ValueError("Password cannot be empty.")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        data.extend(chunk)
    return bytes(data)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME:
        raise ValueError("Encrypted frame is too large.")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(sock: socket.socket) -> bytes:
    length = struct.unpack("!I", recv_exact(sock, 4))[0]
    if length == 0 or length > MAX_FRAME:
        raise ValueError("Invalid encrypted frame size.")
    return recv_exact(sock, length)


def make_aad(kind: bytes, index: int) -> bytes:
    return MAGIC + kind + struct.pack("!Q", index)


def send_file(host: str, port: int, file_path: Path, password: str) -> None:
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = file_path.stat().st_size
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aes = AESGCM(key)

    # Filename, size and SHA-256 are encrypted as metadata.
    digest = hashlib.sha256()
    with file_path.open("rb") as file:
        while chunk := file.read(BUFFER_SIZE):
            digest.update(chunk)
    file_hash = digest.hexdigest()

    metadata = json.dumps(
        {"filename": file_path.name, "size": file_size, "sha256": file_hash},
        separators=(",", ":"),
    ).encode()
    metadata_nonce = os.urandom(NONCE_SIZE)
    encrypted_metadata = metadata_nonce + aes.encrypt(
        metadata_nonce, metadata, make_aad(b"META", 0)
    )

    started = time.monotonic()
    with socket.create_connection((host, port)) as sock:
        sock.sendall(MAGIC + salt)
        send_frame(sock, encrypted_metadata)

        sent = 0
        index = 0
        with file_path.open("rb") as file:
            while chunk := file.read(BUFFER_SIZE):
                nonce = os.urandom(NONCE_SIZE)
                encrypted = nonce + aes.encrypt(nonce, chunk, make_aad(b"DATA", index))
                send_frame(sock, encrypted)
                sent += len(chunk)
                index += 1
                elapsed = max(time.monotonic() - started, 0.001)
                speed = sent / elapsed / (1024 * 1024)
                percent = (sent / file_size * 100) if file_size else 100
                print(f"\r{percent:6.2f}%  {speed:8.2f} MiB/s", end="", flush=True)

        # Empty frame marks the end of the encrypted data stream.
        sock.sendall(struct.pack("!I", 0))

    elapsed = max(time.monotonic() - started, 0.001)
    print(f"\nSent: {file_path.name} ({file_size} bytes) in {elapsed:.2f}s")
    print(f"SHA-256: {file_hash}")


def receive_file(bind_host: str, port: int, output_dir: Path, password: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_host, port))
        server.listen(1)
        print(f"Listening on {bind_host}:{port}")
        print("Waiting for an encrypted sender...")

        conn, address = server.accept()
        with conn:
            print(f"Connected from {address[0]}:{address[1]}")
            magic_and_salt = recv_exact(conn, len(MAGIC) + SALT_SIZE)
            if magic_and_salt[:4] != MAGIC:
                raise ValueError("Unknown protocol or incompatible peer.")

            salt = magic_and_salt[4:]
            key = derive_key(password, salt)
            aes = AESGCM(key)

            encrypted_metadata = recv_frame(conn)
            metadata_nonce = encrypted_metadata[:NONCE_SIZE]
            metadata = aes.decrypt(
                metadata_nonce,
                encrypted_metadata[NONCE_SIZE:],
                make_aad(b"META", 0),
            )
            info = json.loads(metadata.decode())
            filename = Path(info["filename"]).name
            file_size = int(info["size"])
            expected_hash = info["sha256"]
            destination = output_dir / filename

            print(f"Receiving: {filename} ({file_size} bytes)")
            digest = hashlib.sha256()
            received = 0
            index = 0
            started = time.monotonic()

            with destination.open("wb") as output:
                while True:
                    frame_len = struct.unpack("!I", recv_exact(conn, 4))[0]
                    if frame_len == 0:
                        break
                    if frame_len > MAX_FRAME or frame_len <= NONCE_SIZE + 16:
                        raise ValueError("Invalid encrypted data frame.")
                    encrypted = recv_exact(conn, frame_len)
                    nonce = encrypted[:NONCE_SIZE]
                    chunk = aes.decrypt(
                        nonce,
                        encrypted[NONCE_SIZE:],
                        make_aad(b"DATA", index),
                    )
                    received += len(chunk)
                    if received > file_size:
                        raise ValueError("Received more data than declared.")
                    digest.update(chunk)
                    output.write(chunk)
                    index += 1
                    elapsed = max(time.monotonic() - started, 0.001)
                    speed = received / elapsed / (1024 * 1024)
                    percent = (received / file_size * 100) if file_size else 100
                    print(f"\r{percent:6.2f}%  {speed:8.2f} MiB/s", end="", flush=True)

            actual_hash = digest.hexdigest()
            if received != file_size or actual_hash != expected_hash:
                destination.unlink(missing_ok=True)
                raise ValueError("Integrity check failed; incomplete or modified file discarded.")

            elapsed = max(time.monotonic() - started, 0.001)
            print(f"\nReceived: {destination} ({received} bytes) in {elapsed:.2f}s")
            print(f"SHA-256: {actual_hash}  [OK]")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="p2p",
        description="Encrypted direct P2P file sharing over TCP (LAN-focused).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    send = sub.add_parser("send", help="Send a file to another PC")
    send.add_argument("host", help="Receiver IP address")
    send.add_argument("file", type=Path)
    send.add_argument("--port", type=int, default=DEFAULT_PORT)

    receive = sub.add_parser("receive", help="Receive a file")
    receive.add_argument("--host", default="0.0.0.0")
    receive.add_argument("--port", type=int, default=DEFAULT_PORT)
    receive.add_argument("--output", type=Path, default=Path("received"))

    args = parser.parse_args()
    password = getpass.getpass("Shared encryption password: ")

    if args.command == "send":
        send_file(args.host, args.port, args.file, password)
    else:
        receive_file(args.host, args.port, args.output, password)


if __name__ == "__main__":
    main()
