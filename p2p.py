#!/usr/bin/env python3
"""Secure direct P2P file sharing with a unified CLI."""
import argparse
import getpass
import hashlib
import json
import os
import re
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

BUFFER_SIZE = 1024 * 1024
DEFAULT_PORT = 5000
MAGIC = b"P2P3"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
MAX_FRAME = BUFFER_SIZE + NONCE_SIZE + TAG_SIZE
MAX_METADATA = 64 * 1024
MAX_FILENAME = 255
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
DIM = "\033[2m"


def banner():
    print(f"\n{CYAN}{BOLD}╔══════════════════════════════════════╗\n║        P2P FILE SHARE  •  v3        ║\n╚══════════════════════════════════════╝{RESET}")
    print(f"{DIM}Direct TCP • AES-256-GCM • SHA-256{RESET}\n")


def derive_key(password, salt):
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid encryption salt.")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def recv_exact(sock, size):
    if size < 0:
        raise ValueError("Invalid receive size.")
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Peer closed the connection unexpectedly.")
        data.extend(chunk)
    return bytes(data)


def send_frame(sock, payload):
    if not 1 <= len(payload) <= MAX_FRAME:
        raise ValueError("Encrypted frame is too large or empty.")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(sock, allow_end=False):
    length = struct.unpack("!I", recv_exact(sock, 4))[0]
    if length == 0 and allow_end:
        return None
    if length < NONCE_SIZE + TAG_SIZE or length > MAX_FRAME:
        raise ValueError("Invalid encrypted frame size.")
    return recv_exact(sock, length)


def aad(kind, index):
    return MAGIC + kind + struct.pack("!Q", index)


def encrypt_frame(aes, payload, kind, index):
    nonce = os.urandom(NONCE_SIZE)
    return nonce + aes.encrypt(nonce, payload, aad(kind, index))


def decrypt_frame(aes, frame, kind, index):
    if len(frame) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Encrypted frame is too short.")
    nonce, ciphertext = frame[:NONCE_SIZE], frame[NONCE_SIZE:]
    try:
        return aes.decrypt(nonce, ciphertext, aad(kind, index))
    except Exception as exc:
        raise ValueError("Authentication failed: wrong password or modified data.") from exc


def progress(done, total, started):
    elapsed = max(time.monotonic() - started, 0.001)
    speed = done / elapsed / (1024 * 1024)
    pct = (done / total * 100) if total else 100
    width = 28
    filled = min(width, int(width * pct / 100))
    bar = "█" * filled + "░" * (width - filled)
    eta = ((total - done) / (speed * 1024 * 1024)) if speed > 0 and total else 0
    return f"\r{CYAN}[{bar}]{RESET} {pct:6.2f}%  {speed:7.2f} MiB/s  ETA {eta:5.1f}s"


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(BUFFER_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def validate_metadata(info):
    if not isinstance(info, dict):
        raise ValueError("Invalid transfer metadata.")
    filename = Path(str(info.get("filename", ""))).name
    size = info.get("size")
    expected = str(info.get("sha256", "")).lower()
    if not filename or filename in {".", ".."} or len(filename) > MAX_FILENAME:
        raise ValueError("Invalid filename in transfer metadata.")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ValueError("Invalid file size in transfer metadata.")
    if not SHA256_RE.fullmatch(expected):
        raise ValueError("Invalid SHA-256 value in transfer metadata.")
    return filename, size, expected


def send_file(host, port, file_path, password):
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    size = file_path.stat().st_size
    digest = file_sha256(file_path)
    salt = os.urandom(SALT_SIZE)
    aes = AESGCM(derive_key(password, salt))
    metadata = json.dumps(
        {"filename": file_path.name, "size": size, "sha256": digest},
        separators=(",", ":"),
    ).encode("utf-8")
    if len(metadata) > MAX_METADATA:
        raise ValueError("Transfer metadata is too large.")

    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            sock.settimeout(60)
            sock.sendall(MAGIC + salt)
            send_frame(sock, encrypt_frame(aes, metadata, b"META", 0))

            sent = 0
            index = 0
            with file_path.open("rb") as file:
                while chunk := file.read(BUFFER_SIZE):
                    send_frame(sock, encrypt_frame(aes, chunk, b"DATA", index))
                    sent += len(chunk)
                    print(progress(sent, size, started), end="", flush=True)
                    index += 1

            end_payload = json.dumps(
                {"size": sent, "chunks": index, "sha256": digest},
                separators=(",", ":"),
            ).encode("utf-8")
            send_frame(sock, encrypt_frame(aes, end_payload, b"END", index))

            ack_frame = recv_frame(sock)
            ack = json.loads(decrypt_frame(aes, ack_frame, b"ACK", index).decode("utf-8"))
            if ack.get("status") != "ok" or ack.get("sha256") != digest:
                raise ValueError("Receiver rejected the transfer integrity check.")
    except (OSError, ConnectionError) as exc:
        raise ConnectionError(f"Transfer failed: {exc}") from exc

    print(f"\n{GREEN}✓ Sent successfully{RESET}: {file_path.name}")
    print(f"  SHA-256: {digest} [receiver verified]")
    return digest


def receive_file(bind_host, port, output_dir, password, ready_callback=None):
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    output_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_host, port))
        server.listen(1)
        if ready_callback:
            ready_callback(server.getsockname()[1])
        print(f"{DIM}Listening on {bind_host}:{server.getsockname()[1]} — waiting for sender...{RESET}")
        conn, address = server.accept()

        with conn:
            conn.settimeout(60)
            print(f"{DIM}Connected from {address[0]}:{address[1]}{RESET}")
            hello = recv_exact(conn, len(MAGIC) + SALT_SIZE)
            if hello[:len(MAGIC)] != MAGIC:
                raise ValueError("Unknown or unsupported protocol version.")

            aes = AESGCM(derive_key(password, hello[len(MAGIC):]))
            enc_meta = recv_frame(conn)
            try:
                metadata = decrypt_frame(aes, enc_meta, b"META", 0)
                if len(metadata) > MAX_METADATA:
                    raise ValueError("Metadata is too large.")
                info = json.loads(metadata.decode("utf-8"))
                filename, size, expected = validate_metadata(info)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"Invalid or unauthenticated metadata: {exc}") from exc

            dest = output_dir / filename
            if dest.exists():
                dest = output_dir / f"{dest.stem}_{int(time.time())}{dest.suffix}"

            digest = hashlib.sha256()
            received = 0
            index = 0
            started = time.monotonic()
            try:
                with dest.open("wb") as output:
                    while True:
                        frame = recv_frame(conn)
                        if frame is None:
                            raise ValueError("Transfer ended without an authenticated completion frame.")

                        try:
                            # END is distinguished by a JSON payload only after DATA decryption.
                            # DATA frames are always at most BUFFER_SIZE + GCM overhead.
                            chunk = decrypt_frame(aes, frame, b"DATA", index)
                        except ValueError:
                            end_payload = decrypt_frame(aes, frame, b"END", index)
                            try:
                                end = json.loads(end_payload.decode("utf-8"))
                            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                                raise ValueError("Invalid completion frame.") from exc

                            if end.get("size") != received or end.get("chunks") != index or end.get("sha256") != digest.hexdigest():
                                raise ValueError("Authenticated completion data does not match the received file.")
                            break

                        if len(chunk) > BUFFER_SIZE:
                            raise ValueError("Received chunk exceeds the maximum chunk size.")
                        received += len(chunk)
                        if received > size:
                            raise ValueError("Peer sent more data than declared.")
                        digest.update(chunk)
                        output.write(chunk)
                        print(progress(received, size, started), end="", flush=True)
                        index += 1

                actual = digest.hexdigest()
                if received != size or actual != expected:
                    raise ValueError("SHA-256 integrity check failed; file discarded.")

                ack = json.dumps({"status": "ok", "sha256": actual}, separators=(",", ":")).encode()
                send_frame(conn, encrypt_frame(aes, ack, b"ACK", index))
            except Exception:
                dest.unlink(missing_ok=True)
                raise

    print(f"\n{GREEN}✓ Received successfully{RESET}: {dest}")
    print(f"  SHA-256: {actual} [OK]")
    return dest


def prompt_password():
    password = getpass.getpass("Encryption password (min 8 chars): ")
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    return password


def interactive():
    banner()
    print(f"{BOLD}Choose a mode{RESET}\n  {CYAN}[1]{RESET} Send a file\n  {CYAN}[2]{RESET} Receive a file\n  {CYAN}[3]{RESET} Start web interface\n  {CYAN}[q]{RESET} Quit\n")
    choice = input("  Select: ").strip().lower()
    if choice == "1":
        host = input("  Receiver IP: ").strip()
        port = int(input(f"  Port [{DEFAULT_PORT}]: ").strip() or DEFAULT_PORT)
        path = Path(input("  File path: ").strip().strip('"'))
        send_file(host, port, path, prompt_password())
    elif choice == "2":
        port = int(input(f"  Listen port [{DEFAULT_PORT}]: ").strip() or DEFAULT_PORT)
        output = Path(input("  Output folder [received]: ").strip() or "received")
        receive_file("0.0.0.0", port, output, prompt_password())
    elif choice == "3":
        from web import run_web
        run_web("127.0.0.1", 8080)
    elif choice != "q":
        raise ValueError("Invalid selection.")


def main():
    parser = argparse.ArgumentParser(prog="p2p", description="Secure direct P2P file sharing")
    sub = parser.add_subparsers(dest="command")

    sender = sub.add_parser("send", help="Send a file")
    sender.add_argument("host")
    sender.add_argument("file", type=Path)
    sender.add_argument("--port", type=int, default=DEFAULT_PORT)

    receiver = sub.add_parser("receive", help="Receive a file")
    receiver.add_argument("--host", default="0.0.0.0")
    receiver.add_argument("--port", type=int, default=DEFAULT_PORT)
    receiver.add_argument("--output", type=Path, default=Path("received"))

    web = sub.add_parser("web", help="Start local web interface")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()
    try:
        if not args.command:
            interactive()
        elif args.command == "send":
            send_file(args.host, args.port, args.file, prompt_password())
        elif args.command == "receive":
            receive_file(args.host, args.port, args.output, prompt_password())
        else:
            from web import run_web
            run_web(args.host, args.port)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Cancelled.{RESET}")
    except (ValueError, FileNotFoundError, ConnectionError, OSError) as exc:
        print(f"\n{RED}✗ {exc}{RESET}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
