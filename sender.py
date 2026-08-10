#!/usr/bin/env python3
"""Simple LAN file sender for the P2P file-sharing project."""

import argparse
import json
import socket
from pathlib import Path

BUFFER_SIZE = 64 * 1024
DEFAULT_PORT = 5000
HEADER_SIZE = 4


def send_file(host: str, port: int, file_path: Path) -> None:
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    file_size = file_path.stat().st_size
    header = json.dumps({"filename": file_path.name, "size": file_size}).encode("utf-8")
    if len(header) >= 2**32:
        raise ValueError("Metadata header is too large.")

    with socket.create_connection((host, port)) as sock:
        sock.sendall(len(header).to_bytes(HEADER_SIZE, "big"))
        sock.sendall(header)

        sent = 0
        with file_path.open("rb") as file:
            while chunk := file.read(BUFFER_SIZE):
                sock.sendall(chunk)
                sent += len(chunk)
                if file_size:
                    print(f"\rProgress: {sent / file_size * 100:6.2f}%", end="", flush=True)

    print(f"\nSent: {file_path.name} ({file_size} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a file directly to another PC over TCP.")
    parser.add_argument("host", help="Receiver's IP address")
    parser.add_argument("file", help="Path to the file to send")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    send_file(args.host, args.port, Path(args.file))


if __name__ == "__main__":
    main()
