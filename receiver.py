#!/usr/bin/env python3
"""Simple LAN file receiver for the P2P file-sharing project."""

import argparse
import json
import socket
from pathlib import Path

BUFFER_SIZE = 64 * 1024
DEFAULT_PORT = 5000
HEADER_SIZE = 4


def receive_file(bind_host: str, port: int, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind_host, port))
        server.listen(1)
        print(f"Listening on {bind_host}:{port}")
        print("Waiting for a sender...")

        conn, address = server.accept()
        with conn:
            print(f"Connected from {address[0]}:{address[1]}")
            header_size_bytes = _recv_exact(conn, HEADER_SIZE)
            header_size = int.from_bytes(header_size_bytes, "big")
            if header_size > 1024 * 1024:
                raise ValueError("Header is unexpectedly large.")

            header = json.loads(_recv_exact(conn, header_size).decode("utf-8"))
            filename = Path(header["filename"]).name
            file_size = int(header["size"])
            destination = output_dir / filename

            print(f"Receiving: {filename} ({file_size} bytes)")
            received = 0
            with destination.open("wb") as output:
                while received < file_size:
                    chunk = conn.recv(min(BUFFER_SIZE, file_size - received))
                    if not chunk:
                        raise ConnectionError("Connection closed before the file was complete.")
                    output.write(chunk)
                    received += len(chunk)
                    print(f"\rProgress: {received / file_size * 100:6.2f}%", end="", flush=True)

            print(f"\nSaved to: {destination}")


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving metadata.")
        data.extend(chunk)
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Receive a file over a local TCP connection.")
    parser.add_argument("--host", default="0.0.0.0", help="Address to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--output", default="received", help="Directory for received files")
    args = parser.parse_args()

    receive_file(args.host, args.port, Path(args.output))


if __name__ == "__main__":
    main()
