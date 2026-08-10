"""Protocol helpers for resumable, authenticated chunk transfers."""
import hashlib
import json

CHUNK_SIZE = 1024 * 1024
PROTOCOL_VERSION = 3


def manifest(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as file:
        while chunk := file.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return {"version": PROTOCOL_VERSION, "size": size, "sha256": digest.hexdigest(), "chunk_size": CHUNK_SIZE}


def chunk_count(size, chunk_size=CHUNK_SIZE):
    return (size + chunk_size - 1) // chunk_size


def encode_json(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
