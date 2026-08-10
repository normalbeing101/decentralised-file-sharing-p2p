# Decentralised File Sharing P2P

A small educational peer-to-peer file-sharing system built from scratch.

## V1 — Direct LAN transfer

The first version keeps things intentionally simple:

- Two PCs on the same local network
- Direct TCP connection
- No cloud storage
- No central file server
- Files are streamed in 64 KiB chunks
- Basic filename and file-size metadata
- Progress display

> This is an educational prototype, not a secure internet-wide file-sharing system yet.

## Requirements

- Python 3.10+
- Two PCs connected to the same LAN/Wi-Fi

No third-party packages are required.

## Usage

### 1. Start the receiver

On PC B:

```bash
python receiver.py
```

By default it listens on TCP port `5000` and saves files in `received/`.

You can choose a different port/output directory:

```bash
python receiver.py --port 5000 --output received
```

Find PC B's local IP address. For example:

```text
192.168.1.25
```

### 2. Send a file

On PC A:

```bash
python sender.py 192.168.1.25 path/to/file.zip
```

Or with an explicit port:

```bash
python sender.py 192.168.1.25 path/to/file.zip --port 5000
```

The receiver will save the file under its `received/` directory.

## How it works

```text
PC A                              PC B
Sender                            Receiver
  │                                  │
  │──── TCP connection :5000 ──────►│
  │                                  │
  │──── metadata ──────────────────►│
  │──── file chunk ────────────────►│
  │──── file chunk ────────────────►│
  │──── file chunk ────────────────►│
  │                                  │
  └────────────── done ─────────────►│
```

The sender first sends a small JSON header containing the filename and file size. The file is then streamed without loading the whole file into memory.

## Roadmap

- [ ] SHA-256 file integrity verification
- [ ] Better error handling
- [ ] Transfer speed display
- [ ] Resume interrupted transfers
- [ ] Multiple simultaneous peers
- [ ] Peer discovery
- [ ] Distributed hash table (DHT)
- [ ] Peer identities and authentication
- [ ] NAT traversal
- [ ] Desktop UI

## Security

V1 is intentionally minimal. It has **no encryption or authentication**. Only use it on a trusted network for testing.
