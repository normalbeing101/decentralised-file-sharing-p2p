# Decentralised P2P File Sharing

A small educational peer-to-peer file-sharing system that sends files directly between computers over TCP.

## Current version — unified CLI + local web UI

There is now **one program** for both sides. Run it without arguments and choose **Send**, **Receive**, or **Web** from the menu.

```bash
python p2p.py
```

You can also use explicit commands:

```bash
python p2p.py send 192.168.1.25 ./example.zip
python p2p.py receive
python p2p.py web
```

## Install

Python 3.10+ is recommended.

```bash
python -m pip install -r requirements.txt
```

## Web interface

Start the local UI:

```bash
python p2p.py web
```

Open `http://127.0.0.1:8080` in your browser. It provides simple Send and Receive forms while using the same encrypted transfer engine as the CLI.

The web server binds to **localhost by default**. Do not expose it to the LAN unless you deliberately want another device to control the computer running it.

## Security model

- **AES-256-GCM** provides authenticated end-to-end encryption for metadata and file chunks.
- A fresh random salt is generated for every transfer.
- The shared password is converted into a 256-bit key using **scrypt**.
- Every encrypted chunk uses a fresh random nonce and authenticated associated data.
- **SHA-256 verifies the complete file after transfer.** SHA-256 is a hash, not encryption.
- Wrong passwords, modified frames, invalid metadata, incomplete transfers, and failed integrity checks are rejected.
- Failed receiving transfers are deleted instead of leaving a corrupted file behind.
- The connection is direct TCP; there is no file-storage server in this version.

## Performance

Files are streamed in 1 MiB chunks, so the CLI does not load an entire large file into RAM. Progress shows percentage, throughput, and ETA. AES-GCM is designed for fast authenticated encryption and can benefit from hardware acceleration. Encryption itself does not guarantee higher network speed.

## Better failure handling

The transfer layer validates protocol magic, frame sizes, metadata, declared file size, authenticated encryption, and final SHA-256. It also uses connection timeouts and avoids silently accepting truncated or modified files.

## Important limitation

This is an early LAN-focused educational protocol, not production-grade anonymous file sharing. The shared password is the trust anchor. Use a long, random password and keep the web UI on localhost.

## Roadmap

- [x] Direct TCP transfer
- [x] Unified CLI with Send/Receive menu
- [x] Polished terminal progress UI
- [x] Streaming large files
- [x] AES-256-GCM authenticated encryption
- [x] SHA-256 integrity verification
- [x] Better protocol/error handling
- [x] Local web interface
- [ ] Resume interrupted transfers
- [ ] LAN peer discovery
- [ ] Multiple simultaneous peers
- [ ] Chunk-level distribution
- [ ] Distributed peer discovery / DHT
- [ ] Strong peer identities and key exchange
- [ ] Internet-wide NAT traversal
- [ ] Full browser streaming for very large uploads
