# Decentralised P2P File Sharing

A small educational peer-to-peer file-sharing system that sends files directly between computers over TCP.

## Current version — encrypted CLI

The project now has a CLI for direct transfers:

```bash
python p2p.py receive
python p2p.py send <receiver-ip> <file>
```

### Install

Python 3.10+ is recommended.

```bash
python -m pip install -r requirements.txt
```

### Receive

On PC B:

```bash
python p2p.py receive
```

### Send

On PC A, replace the IP with PC B's LAN IP:

```bash
python p2p.py send 192.168.1.25 ./example.zip
```

Both peers enter the **same strong encryption password** when prompted. Do not put the password in the command line or commit it to the repository.

## Security

- **AES-256-GCM** provides authenticated end-to-end encryption for the file and metadata.
- A fresh random salt is generated for every transfer.
- The shared password is converted into a key using **scrypt**.
- Every data chunk has its own random nonce and authenticated associated data.
- **SHA-256 verifies file integrity after transfer.** SHA-256 is a hash, not encryption, so it cannot provide confidentiality by itself.
- If authenticated decryption or the final SHA-256 check fails, the received file is discarded.
- The connection remains direct TCP; there is no file-storage server in this version.

## Performance

Large files are streamed in 1 MiB chunks instead of being loaded into RAM. AES-GCM is designed for fast authenticated encryption and can benefit from hardware acceleration. Encryption does **not** inherently make the transfer faster; network, disk, CPU, and TCP performance determine the actual speed.

## Important limitation

This is an early LAN-focused protocol, not a production-grade anonymous file-sharing network. The shared password is the trust anchor. A weak password can be guessed offline from the public transfer salt, so use a long random password.

## Roadmap

- [x] Direct TCP file transfer
- [x] CLI
- [x] Streaming large files
- [x] AES-256-GCM authenticated encryption
- [x] SHA-256 integrity verification
- [ ] Resume interrupted transfers
- [ ] LAN peer discovery
- [ ] Multiple simultaneous peers
- [ ] Chunk-level distribution
- [ ] Distributed peer discovery / DHT
- [ ] Strong peer identities and key exchange
- [ ] Internet-wide NAT traversal
- [ ] GUI
