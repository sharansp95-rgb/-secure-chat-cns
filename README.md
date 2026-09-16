# Secure Chat Application with Encryption

**CNS course project — Team 15.**

A client-server chat application where messages are encrypted end-to-end (AES-256-GCM)
so the relay server and network never see plaintext.

## Status

Work in progress.

- **Phase 1 — baseline plaintext socket chat:** done
- **Phase 2 — AES-256-GCM crypto engine (standalone, unit-tested):** done
- Phase 3+ (key exchange, identity, signatures, TLS): not started

## How to run

Requires Python 3.8+. Phase 1 uses only the standard library.

**1. Start the server** (one terminal):

```
python server/server.py
```

Defaults to `127.0.0.1:5000`; override with `--host` / `--port`.

**2. Start two clients** (one in each of two more terminals):

```
python client/client.py
```

Each client prompts for a username, then you can type messages and press Enter.
Anything one client sends is relayed to the other. Pass `--username alice` to skip
the prompt, and `--host` / `--port` to point at a non-default server.

> **Note:** this Phase 1 baseline sends messages in **plaintext** over the socket.
> Encryption is added in Phase 2 and later.

## Running the tests

```
pip install -r requirements.txt
pytest tests/ -v
```

## Crypto engine (Phase 2)

`crypto_engine/aes_gcm.py` is a standalone AES-256-GCM module — not yet wired into
the live chat, since the session key it needs comes from the Diffie-Hellman exchange
in Phase 3. It is independently testable today:

```python
from crypto_engine import generate_key, encrypt, decrypt

key = generate_key()                       # 32 random bytes
box = encrypt(key, b"hello")               # {"nonce", "ciphertext", "tag"}
decrypt(key, box["nonce"], box["ciphertext"], box["tag"])  # b"hello"
```

Tampered ciphertext or a wrong key raises `DecryptionError` rather than returning
garbage plaintext.
