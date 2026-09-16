# Secure Chat Application with Encryption

**CNS course project — Team 15.**

A client-server chat application where messages are encrypted end-to-end (AES-256-GCM)
so the relay server and network never see plaintext.

## Status

Work in progress.

- **Phase 1 — baseline plaintext socket chat:** done
- **Phase 2 — AES-256-GCM crypto engine (standalone, unit-tested):** done
- **Phase 3 — ECDH (X25519) key exchange, wired into live chat encryption:** done
- Phase 4+ (identity/login, digital signatures, TLS, capture/replay tests): not started

## How to run

Requires Python 3.8+. Install dependencies first:

```
pip install -r requirements.txt
```

**1. Start the server** (one terminal):

```
python server/server.py
```

Defaults to `127.0.0.1:5000`; override with `--host` / `--port`.

**2. Start two clients**, each naming the other as its peer (one in each of two more
terminals):

```
python client/client.py --username alice --peer bob
python client/client.py --username bob --peer alice
```

As soon as both are online, they automatically perform the ECDH handshake described
below, then every message either types is AES-256-GCM encrypted before it leaves the
client and decrypted on arrival. `--host` / `--port` point at a non-default server;
omit `--username`/`--peer` to be prompted interactively.

## How the handshake works

Each client generates a brand-new X25519 (elliptic-curve Diffie-Hellman) keypair for
every chat session — never reused across logins, so compromising one session's key
reveals nothing about any other session (forward secrecy). When two named peers are
both online, the client whose username sorts alphabetically first automatically sends
its public key to the other, relayed through the server inside a `handshake_init`
JSON envelope; the second client generates its own keypair and replies with a
`handshake_response` carrying its own public key. Both sides then independently run
`compute_shared_key()` — each combining *their own* private key with the *other's*
public key — which by the math of Diffie-Hellman produces the identical raw shared
secret on both ends without either private key ever crossing the network. That raw
secret is then passed through HKDF-SHA256 to derive a clean, uniformly random 32-byte
AES-256 key (the raw ECDH output itself is never used directly as a cipher key). From
that point on, every chat message is encrypted with `aes_gcm.encrypt()` before being
sent and decrypted with `aes_gcm.decrypt()` after being received; the relay server only
ever forwards opaque public-key bytes and encrypted (nonce/ciphertext/tag) envelopes —
it never computes, stores, or sees the shared secret, and a tampered or forged message
is rejected with a warning instead of being decrypted into garbage.

## Wire protocol

One JSON object per line (newline-terminated). Every envelope has a `"type"` field:

| type | direction | carries |
|---|---|---|
| `hello` | client → server | `username` |
| `roster` | server → client | list of currently-online usernames |
| `system` | server → client | human-readable join/leave/error text |
| `user_joined` | server → client | `username` of a newly-connected peer |
| `handshake_init` | client ↔ client (via server) | `from`, `to`, `pubkey` (base64, 32 raw bytes) |
| `handshake_response` | client ↔ client (via server) | `from`, `to`, `pubkey` (base64, 32 raw bytes) |
| `chat` | client ↔ client (via server) | `from`, `to`, `nonce`, `ciphertext`, `tag` (all base64) |

The server routes `handshake_init` / `handshake_response` / `chat` envelopes to the
named `to` recipient only, based on the sender's own claimed `from` field; it never
inspects or needs to understand their payload beyond that routing.

## Running the tests

```
pip install -r requirements.txt
pytest tests/ -v
```

## Crypto modules

`crypto_engine/aes_gcm.py` — standalone AES-256-GCM module (Phase 2):

```python
from crypto_engine import generate_key, encrypt, decrypt

key = generate_key()                       # 32 random bytes (testing only)
box = encrypt(key, b"hello")               # {"nonce", "ciphertext", "tag"}
decrypt(key, box["nonce"], box["ciphertext"], box["tag"])  # b"hello"
```

Tampered ciphertext or a wrong key raises `DecryptionError` rather than returning
garbage plaintext.

`crypto_engine/dh_exchange.py` — ECDH (X25519) key exchange + HKDF-SHA256 key
derivation (Phase 3), used by `client/client.py` to derive the AES key that
`aes_gcm` then encrypts every chat message with:

```python
from crypto_engine.dh_exchange import generate_keypair, compute_shared_key

priv_a, pub_a = generate_keypair()
priv_b, pub_b = generate_keypair()
assert compute_shared_key(priv_a, pub_b) == compute_shared_key(priv_b, pub_a)
```
