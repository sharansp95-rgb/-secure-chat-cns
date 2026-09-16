# Secure Chat Application with Encryption

**CNS course project — Team 15.**

A client-server chat application where messages are encrypted end-to-end (AES-256-GCM)
so the relay server and network never see plaintext.

## Status

Work in progress.

- **Phase 1 — baseline plaintext socket chat:** done
- **Phase 2 — AES-256-GCM crypto engine (standalone, unit-tested):** done
- **Phase 3 — ECDH (X25519) key exchange, wired into live chat encryption:** done
- **Phase 4 — login, identity, and PBKDF2 password hashing:** done
- **Phase 5 — RSA-2048 digital signatures for non-repudiation:** done
- **Phase 6 — TLS transport encryption:** done
- **Phase 7 — signed handshake (MITM fix), replay protection, live demo scripts:** done
- Phase 8+ (final report, final demo prep): not started

## How to run

Requires Python 3.8+. Install dependencies first:

```
pip install -r requirements.txt
```

**0. One-time per teammate: generate a local TLS certificate.** The server and
client both need `certs/server.crt` / `certs/server.key`, which are gitignored (a
committed private key would let anyone with repo access impersonate the server) and
must be generated locally, once, by each person running this project:

```
python certs/generate_certs.py
```

This writes a self-signed cert for `CN=localhost`, valid 365 days. Re-run with
`--force` to regenerate (then restart the server and re-run this on every client, too
— an old cert and a new one won't match).

**1. Start the server** (one terminal):

```
python server/server.py
```

Defaults to `127.0.0.1:5000`; override with `--host` / `--port`.

**2. Start two clients**, each naming the other as its peer (one in each of two more
terminals):

```
python client/client.py --peer bob
python client/client.py --peer alice
```

Each client first asks you to **register** a new account or **login** to an existing
one — pick `1) Register` the first time for each username, `2) Login` afterward. The
password prompt hides your input (it won't echo to the terminal). Registering also
generates a long-term RSA-2048 identity keypair for that account (see "How signing
works" below) — the private key is saved locally, and only the public key is sent to
the server. Once both peers are authenticated and online, they automatically perform
the ECDH handshake described below, fetch each other's RSA public key, and from then
on every message is signed, AES-256-GCM encrypted before it leaves the client, and
decrypted + signature-verified on arrival. `--host` / `--port` point at a non-default
server; omit `--peer` to be prompted interactively.

Registered accounts (as PBKDF2 password hashes and RSA public keys only — see below)
persist in `data/users.json`; each account's RSA private key is saved separately as
`data/keys/<username>_private.pem`. Both `data/users.json` and `data/keys/` are
gitignored since they hold real credentials and private key material from local
testing.

**Gap closed:** as of Phase 6, the entire connection — including the register/login
envelope, which used to be readable JSON on the wire — is wrapped in TLS before a
single byte of the envelope protocol is sent. A network observer between a client and
the server now sees only opaque TLS records, not `"type": "login"` or a password. See
"How TLS layers with the app-level crypto" below for how this relates to the
AES-GCM/RSA protections that were already there.

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

## How the signed handshake stops a relay-server MITM (Phase 7a)

The handshake above has a gap: `handshake_init`/`handshake_response` carry a raw ECDH
public key, and nothing about the handshake itself ties that key to a particular long-
term identity. A malicious or **compromised relay server** — a different threat than a
network eavesdropper; TLS (Phase 6) does not help here, since the server is the trusted
TLS endpoint — could substitute its own ECDH public key for either peer's, completing
two separate handshakes (attacker↔A, attacker↔B) while both clients believe they're
talking directly to each other. Since each client already has a long-term RSA identity
(Phase 5), the fix reuses it: the ECDH public key is signed with the sender's RSA
private key before sending (`handshake_sig`), and the receiver verifies that signature
against the sender's already-known RSA public key **before** computing the shared
secret. If verification fails — or the ECDH key was swapped after signing, or the
signature was produced by the wrong RSA key — the handshake **aborts with a clear
error and no session key is ever derived**; nothing gets silently trusted. After a
*successful* handshake, both clients also print a short human-readable **fingerprint**
of the peer's RSA public key (`crypto_engine/signatures.fingerprint`, the first 16 hex
characters of SHA-256 of the key's PEM bytes) — the "check key fingerprints"
mitigation: two people can read this aloud to each other (voice call, in person) to
independently confirm they hold the same identity for their peer, catching a MITM even
if some future bug let a forged handshake slip past the automated check. See
`demo/run_mitm_handshake_demo.py` for a live demonstration of a relay attempting this
attack and being stopped.

## How replay protection works (Phase 7b)

A captured, validly-encrypted, validly-signed chat envelope could otherwise be resent
later (or twice) and would still pass both AES-GCM and the RSA signature check, since
neither says anything about *when* the message is being presented. Two independent
defenses close this: first, a Unix timestamp is included in what gets **signed**
(`chat_signable_bytes(message, timestamp)`) before encryption, so it travels tamper-
evident — an attacker can't just bump the timestamp on a captured message to make it
look fresh again, since that invalidates the signature. On receipt, a message is
rejected if its timestamp is more than `REPLAY_WINDOW_SECONDS` (30s) old or more than
`CLOCK_SKEW_SECONDS` (5s) in the future. Second, belt-and-suspenders: each client
tracks recently-seen `(sender, nonce)` pairs in memory (nonces are already fresh random
values per `aes_gcm.encrypt()` call, so a genuine resend from the sender would carry a
*different* nonce) and rejects an exact repeat outright, even if it somehow fell inside
the freshness window; old entries are pruned automatically once they're old enough that
the timestamp check alone would catch them anyway. See `demo/run_replay_demo.py` for a
live demonstration of a relay resending a captured message and the recipient's client
rejecting the duplicate.

## How signing works (non-repudiation)

The Phase 3 ECDH session key proves a message was encrypted for this pair of peers,
but it's symmetric — both sides hold it, so it can never by itself prove *which* of
them actually wrote a given message to a third party. Phase 5 adds a separate,
long-term RSA-2048 keypair per user identity to close that gap: at registration a
client generates its own RSA keypair, keeps the private key on disk locally (see
`auth/keystore.py`), and sends only the public key to the server, which stores it
next to that user's password hash. Before sending a chat message, the sender signs
the plaintext with its own RSA private key (RSA-PSS + SHA-256), then wraps
`{message, signature}` together as the payload that gets AES-256-GCM encrypted —
**sign, then encrypt** — so the signature travels protected inside the same
ciphertext as the message, never sent in the clear. On the receiving side the order
reverses: **decrypt, then verify** — the client AES-GCM-decrypts the envelope exactly
as in Phase 3, unwraps `{message, signature}`, and only then checks the signature
against the sender's RSA public key (fetched once via a `get_pubkey` request to the
server and cached for the session). A message whose signature doesn't check out —
tampered content, a forged signature, or a signature checked against the wrong public
key — is never displayed; the client prints a clear warning and discards it, exactly
as an unauthenticated (tampering-detected) AES-GCM message is discarded in Phase 3.

## How TLS layers with the app-level crypto

Phase 6 adds TLS (`ssl.PROTOCOL_TLS_SERVER` / `PROTOCOL_TLS_CLIENT`) around the whole
client↔server TCP connection, wrapping every socket **before** any envelope — including
the very first register/login — is read or written. This is a **transport-layer**
protection: it makes the connection itself opaque to anyone on the network path, so an
observer between a client and the server can no longer see the JSON structure, field
names, or content of anything at all, not even metadata like `"type": "login"`. It sits
alongside, not in place of, the **application-layer** crypto from Phases 2/3/5 — AES-GCM
session keys and RSA signatures — which protect message content and identity end-to-end
between the two chat *peers themselves*, independent of transport. The distinction that
matters: TLS protects data only while it's in transit to/from the server; the server
itself sees the connection in the clear once TLS terminates there (it's the trusted
relay, not an untrusted network link). AES-GCM + RSA signatures, by contrast, protect a
chat message even from the server — the server only ever sees opaque ciphertext and
routing metadata, never plaintext content, a private key, or a session key, whether or
not TLS is present. Put together: if the *network* were compromised (a MITM on the wire),
TLS is the layer that stops them; if the *relay server itself* were compromised, it's
still the AES-GCM/RSA layer doing the protecting, because the server never held the
keys needed to read chat content or forge a signature in the first place. The client
does not use `check_hostname=False` or `CERT_NONE` to sidestep certificate verification
— that would accept a certificate from literally anyone, which defeats the point of
using TLS at all. Instead it pins trust to exactly the one self-signed certificate this
project generated (`certs/server.crt`, loaded via `load_verify_locations`), so a
different server presenting a different certificate is rejected at the TLS handshake,
before any envelope is ever sent.

## Wire protocol

One JSON object per line (newline-terminated), carried inside the TLS tunnel described
above. Every envelope has a `"type"` field:

| type | direction | carries |
|---|---|---|
| `register` | client → server | `username`, `password`, `public_key` (RSA PEM text) |
| `register_result` | server → client | `success`, `reason` |
| `login` | client → server | `username`, `password` |
| `login_result` | server → client | `success`, `reason` |
| `roster` | server → client | list of currently-online usernames |
| `system` | server → client | human-readable join/leave/error text |
| `user_joined` | server → client | `username` of a newly-connected peer |
| `handshake_init` | client ↔ client (via server) | `from`, `to`, `pubkey` (base64, 32 raw bytes), `handshake_sig` (base64, RSA-PSS signature over `pubkey`) |
| `handshake_response` | client ↔ client (via server) | `from`, `to`, `pubkey` (base64, 32 raw bytes), `handshake_sig` (base64, RSA-PSS signature over `pubkey`) |
| `get_pubkey` | client → server | `username` (whose RSA public key to look up) |
| `pubkey_result` | server → client | `username`, `public_key` (RSA PEM text or null), `success` |
| `chat` | client ↔ client (via server) | `from`, `to`, `nonce`, `ciphertext`, `tag` (all base64); the plaintext AES-GCM decrypts to is itself `{"message", "timestamp", "signature"}` JSON, where `signature` covers `{message, timestamp}` together |

A connection must complete a successful `register` or `login` exchange before the
server admits it to the roster or accepts any handshake/chat envelope from it. The
server routes `handshake_init` / `handshake_response` / `chat` envelopes to the named
`to` recipient only, based on the sender's own claimed `from` field; it never inspects
or needs to understand their payload beyond that routing. `get_pubkey` is answered
directly by the server from its user store (the requested user doesn't need to be
online — a public key is public information regardless of presence).

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

`auth/password_hash.py` — PBKDF2-HMAC-SHA256 password hashing (Phase 4), 200,000+
iterations, a fresh random salt per password, and a constant-time comparison
(`hmac.compare_digest`) on verify:

```python
from auth.password_hash import hash_password, verify_password

stored = hash_password("correct horse battery staple")
# stored == "pbkdf2_sha256$200000$<salt_b64>$<hash_b64>"
assert verify_password("correct horse battery staple", stored)
assert not verify_password("wrong guess", stored)
```

`server/user_store.py` persists only that encoded hash string per username, in
`data/users.json` — the plaintext password is never written to disk.

`crypto_engine/signatures.py` — RSA-2048 signatures (Phase 5), RSA-PSS padding +
SHA-256, with PEM (de)serialization helpers for moving keys to/from disk and the wire:

```python
from crypto_engine.signatures import generate_keypair, sign, verify

private_key, public_key = generate_keypair()
signature = sign(private_key, b"hello")
assert verify(public_key, b"hello", signature) is True
assert verify(public_key, b"tampered", signature) is False  # never raises
```

`crypto_engine/signatures.fingerprint()` (Phase 7a) produces the short human-readable
fingerprint printed after a handshake, for the "check key fingerprints" mitigation:

```python
from crypto_engine.signatures import fingerprint, generate_keypair, serialize_public_key

_, public_key = generate_keypair()
print(fingerprint(serialize_public_key(public_key)))  # e.g. "A1B2 C3D4 E5F6 A7B8"
```

`auth/keystore.py` saves each account's RSA private key locally as an unencrypted PEM
file under `data/keys/<username>_private.pem` (gitignored). In a production system
that file would itself be encrypted at rest (e.g. wrapped under a key derived from the
user's login password); storing it as plain PEM here is a deliberate scope reduction
for this course project, not an oversight — see the comment in `keystore.py`.

`certs/generate_certs.py` (Phase 6) generates the self-signed TLS cert + key used by
`server.py`/`client.py`, using the `cryptography` library directly (not the `openssl`
CLI), so it produces an identical result on every teammate's machine:

```
python certs/generate_certs.py           # writes certs/server.key + certs/server.crt
python certs/generate_certs.py --force   # regenerate, overwriting existing certs
```

Both output files are gitignored — see "How to run" above for why, and for the
one-time setup step every teammate needs to run.

## Live demo scripts

`demo/run_*.py` (Phase 7c) are standalone scripts that each start their own real mini
relay server and two real clients to demonstrate one attack being stopped — meant to be
run live for a demo or in front of the professor, not just as passing tests. Each
prints a clear `[PASS]`/`[FAIL]` per check and an overall result:

| Script | What it proves |
|---|---|
| `demo/run_tamper_demo.py` | A malicious/compromised relay flipping a ciphertext byte in transit cannot get a tampered message displayed — AES-GCM's tag (Phase 2/3) catches it. |
| `demo/run_replay_demo.py` | A relay resending a captured chat message a second time cannot get it displayed twice — the Phase 7b timestamp + duplicate-nonce tracking rejects the replay. |
| `demo/run_mitm_handshake_demo.py` | A malicious relay substituting its own ECDH public key during the handshake is stopped by the Phase 7a signed handshake — no session key is ever derived, and the fingerprint that would result doesn't match either. |

```
python certs/generate_certs.py   # once, if you haven't already
python demo/run_tamper_demo.py
python demo/run_replay_demo.py
python demo/run_mitm_handshake_demo.py
```

See [`demo/README.md`](demo/README.md) for more detail, and
[`demo/capture_instructions.md`](demo/capture_instructions.md) for reproducing a
Wireshark capture of a normal session (not included in this repo, since Wireshark
wasn't available in the sandbox this project was built in — see that file for why and
how to produce one yourself).
