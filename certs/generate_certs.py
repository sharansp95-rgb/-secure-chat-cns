"""Generate a self-signed TLS certificate + private key for localhost
testing (Phase 6).

Uses the `cryptography` library directly rather than shelling out to the
`openssl` CLI, so every teammate gets an identical result without needing
openssl installed separately.

Output: certs/server.key (RSA-2048 private key, PEM) and certs/server.crt
(self-signed X.509 certificate, PEM), both for CN=localhost, valid 365 days.

Both files are gitignored (see .gitignore's certs/*.key and certs/*.crt
entries) -- a self-signed cert is fine to share, but a *committed* private
key would let anyone with repo access impersonate the server, which defeats
the point of TLS entirely. Each teammate runs this script once, locally,
before first use.

Run: python certs/generate_certs.py [--force]
"""

import argparse
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(CERTS_DIR, "server.key")
CERT_PATH = os.path.join(CERTS_DIR, "server.crt")

VALIDITY_DAYS = 365
KEY_SIZE = 2048


def generate(force=False):
    if (os.path.exists(KEY_PATH) or os.path.exists(CERT_PATH)) and not force:
        print(f"[!] Certs already exist at {KEY_PATH} / {CERT_PATH} -- not overwriting.")
        print("    Re-run with --force to regenerate (this invalidates the old cert; "
              "restart any running server and re-trust the new certs/server.crt "
              "on every client).")
        return False

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # self-signed: issuer == subject
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(
            # Not a CA -- this is a self-signed end-entity (leaf) cert. It's
            # trusted directly as its own root via load_verify_locations on
            # the client, which Python's ssl module supports regardless of
            # this flag; CA:FALSE is just the honest description of what
            # this certificate actually is.
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CERT_PATH, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"[*] Generated {KEY_PATH}")
    print(f"[*] Generated {CERT_PATH}")
    print(f"[*] CN=localhost, valid {VALIDITY_DAYS} days from now.")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate a self-signed TLS cert+key for localhost testing"
    )
    parser.add_argument("--force", action="store_true",
                         help="overwrite existing certs/server.key and certs/server.crt")
    args = parser.parse_args()
    ok = generate(force=args.force)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
