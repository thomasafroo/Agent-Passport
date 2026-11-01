"""Operator tool: generate an issuer Ed25519 key for PASSPORT_ISSUER_KEY_REFERENCE.

Prints the private key, base64url-encoded raw 32 bytes, on stdout and nothing else there, so it
can be pasted into a 1Password item. The matching public key goes to stderr for pinning in
`verify_evidence.py --public-key-file`. Nothing is written to disk. Clear the terminal (and its
scrollback) after pasting, and do not redirect stdout into a file in the repository.

    python scripts/generate_issuer_key.py
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from agent_passport.core import b64


def main():
    key = Ed25519PrivateKey.generate()
    public = b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    print(f"Issuer public key (pin this): {public}", file=sys.stderr)
    print(b64(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
