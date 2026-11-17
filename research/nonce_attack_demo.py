"""Recover the published test key from two signatures made by nonce-demo.

Build wallet-nonce-demo.zip first with build/build-wallet-zip.sh nonce-demo.
This script only ever uses the fixed public test key below.
"""

import hashlib
from pathlib import Path
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
WALLET_ZIP = ROOT / "build" / "out" / "wallet-nonce-demo.zip"
SECRET = int.from_bytes(bytes.fromhex("11" * 32), "big")

if not WALLET_ZIP.is_file():
    raise SystemExit("build wallet-nonce-demo.zip first")

with tempfile.TemporaryDirectory(prefix="nonce-demo-") as extracted:
    with zipfile.ZipFile(WALLET_ZIP) as archive:
        archive.extractall(extracted)
    sys.path.insert(0, extracted)

    from embit import ec
    from seedsigner.helpers.fixed_nonce import _GX, _N, install_fixed_nonce

    install_fixed_nonce()

    def parse_der(signature):
        i = 0
        assert signature[i] == 0x30
        i += 1
        assert signature[i] + i + 1 == len(signature)
        i += 1
        assert signature[i] == 0x02
        i += 1
        r_len = signature[i]
        i += 1
        r = int.from_bytes(signature[i : i + r_len], "big")
        i += r_len
        assert signature[i] == 0x02
        i += 1
        s_len = signature[i]
        i += 1
        s = int.from_bytes(signature[i : i + s_len], "big")
        return r, s

    key = ec.PrivateKey(SECRET.to_bytes(32, "big"))
    message_hashes = [
        hashlib.sha256(b"transaction one").digest(),
        hashlib.sha256(b"transaction two").digest(),
    ]
    signatures = [key.sign(message_hash).serialize() for message_hash in message_hashes]
    parsed = [parse_der(signature) for signature in signatures]

    z1, z2 = (int.from_bytes(message_hash, "big") for message_hash in message_hashes)
    (r1, s1), (r2, s2) = parsed
    r_inv = pow(r1, -1, _N)
    candidates = {
        ((s1 - z1) * r_inv) % _N,
        ((s2 - z2) * r_inv) % _N,
        ((-s1 - z1) * r_inv) % _N,
        ((-s2 - z2) * r_inv) % _N,
    }
    recovered = next((candidate for candidate in candidates if candidate == SECRET), None)

    print("same ECDSA r:", r1 == r2 == _GX)
    print("recovered test private key:", recovered == SECRET)
    print("public key:", key.get_public_key().sec().hex())
