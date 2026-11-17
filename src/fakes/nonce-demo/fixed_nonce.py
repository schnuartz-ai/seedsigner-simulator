"""EDUCATIONAL ONLY: ECDSA/Schnorr signing with a fixed nonce of 1.

This module replaces embit's nonce derivation (RFC6979 for ECDSA and the
BIP340 nonce function for Schnorr) with k = 1. Reusing a nonce leaks the
private key. Never use this outside of a controlled teaching environment.
"""

from hashlib import sha256

from embit import ec

_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_GY_IS_EVEN = (_GY & 1) == 0


class FixedNonceSignature:
    def __init__(self, der):
        self._der = der

    def serialize(self):
        return self._der

    def write_to(self, stream):
        return stream.write(self._der)


def _der_integer(value):
    raw = value.to_bytes(32, "big")
    start = 0
    while start < len(raw) - 1 and raw[start] == 0:
        start += 1
    raw = raw[start:]
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def _der_encode(r, s):
    body = _der_integer(r) + _der_integer(s)
    return b"\x30" + bytes([len(body)]) + body


def _fixed_nonce_ecdsa_sign(self, msg_hash, grind=True):
    if len(msg_hash) != 32:
        raise ValueError("Message should be 32 bytes long")
    secret = int.from_bytes(self._secret, "big")
    z = int.from_bytes(msg_hash, "big")
    r = _GX % _N
    s = (z + r * secret) % _N
    if s == 0:
        raise ValueError("Invalid signature")
    if s > _N // 2:
        s = _N - s
    return FixedNonceSignature(_der_encode(r, s))


def _tagged_hash(tag, msg):
    tag_hash = sha256(tag).digest()
    return sha256(tag_hash + tag_hash + msg).digest()


def _fixed_nonce_schnorr_sign(self, msg_hash):
    if len(msg_hash) != 32:
        raise ValueError("Message should be 32 bytes long")
    d0 = int.from_bytes(self._secret, "big")
    sec = self.get_public_key().sec()
    d = _N - d0 if sec[0] == 0x03 else d0
    pub_x = sec[1:33]
    r = _GX % _N
    if not _GY_IS_EVEN:
        r = _N - r
    rx = r.to_bytes(32, "big")
    e = int.from_bytes(_tagged_hash(b"BIP0340/challenge", rx + pub_x + msg_hash), "big") % _N
    s = (1 + e * d) % _N
    return ec.SchnorrSig(rx + s.to_bytes(32, "big"))


def install_fixed_nonce():
    ec.PrivateKey.sign = _fixed_nonce_ecdsa_sign
    ec.PrivateKey.schnorr_sign = _fixed_nonce_schnorr_sign
