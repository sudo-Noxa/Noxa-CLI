import os
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PADDING_BLOCK = 512


def _derive_key(raw_secret: bytes, info: bytes = b"anonchat-v2") -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(raw_secret)


def _pad(data: bytes, block: int = PADDING_BLOCK) -> bytes:
    remainder = len(data) % block
    pad_len = block - remainder if remainder != 0 else block
    padding = os.urandom(pad_len - 1) + bytes([pad_len])
    return data + padding


def _unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data after decryption")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError(f"Invalid padding length: {pad_len}")
    return data[:-pad_len]


def aes_encrypt(key: bytes, plaintext: bytes) -> dict:
    nonce = os.urandom(12)
    padded = _pad(plaintext)
    ct = AESGCM(key).encrypt(nonce, padded, None)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(nonce).decode(),
    }


def aes_decrypt(key: bytes, ciphertext_b64: str, nonce_b64: str) -> bytes:
    ct = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    padded = AESGCM(key).decrypt(nonce, ct, None)
    return _unpad(padded)


def make_cover_payload(key: bytes) -> dict:
    return aes_encrypt(key, b"")


class IdentityKey:
    def __init__(self):
        self._priv = X25519PrivateKey.generate()

    def public_key_b64(self) -> str:
        raw = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def compute_shared_key(self, peer_pubkey_b64: str, role: str = "") -> bytes:
        raw = base64.b64decode(peer_pubkey_b64)
        peer_pub = X25519PublicKey.from_public_bytes(raw)
        raw_secret = self._priv.exchange(peer_pub)
        return _derive_key(raw_secret, info=f"anonchat-dm-{role}".encode())

    def decrypt_group_key(self, encrypted_key: dict) -> bytes:
        ephemeral_pub_b64 = encrypted_key["ephemeral_pubkey"]
        raw_bytes = base64.b64decode(ephemeral_pub_b64)
        ephemeral_pub = X25519PublicKey.from_public_bytes(raw_bytes)
        raw_secret = self._priv.exchange(ephemeral_pub)
        shared = _derive_key(raw_secret, info=b"anonchat-group-key")
        return aes_decrypt(shared, encrypted_key["ciphertext"], encrypted_key["nonce"])


class DMSession:
    def __init__(self, shared_key: bytes):
        self._key = shared_key

    def encrypt(self, text: str) -> dict:
        return aes_encrypt(self._key, text.encode())

    def decrypt(self, ciphertext_b64: str, nonce_b64: str) -> str:
        return aes_decrypt(self._key, ciphertext_b64, nonce_b64).decode()

    def make_cover(self) -> dict:
        return make_cover_payload(self._key)


class GroupSession:
    def __init__(self, group_key: bytes = None):
        self._key = group_key if group_key is not None else os.urandom(32)

    @property
    def key(self) -> bytes:
        return self._key

    def encrypt(self, text: str) -> dict:
        return aes_encrypt(self._key, text.encode())

    def decrypt(self, ciphertext_b64: str, nonce_b64: str) -> str:
        return aes_decrypt(self._key, ciphertext_b64, nonce_b64).decode()

    def make_cover(self) -> dict:
        return make_cover_payload(self._key)

    def encrypt_key_for_peer(self, peer_pubkey_b64: str) -> dict:
        ephemeral_priv = X25519PrivateKey.generate()
        ephemeral_pub_raw = ephemeral_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        peer_pub = X25519PublicKey.from_public_bytes(base64.b64decode(peer_pubkey_b64))
        raw_secret = ephemeral_priv.exchange(peer_pub)
        shared = _derive_key(raw_secret, info=b"anonchat-group-key")
        encrypted = aes_encrypt(shared, self._key)
        encrypted["ephemeral_pubkey"] = base64.b64encode(ephemeral_pub_raw).decode()
        return encrypted
