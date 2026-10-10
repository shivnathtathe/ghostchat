"""Local key management and AES-256-GCM message encryption."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_FILE = Path(__file__).with_name(".offline_chat.key")
KEY_ENV = "OFFLINE_CHAT_KEY"


def load_key(create: bool = False) -> bytes:
    configured = os.environ.get(KEY_ENV)
    if configured:
        key = _decode_key(configured)
    elif KEY_FILE.exists():
        key = _decode_key(KEY_FILE.read_text(encoding="ascii").strip())
    elif create:
        key = AESGCM.generate_key(bit_length=256)
        KEY_FILE.write_text(base64.urlsafe_b64encode(key).decode("ascii"), encoding="ascii")
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
        print(f"Generated shared AES key: {KEY_FILE}")
    else:
        raise RuntimeError(
            f"No shared key found. Start server.py first, or set {KEY_ENV} to a Base64-encoded 32-byte key."
        )
    if len(key) != 32:
        raise RuntimeError("The AES key must decode to exactly 32 bytes")
    return key


def encrypt_message(key: bytes, sender: str, recipient: str, message_id: str, plaintext: str) -> bytes:
    nonce = os.urandom(12)
    aad = _associated_data(sender, recipient, message_id)
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)


def decrypt_message(key: bytes, sender: str, recipient: str, message_id: str, encrypted: bytes) -> str:
    if len(encrypted) < 28:
        raise ValueError("encrypted message is too short")
    aad = _associated_data(sender, recipient, message_id)
    return AESGCM(key).decrypt(encrypted[:12], encrypted[12:], aad).decode("utf-8")


def _associated_data(sender: str, recipient: str, message_id: str) -> bytes:
    return f"{sender}\0{recipient}\0{message_id}".encode("utf-8")


def _decode_key(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError("The shared key is not valid Base64") from exc
