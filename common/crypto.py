import base64
import hashlib

from nacl.public import Box, PrivateKey, PublicKey


def generate_keypair():
    private = PrivateKey.generate()
    return private, private.public_key


def pub_to_str(public):
    """Cheie publica -> text (base64), ca sa intre in JSON."""
    return base64.b64encode(bytes(public)).decode("ascii")


def pub_from_str(text):
    """Text (base64) -> cheie publica."""
    return PublicKey(base64.b64decode(text))


def fingerprint(public):
    """Amprenta: SHA-256 din cheia publica, 32 caractere hex in grupuri de 4."""
    digest = hashlib.sha256(bytes(public)).hexdigest().upper()[:32]
    return "-".join(digest[i:i + 4] for i in range(0, 32, 4))


def encrypt(text, my_private, their_public):
    """Cripteaza un text pentru destinatar. Intoarce text base64 (nonce + ciphertext)."""
    box = Box(my_private, their_public)
    encrypted = box.encrypt(text.encode("utf-8"))
    return base64.b64encode(bytes(encrypted)).decode("ascii")


def decrypt(data, my_private, their_public):
    """Decripteaza. Arunca nacl.exceptions.CryptoError daca mesajul a fost modificat."""
    box = Box(my_private, their_public)
    raw = base64.b64decode(data)
    return box.decrypt(raw).decode("utf-8")