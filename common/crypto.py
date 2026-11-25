import base64
import hashlib

from nacl.public import PrivateKey, PublicKey


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