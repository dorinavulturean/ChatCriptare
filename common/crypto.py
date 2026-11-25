from nacl.public import Box, PrivateKey, PublicKey

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

