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


ROTATE_AFTER = 20  # mesaje trimise cu aceeasi pereche de chei efemere
KEEP = 3  # cate chei efemere pastram (curenta + cateva vechi, pentru mesaje in zbor)


def eph_id(public):
    """Un identificator scurt pentru o cheie efemera."""
    return hashlib.sha256(bytes(public)).hexdigest()[:8]


class PeerSession:
    """Sesiune cu chei efemere intre noi si un alt utilizator (doar in memorie)."""

    def __init__(self, my_identity, peer_identity):
        self.my_identity = my_identity  # PrivateKey de identitate
        self.peer_identity = peer_identity  # PublicKey de identitate a celuilalt
        self.mine = {}  # id -> PrivateKey efemera (cele mai noi KEEP)
        self.theirs = {}  # id -> PublicKey efemera a celuilalt
        self.my_current = None
        self.their_current = None
        self.sent = 0

    def new_ephemeral(self):
        """Genereaza o cheie efemera noua si intoarce anuntul ei, autentificat cu identitatea."""
        private = PrivateKey.generate()
        key_id = eph_id(private.public_key)
        self.mine[key_id] = private
        self.my_current = key_id
        self.sent = 0
        while len(self.mine) > KEEP:
            del self.mine[next(iter(self.mine))]  # cheia veche e stearsa
        box = Box(self.my_identity, self.peer_identity)
        announcement = box.encrypt(bytes(private.public_key))
        return base64.b64encode(bytes(announcement)).decode("ascii")

    def accept(self, announcement):
        """Primeste anuntul celuilalt. Intoarce False daca e o repetitie a unui anunt vechi."""
        box = Box(self.my_identity, self.peer_identity)
        raw = box.decrypt(base64.b64decode(announcement))  # CryptoError daca e fals
        if len(raw) != 32:
            raise ValueError("cheie efemera invalida")
        public = PublicKey(raw)
        key_id = eph_id(public)
        if key_id in self.theirs:
            return False
        self.theirs[key_id] = public
        self.their_current = key_id
        while len(self.theirs) > KEEP:
            del self.theirs[next(iter(self.theirs))]
        return True

    def ready(self):
        return self.my_current is not None and self.their_current is not None

    def needs_rotation(self):
        return self.sent >= ROTATE_AFTER

    def encrypt(self, text):
        box = Box(self.mine[self.my_current], self.theirs[self.their_current])
        payload = base64.b64encode(bytes(box.encrypt(text.encode("utf-8")))).decode("ascii")
        self.sent += 1
        return f"fs1:{self.my_current}:{self.their_current}:{payload}"

    def decrypt(self, data):
        parts = data.split(":", 3)
        if len(parts) != 4 or parts[0] != "fs1":
            raise ValueError("format invalid")
        _, sender_id, my_id, payload = parts
        private = self.mine.get(my_id)
        public = self.theirs.get(sender_id)
        if private is None or public is None:
            raise ValueError("cheie efemera necunoscuta (probabil stearsa)")
        return Box(private, public).decrypt(base64.b64decode(payload)).decode("utf-8")