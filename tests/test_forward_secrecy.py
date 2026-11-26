import base64

import pytest
from nacl.exceptions import CryptoError

from common.crypto import (
    KEEP,
    ROTATE_AFTER,
    PeerSession,
    decrypt,
    encrypt,
    generate_keypair,
)


def make_pair():
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    return PeerSession(a_priv, b_pub), PeerSession(b_priv, a_pub), a_priv, b_priv


def handshake(a, b):
    """A trimite eph1, B raspunde cu eph2, ca in client."""
    b.accept(a.new_ephemeral())
    a.accept(b.new_ephemeral())


def altereaza(ct):
    prefix, sid, mid, payload = ct.split(":", 3)
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 1
    return ":".join([prefix, sid, mid, base64.b64encode(bytes(raw)).decode("ascii")])


def test_mesaj_trece_in_ambele_sensuri():
    a, b, _, _ = make_pair()
    handshake(a, b)
    assert b.decrypt(a.encrypt("salut")) == "salut"
    assert a.decrypt(b.encrypt("buna")) == "buna"


def test_ciphertext_nu_contine_textul():
    a, b, _, _ = make_pair()
    handshake(a, b)
    ct = a.encrypt("mesaj-foarte-secret")
    assert ct.startswith("fs1:")
    assert "secret" not in ct


def test_mesaj_modificat_este_respins():
    a, b, _, _ = make_pair()
    handshake(a, b)
    with pytest.raises(CryptoError):
        b.decrypt(altereaza(a.encrypt("salut")))


def test_anunt_de_la_impostor_este_respins():
    a, b, _, _ = make_pair()
    atacator_priv, _ = generate_keypair()
    impostor = PeerSession(atacator_priv, b.my_identity.public_key)
    with pytest.raises(CryptoError):
        b.accept(impostor.new_ephemeral())


def test_anunt_reluat_este_ignorat():
    a, b, _, _ = make_pair()
    vechi = a.new_ephemeral()
    assert b.accept(vechi) is True
    assert b.accept(a.new_ephemeral()) is True
    curenta = b.their_current
    assert b.accept(vechi) is False
    assert b.their_current == curenta


def test_mesaje_in_zbor_supravietuiesc_unei_rotiri():
    a, b, _, _ = make_pair()
    handshake(a, b)
    ct = a.encrypt("in zbor")
    handshake(a, b)  # rotire inainte ca B sa citeasca mesajul
    assert b.decrypt(ct) == "in zbor"


def test_rotatie_dupa_n_mesaje():
    a, b, _, _ = make_pair()
    handshake(a, b)
    for _ in range(ROTATE_AFTER):
        assert not a.needs_rotation()
        a.encrypt("x")
    assert a.needs_rotation()
    handshake(a, b)
    assert not a.needs_rotation()


def test_forward_secrecy_mesajul_vechi_nu_mai_poate_fi_citit():
    a, b, a_priv, b_priv = make_pair()
    handshake(a, b)
    vechi = a.encrypt("secret vechi")
    for _ in range(KEEP):
        handshake(a, b)  # rotiri: cheile efemere vechi sunt sterse
    # "Atacatorul" are acum cheile de identitate ale ambilor si starea curenta
    with pytest.raises(ValueError):
        b.decrypt(vechi)
    with pytest.raises(ValueError):
        PeerSession(b_priv, a_priv.public_key).decrypt(vechi)


def test_fara_forward_secrecy_cheia_de_identitate_citeste_tot():
    """Contrast: modul vechi (cheie de identitate) se poate citi cu cheia furata."""
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    ct = encrypt("x", a_priv, b_pub)
    assert decrypt(ct, b_priv, a_pub) == "x"  