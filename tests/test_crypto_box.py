import base64

import pytest
from nacl.exceptions import CryptoError

from common.crypto import decrypt, encrypt, generate_keypair


def altereaza(ciphertext):
    raw = bytearray(base64.b64decode(ciphertext))
    raw[-1] ^= 1
    return base64.b64encode(bytes(raw)).decode("ascii")


def test_ana_catre_bogdan():
    ana_priv, ana_pub = generate_keypair()
    bogdan_priv, bogdan_pub = generate_keypair()
    ct = encrypt("salut", ana_priv, bogdan_pub)
    assert decrypt(ct, bogdan_priv, ana_pub) == "salut"


def test_diacritice():
    ana_priv, ana_pub = generate_keypair()
    bogdan_priv, bogdan_pub = generate_keypair()
    text = "\u0103\u00ee\u0219\u021b\u00e2"
    ct = encrypt(text, ana_priv, bogdan_pub)
    assert decrypt(ct, bogdan_priv, ana_pub) == text


def test_mesaj_modificat_este_respins():
    ana_priv, ana_pub = generate_keypair()
    bogdan_priv, bogdan_pub = generate_keypair()
    ct = encrypt("salut", ana_priv, bogdan_pub)
    with pytest.raises(CryptoError):
        decrypt(altereaza(ct), bogdan_priv, ana_pub)


def test_alta_cheie_nu_poate_decripta():
    ana_priv, ana_pub = generate_keypair()
    _bogdan_priv, bogdan_pub = generate_keypair()
    corina_priv, _corina_pub = generate_keypair()
    ct = encrypt("secret", ana_priv, bogdan_pub)
    with pytest.raises(CryptoError):
        decrypt(ct, corina_priv, ana_pub)


def test_acelasi_text_da_ciphertext_diferit():
    ana_priv, _ana_pub = generate_keypair()
    _bogdan_priv, bogdan_pub = generate_keypair()
    assert encrypt("salut", ana_priv, bogdan_pub) != encrypt("salut", ana_priv, bogdan_pub)


def test_ciphertext_nu_contine_textul():
    ana_priv, _ana_pub = generate_keypair()
    _bogdan_priv, bogdan_pub = generate_keypair()
    ct = encrypt("mesaj-foarte-secret", ana_priv, bogdan_pub)
    assert "secret" not in ct