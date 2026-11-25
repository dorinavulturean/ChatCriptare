import pytest

from client.keystore import load_or_create
from common.crypto import fingerprint, generate_keypair, pub_from_str, pub_to_str


def test_cheie_publica_dus_intors():
    _private, public = generate_keypair()
    assert bytes(pub_from_str(pub_to_str(public))) == bytes(public)


def test_amprenta_stabila_si_diferita():
    _, p1 = generate_keypair()
    _, p2 = generate_keypair()
    assert fingerprint(p1) == fingerprint(p1)
    assert fingerprint(p1) != fingerprint(p2)


def test_amprenta_are_formatul_corect():
    _, public = generate_keypair()
    parts = fingerprint(public).split("-")
    assert len(parts) == 8
    assert all(len(p) == 4 for p in parts)


def test_keystore_pastreaza_aceeasi_cheie(tmp_path):
    prima = load_or_create("ana", base_dir=tmp_path)
    a_doua = load_or_create("ana", base_dir=tmp_path)
    assert bytes(prima) == bytes(a_doua)


def test_keystore_chei_diferite_pe_utilizator(tmp_path):
    ana = load_or_create("ana", base_dir=tmp_path)
    bogdan = load_or_create("bogdan", base_dir=tmp_path)
    assert bytes(ana) != bytes(bogdan)


def test_keystore_refuza_nume_periculos(tmp_path):
    with pytest.raises(ValueError):
        load_or_create("../hack", base_dir=tmp_path)