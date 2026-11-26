from client.keystore import check_known, trust_key


def test_prima_data_e_noua_apoi_aceeasi(tmp_path):
    assert check_known("ana", "bogdan", "cheieA", base_dir=tmp_path) == "new"
    assert check_known("ana", "bogdan", "cheieA", base_dir=tmp_path) == "same"


def test_cheie_schimbata_e_detectata(tmp_path):
    check_known("ana", "bogdan", "cheieA", base_dir=tmp_path)
    assert check_known("ana", "bogdan", "cheieB", base_dir=tmp_path) == "changed"
    # a doua oara tot 'changed': cheia veche nu s-a suprascris singura
    assert check_known("ana", "bogdan", "cheieB", base_dir=tmp_path) == "changed"


def test_trust_accepta_cheia_noua(tmp_path):
    check_known("ana", "bogdan", "cheieA", base_dir=tmp_path)
    trust_key("ana", "bogdan", "cheieB", base_dir=tmp_path)
    assert check_known("ana", "bogdan", "cheieB", base_dir=tmp_path) == "same"


def test_persoane_diferite_sunt_independente(tmp_path):
    check_known("ana", "bogdan", "cheieA", base_dir=tmp_path)
    assert check_known("ana", "corina", "cheieX", base_dir=tmp_path) == "new"