from server.storage import MAX_QUEUE, Storage


def test_cheie_si_coada_persista(tmp_path):
    path = tmp_path / "store.json"
    s = Storage(path)
    s.set_key("bogdan", "k")
    assert s.enqueue("bogdan", {"from": "ana", "ciphertext": "x"})

    s2 = Storage(path)
    assert s2.get_key("bogdan") == "k"
    assert s2.pending("bogdan") == [{"from": "ana", "ciphertext": "x"}]
    s2.clear("bogdan")
    assert Storage(path).pending("bogdan") == []


def test_cutia_se_umple():
    s = Storage()
    for i in range(MAX_QUEUE):
        assert s.enqueue("bogdan", {"i": i})
    assert not s.enqueue("bogdan", {"i": "peste"})