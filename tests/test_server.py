import asyncio

from common.protocol import pack, unpack
from server import main as server_main
from server.main import MAX_CIPHERTEXT, clients, handle_client
from server.storage import Storage


async def connect(port, name):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(pack({"type": "REGISTER", "name": name, "pubkey": "k"}))
    await writer.drain()
    return reader, writer


async def with_server(scenario):
    clients.clear()
    server_main.storage = Storage()
    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        return await scenario(port)


def test_relay():
    async def scenario(port):
        ra, wa = await connect(port, "ana")
        rb, wb = await connect(port, "bogdan")
        assert (await unpack(ra))["type"] == "OK"
        assert (await unpack(rb))["type"] == "OK"
        wa.write(pack({"type": "MSG", "to": "bogdan", "ciphertext": "xyz"}))
        await wa.drain()
        got = await asyncio.wait_for(unpack(rb), 2)
        wa.close()
        wb.close()
        return got

    got = asyncio.run(with_server(scenario))
    assert got == {"type": "MSG", "from": "ana", "ciphertext": "xyz"}


def test_nume_duplicat():
    async def scenario(port):
        ra, wa = await connect(port, "ana")
        assert (await unpack(ra))["type"] == "OK"
        rb, wb = await connect(port, "ana")
        got = await asyncio.wait_for(unpack(rb), 2)
        wa.close()
        wb.close()
        return got

    got = asyncio.run(with_server(scenario))
    assert got["type"] == "ERROR"

def test_get_key():
    async def scenario(port):
        ra, wa = await connect(port, "ana")
        rb, wb = await connect(port, "bogdan")
        await unpack(ra)
        await unpack(rb)
        wa.write(pack({"type": "GET_KEY", "name": "bogdan"}))
        await wa.drain()
        got = await asyncio.wait_for(unpack(ra), 2)
        wa.close()
        wb.close()
        return got

    got = asyncio.run(with_server(scenario))
    assert got == {"type": "KEY", "name": "bogdan", "pubkey": "k"}


async def join(reader, writer, room):
    writer.write(pack({"type": "JOIN", "room": room}))
    await writer.drain()
    return await asyncio.wait_for(unpack(reader), 2)


def test_grup():
    async def scenario(port):
        ra, wa = await connect(port, "ana")
        rb, wb = await connect(port, "bogdan")
        rc, wc = await connect(port, "corina")
        for r in (ra, rb, rc):
            assert (await unpack(r))["type"] == "OK"
        for r, w in ((ra, wa), (rb, wb), (rc, wc)):
            assert (await join(r, w, "proiect"))["type"] == "JOINED"
        items = [
            {"to": "bogdan", "ciphertext": "x1"},
            {"to": "corina", "ciphertext": "x2"},
        ]
        wa.write(pack({"type": "GROUP_MSG", "room": "proiect", "messages": items}))
        await wa.drain()
        got_b = await asyncio.wait_for(unpack(rb), 2)
        got_c = await asyncio.wait_for(unpack(rc), 2)
        for w in (wa, wb, wc):
            w.close()
        return got_b, got_c

    got_b, got_c = asyncio.run(with_server(scenario))
    assert got_b == {"type": "GROUP_MSG", "room": "proiect", "from": "ana", "ciphertext": "x1"}
    assert got_c == {"type": "GROUP_MSG", "room": "proiect", "from": "ana", "ciphertext": "x2"}


def test_grup_nemembru_este_respins():
    async def scenario(port):
        ra, wa = await connect(port, "ana")
        rb, wb = await connect(port, "bogdan")
        await unpack(ra)
        await unpack(rb)
        await join(rb, wb, "proiect")  # doar bogdan e in camera
        items = [{"to": "bogdan", "ciphertext": "x"}]
        wa.write(pack({"type": "GROUP_MSG", "room": "proiect", "messages": items}))
        await wa.drain()
        got = await asyncio.wait_for(unpack(ra), 2)
        wa.close()
        wb.close()
        return got

    got = asyncio.run(with_server(scenario))
    assert got["type"] == "ERROR"

async def wait_offline(name):
    for _ in range(100):
        if name not in clients:
            return
        await asyncio.sleep(0.05)


def test_mesaj_offline_livrat_la_conectare():
    async def scenario(port):
        rb, wb = await connect(port, "bogdan")
        assert (await unpack(rb))["type"] == "OK"
        wb.close()
        await wait_offline("bogdan")

        ra, wa = await connect(port, "ana")
        assert (await unpack(ra))["type"] == "OK"
        wa.write(pack({"type": "MSG", "to": "bogdan", "ciphertext": "xyz"}))
        await wa.drain()
        queued = await asyncio.wait_for(unpack(ra), 2)

        rb2, wb2 = await connect(port, "bogdan")
        assert (await unpack(rb2))["type"] == "OK"
        got = await asyncio.wait_for(unpack(rb2), 2)
        wa.close()
        wb2.close()
        return queued, got

    queued, got = asyncio.run(with_server(scenario))
    assert queued == {"type": "QUEUED", "to": "bogdan"}
    assert got == {"type": "MSG", "from": "ana", "ciphertext": "xyz", "offline": True}


def test_offline_destinatar_necunoscut():
    async def scenario(port):
        ra, wa = await connect(port, "ana")
        assert (await unpack(ra))["type"] == "OK"
        wa.write(pack({"type": "MSG", "to": "nimeni", "ciphertext": "x"}))
        await wa.drain()
        got = await asyncio.wait_for(unpack(ra), 2)
        wa.close()
        return got

    got = asyncio.run(with_server(scenario))
    assert got["type"] == "ERROR"


def test_flood_deconecteaza(monkeypatch):
    monkeypatch.setattr(server_main, "BURST", 3)

    async def scenario(port):
        ra, wa = await connect(port, "ana")
        assert (await unpack(ra))["type"] == "OK"
        wa.write(b"".join(pack({"type": "LIST"}) for _ in range(30)))
        await wa.drain()
        types = []
        while True:
            try:
                msg = await asyncio.wait_for(unpack(ra), 2)
            except asyncio.IncompleteReadError:
                break
            types.append(msg["type"])
        wa.close()
        return types

    types = asyncio.run(with_server(scenario))
    assert "ERROR" in types
    assert types.count("USERS") < 30


def test_register_timeout(monkeypatch):
    monkeypatch.setattr(server_main, "REGISTER_TIMEOUT", 0.2)

    async def scenario(port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        data = await asyncio.wait_for(reader.read(), 2)
        writer.close()
        return data

    assert asyncio.run(with_server(scenario)) == b""


def test_ciphertext_prea_lung():
    async def scenario(port):
        ra, wa = await connect(port, "ana")
        assert (await unpack(ra))["type"] == "OK"
        wa.write(pack({"type": "MSG", "to": "bogdan", "ciphertext": "x" * (MAX_CIPHERTEXT + 1)}))
        await wa.drain()
        got = await asyncio.wait_for(unpack(ra), 2)
        wa.close()
        return got

    got = asyncio.run(with_server(scenario))
    assert got == {"type": "ERROR", "reason": "mesaj invalid sau prea lung"}

def test_anunt_efemer_nu_se_pune_in_coada():
    async def scenario(port):
        rb, wb = await connect(port, "bogdan")
        assert (await unpack(rb))["type"] == "OK"
        wb.close()
        await wait_offline("bogdan")

        ra, wa = await connect(port, "ana")
        assert (await unpack(ra))["type"] == "OK"
        wa.write(pack({"type": "MSG", "to": "bogdan", "ciphertext": "eph1:abc"}))
        await wa.drain()
        got = await asyncio.wait_for(unpack(ra), 2)
        wa.close()
        return got, server_main.storage.pending("bogdan")

    got, pending = asyncio.run(with_server(scenario))
    assert got == {"type": "ERROR", "reason": "utilizator offline"}
    assert pending == []

