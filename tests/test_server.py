import asyncio

from common.protocol import pack, unpack
from server.main import clients, handle_client


async def connect(port, name):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(pack({"type": "REGISTER", "name": name, "pubkey": "k"}))
    await writer.drain()
    return reader, writer


async def with_server(scenario):
    clients.clear()
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