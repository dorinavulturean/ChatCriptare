import asyncio
import struct

import pytest

from common.protocol import MAX_SIZE, pack, unpack


async def run(data: bytes):
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return await unpack(reader)


def test_roundtrip():
    msg = {"type": "MSG", "to": "bogdan", "ciphertext": "abc"}
    assert asyncio.run(run(pack(msg))) == msg


def test_diacritice():
    msg = {"text": "ăîșțâ"}
    assert asyncio.run(run(pack(msg))) == msg


def test_mesaj_trunchiat():
    data = pack({"type": "MSG"})[:-3]
    with pytest.raises(asyncio.IncompleteReadError):
        asyncio.run(run(data))


def test_lungime_prea_mare():
    data = struct.pack(">I", MAX_SIZE + 1) + b"x"
    with pytest.raises(ValueError):
        asyncio.run(run(data))