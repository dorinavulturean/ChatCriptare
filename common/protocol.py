import json
import struct

MAX_SIZE = 64 * 1024  # 64 KB, limită anti-abuz


def pack(msg: dict) -> bytes:
    """Transforma un dict în bytes: 4 bytes lungime + JSON."""
    data = json.dumps(msg).encode("utf-8")
    if len(data) > MAX_SIZE:
        raise ValueError("mesaj prea mare")
    return struct.pack(">I", len(data)) + data


async def unpack(reader) -> dict:
    """Citeste exact un mesaj dintr-un asyncio.StreamReader."""
    header = await reader.readexactly(4)
    (length,) = struct.unpack(">I", header)
    if length > MAX_SIZE:
        raise ValueError("mesaj prea mare")
    data = await reader.readexactly(length)
    return json.loads(data.decode("utf-8"))