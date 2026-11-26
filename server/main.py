import asyncio
import logging
import re

from common.protocol import pack, unpack

HOST = "0.0.0.0"
PORT = 9000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("server")

# nume -> (writer, cheie publica)
clients = {}
rooms = {}  # camera -> set de nume
ROOM_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")


async def send(writer, msg):
    writer.write(pack(msg))
    await writer.drain()


async def handle_client(reader, writer):
    name = None
    try:
        msg = await unpack(reader)
        if msg.get("type") != "REGISTER" or not msg.get("name"):
            await send(writer, {"type": "ERROR", "reason": "trebuie REGISTER"})
            return
        if msg["name"] in clients:
            await send(writer, {"type": "ERROR", "reason": "nume deja folosit"})
            return

        name = msg["name"]
        clients[name] = (writer, msg.get("pubkey", ""))
        await send(writer, {"type": "OK"})
        log.info("REGISTER %s", name)

        while True:
            msg = await unpack(reader)
            kind = msg.get("type")
            if kind == "LIST":
                await send(writer, {"type": "USERS", "users": sorted(clients)})
            elif kind == "GET_KEY":
                target = clients.get(msg.get("name"))
                if target is None:
                    await send(writer, {"type": "ERROR", "reason": "utilizator necunoscut"})
                else:
                    await send(writer, {"type": "KEY", "name": msg["name"], "pubkey": target[1]})
            elif kind == "MSG":
                dest = clients.get(msg.get("to"))
                if dest is None:
                    await send(writer, {"type": "ERROR", "reason": "utilizator offline"})
                    continue
                ciphertext = msg.get("ciphertext", "")
                log.info("MSG %s -> %s len=%d", name, msg["to"], len(ciphertext))
                await send(dest[0], {"type": "MSG", "from": name, "ciphertext": ciphertext})
            elif kind == "JOIN":
                room = str(msg.get("room", ""))
                if not ROOM_RE.fullmatch(room):
                    await send(writer, {"type": "ERROR", "reason": "nume camera invalid"})
                    continue
                members = rooms.setdefault(room, set())
                members.add(name)
                await send(writer, {"type": "JOINED", "room": room, "members": sorted(members)})
                log.info("JOIN %s %s", name, room)
            elif kind == "LEAVE":
                room = str(msg.get("room", ""))
                members = rooms.get(room)
                if members and name in members:
                    members.discard(name)
                    if not members:
                        del rooms[room]
                    await send(writer, {"type": "LEFT", "room": room})
                else:
                    await send(writer, {"type": "ERROR", "reason": "nu esti in camera"})
            elif kind == "MEMBERS":
                room = str(msg.get("room", ""))
                members = rooms.get(room, set())
                if name not in members:
                    await send(writer, {"type": "ERROR", "reason": "nu esti in camera"})
                else:
                    await send(writer, {"type": "MEMBERS", "room": room, "members": sorted(members)})
            elif kind == "GROUP_MSG":
                room = str(msg.get("room", ""))
                members = rooms.get(room, set())
                items = msg.get("messages")
                if name not in members or not isinstance(items, list) or len(items) > 50:
                    await send(writer, {"type": "ERROR", "reason": "mesaj de grup invalid"})
                    continue
                delivered = 0
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    to = item.get("to")
                    ciphertext = item.get("ciphertext")
                    if not isinstance(to, str) or not isinstance(ciphertext, str):
                        continue
                    if to == name or to not in members or to not in clients:
                        continue
                    try:
                        await send(
                            clients[to][0],
                            {"type": "GROUP_MSG", "room": room, "from": name, "ciphertext": ciphertext},
                        )
                        delivered += 1
                    except ConnectionError:
                        pass
                log.info("GROUP_MSG %s in %s catre %d membri", name, room, delivered)
            else:
                await send(writer, {"type": "ERROR", "reason": "tip necunoscut"})
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    except ValueError as e:
        log.info("mesaj invalid de la %s: %s", name, e)
    finally:
        if name is not None and clients.get(name, (None,))[0] is writer:
            del clients[name]
            log.info("DISCONNECT %s", name)
            for room in list(rooms):
                rooms[room].discard(name)
                if not rooms[room]:
                    del rooms[room]
        writer.close()


async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    log.info("server pornit pe %s:%d", HOST, PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())