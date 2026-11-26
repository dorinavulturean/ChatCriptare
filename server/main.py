import asyncio
import logging
import os
import re

from common.protocol import pack, unpack
from server.limits import RateLimiter
from server.storage import Storage

HOST = "0.0.0.0"
PORT = 9000

REGISTER_TIMEOUT = 10  # secunde pana la primul mesaj (REGISTER)
IDLE_TIMEOUT = 300  # secunde fara niciun mesaj
SEND_TIMEOUT = 5  # secunde pentru a trimite catre un client lent
RATE = 5.0  # mesaje pe secunda, in medie
BURST = 10  # mesaje permise deodata
MAX_CLIENTS = 100
MAX_CIPHERTEXT = 8192  # caractere (base64)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("server")

NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")

# nume -> (writer, cheie publica), doar cei online
clients = {}
rooms = {}  # camera -> set de nume
storage = Storage(os.environ.get("E2E_STORE", "data/store.json"))


async def send(writer, msg):
    writer.write(pack(msg))
    await asyncio.wait_for(writer.drain(), SEND_TIMEOUT)


def valid_ciphertext(value):
    return isinstance(value, str) and 0 < len(value) <= MAX_CIPHERTEXT


async def handle_client(reader, writer):
    name = None
    limiter = RateLimiter(RATE, BURST)
    try:
        msg = await asyncio.wait_for(unpack(reader), REGISTER_TIMEOUT)
        wanted = msg.get("name")
        pubkey = msg.get("pubkey", "")
        if msg.get("type") != "REGISTER" or not isinstance(wanted, str):
            await send(writer, {"type": "ERROR", "reason": "trebuie REGISTER"})
            return
        if not NAME_RE.fullmatch(wanted) or not isinstance(pubkey, str) or len(pubkey) > 200:
            await send(writer, {"type": "ERROR", "reason": "nume sau cheie invalida"})
            return
        if wanted in clients:
            await send(writer, {"type": "ERROR", "reason": "nume deja folosit"})
            return
        if len(clients) >= MAX_CLIENTS:
            await send(writer, {"type": "ERROR", "reason": "server plin"})
            return

        name = wanted
        clients[name] = (writer, pubkey)
        storage.set_key(name, pubkey)
        await send(writer, {"type": "OK"})
        log.info("REGISTER %s", name)

        # livreaza mesajele primite cat timp era offline
        for item in storage.pending(name):
            await send(
                writer,
                {"type": "MSG", "from": item["from"], "ciphertext": item["ciphertext"], "offline": True},
            )
        storage.clear(name)

        while True:
            msg = await asyncio.wait_for(unpack(reader), IDLE_TIMEOUT)
            if not limiter.allow():
                log.info("FLOOD %s deconectat", name)
                await send(writer, {"type": "ERROR", "reason": "prea multe mesaje"})
                break
            kind = msg.get("type")
            if kind == "LIST":
                await send(writer, {"type": "USERS", "users": sorted(clients)})
            elif kind == "GET_KEY":
                target = msg.get("name")
                pub = storage.get_key(target) if isinstance(target, str) else None
                if pub is None:
                    await send(writer, {"type": "ERROR", "reason": "utilizator necunoscut"})
                else:
                    await send(writer, {"type": "KEY", "name": target, "pubkey": pub})
            elif kind == "MSG":
                to = msg.get("to")
                ciphertext = msg.get("ciphertext")
                if not isinstance(to, str) or not valid_ciphertext(ciphertext):
                    await send(writer, {"type": "ERROR", "reason": "mesaj invalid sau prea lung"})
                    continue
                dest = clients.get(to)
                if dest is not None:
                    try:
                        await send(dest[0], {"type": "MSG", "from": name, "ciphertext": ciphertext})
                        log.info("MSG %s -> %s len=%d", name, to, len(ciphertext))
                        continue
                    except (ConnectionError, TimeoutError):
                        pass
                if storage.get_key(to) is None:
                    await send(writer, {"type": "ERROR", "reason": "utilizator necunoscut"})
                elif storage.enqueue(to, {"from": name, "ciphertext": ciphertext}):
                    log.info("QUEUE %s -> %s len=%d", name, to, len(ciphertext))
                    await send(writer, {"type": "QUEUED", "to": to})
                else:
                    await send(writer, {"type": "ERROR", "reason": "cutia postala e plina"})
            elif kind == "JOIN":
                room = str(msg.get("room", ""))
                if not NAME_RE.fullmatch(room):
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
                    if not isinstance(to, str) or not valid_ciphertext(ciphertext):
                        continue
                    if to == name or to not in members or to not in clients:
                        continue
                    try:
                        await send(
                            clients[to][0],
                            {"type": "GROUP_MSG", "room": room, "from": name, "ciphertext": ciphertext},
                        )
                        delivered += 1
                    except (ConnectionError, TimeoutError):
                        pass
                log.info("GROUP_MSG %s in %s catre %d membri", name, room, delivered)
            else:
                await send(writer, {"type": "ERROR", "reason": "tip necunoscut"})
    except TimeoutError:
        log.info("TIMEOUT %s", name)
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