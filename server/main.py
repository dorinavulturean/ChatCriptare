import asyncio
import logging

from common.protocol import pack, unpack

HOST = "0.0.0.0"
PORT = 9000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("server")

# nume -> (writer, cheie publica)
clients = {}


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
            elif kind == "MSG":
                dest = clients.get(msg.get("to"))
                if dest is None:
                    await send(writer, {"type": "ERROR", "reason": "utilizator offline"})
                    continue
                ciphertext = msg.get("ciphertext", "")
                log.info("MSG %s -> %s len=%d", name, msg["to"], len(ciphertext))
                await send(dest[0], {"type": "MSG", "from": name, "ciphertext": ciphertext})
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
        writer.close()


async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    log.info("server pornit pe %s:%d", HOST, PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())