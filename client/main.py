import asyncio
import sys
import threading

from nacl.exceptions import CryptoError

from client.keystore import load_or_create
from common.crypto import decrypt, encrypt, fingerprint, pub_from_str, pub_to_str
from common.protocol import pack, unpack

HOST = "localhost"
PORT = 9000

HELP = "Comenzi: /list, /msg <nume> <text>, /fingerprint, /quit"


class Client:
    def __init__(self, name, private, reader, writer):
        self.name = name
        self.private = private
        self.reader = reader
        self.writer = writer
        self.keys = {}  # nume -> cheie publica
        self.pending = {}  # nume -> Future (cerere GET_KEY in curs)
        self.tasks = set()

    async def send(self, msg):
        self.writer.write(pack(msg))
        await self.writer.drain()

    async def get_key(self, name):
        """Intoarce cheia publica a unui utilizator (din cache sau de la server)."""
        if name in self.keys:
            return self.keys[name]
        fut = asyncio.get_running_loop().create_future()
        self.pending[name] = fut
        await self.send({"type": "GET_KEY", "name": name})
        try:
            return await asyncio.wait_for(fut, 3)
        except TimeoutError:
            return None
        finally:
            self.pending.pop(name, None)

    async def show_message(self, msg):
        sender = msg.get("from", "?")
        key = await self.get_key(sender)
        if key is None:
            print(f"[{sender}] (nu am cheia expeditorului)")
            return
        try:
            text = decrypt(msg.get("ciphertext", ""), self.private, key)
        except (CryptoError, ValueError):
            print(f"[{sender}] (mesaj invalid sau modificat, respins)")
            return
        print(f"[{sender}] {text}")

    async def receive_loop(self):
        try:
            while True:
                msg = await unpack(self.reader)
                kind = msg.get("type")
                if kind == "KEY":
                    fut = self.pending.get(msg.get("name"))
                    try:
                        key = pub_from_str(msg.get("pubkey", ""))
                    except ValueError:
                        key = None
                    if key is not None:
                        self.keys[msg["name"]] = key
                    if fut is not None and not fut.done():
                        fut.set_result(key)
                elif kind == "MSG":
                    task = asyncio.create_task(self.show_message(msg))
                    self.tasks.add(task)
                    task.add_done_callback(self.tasks.discard)
                elif kind == "USERS":
                    print("[sistem] online:", ", ".join(msg.get("users", [])))
                elif kind == "ERROR":
                    reason = msg.get("reason", "")
                    if self.pending and reason == "utilizator necunoscut":
                        fut = next(iter(self.pending.values()))
                        if not fut.done():
                            fut.set_result(None)
                    else:
                        print("[eroare]", reason)
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            print("[sistem] conexiune inchisa")

    async def send_private(self, to, text):
        key = await self.get_key(to)
        if key is None:
            print("[sistem] utilizator necunoscut sau offline")
            return
        ciphertext = encrypt(text, self.private, key)
        await self.send({"type": "MSG", "to": to, "ciphertext": ciphertext})
        print(f"[tu -> {to}] {text}")

    async def handle_line(self, line):
        """Intoarce False cand utilizatorul vrea sa iasa."""
        if not line:
            return True
        if line == "/quit":
            return False
        if line == "/list":
            await self.send({"type": "LIST"})
        elif line == "/fingerprint":
            print("[sistem] amprenta ta:", fingerprint(self.private.public_key))
        elif line.startswith("/msg "):
            parts = line.split(" ", 2)
            if len(parts) < 3 or not parts[2].strip():
                print("Folosire: /msg <nume> <text>")
            else:
                await self.send_private(parts[1], parts[2])
        else:
            print(HELP)
        return True


def start_stdin_thread(loop, queue):
    """Citeste tastatura intr-un thread separat, ca sa nu blocheze asyncio."""

    def reader():
        while True:
            line = sys.stdin.readline()
            if not line:
                loop.call_soon_threadsafe(queue.put_nowait, None)
                return
            loop.call_soon_threadsafe(queue.put_nowait, line.rstrip("\n"))

    threading.Thread(target=reader, daemon=True).start()


async def main():
    name = sys.argv[1] if len(sys.argv) > 1 else input("Nume: ").strip()
    host = sys.argv[2] if len(sys.argv) > 2 else HOST

    try:
        private = load_or_create(name)
    except ValueError:
        print("Nume invalid (litere, cifre, _ si -, maxim 32 caractere)")
        return

    reader, writer = await asyncio.open_connection(host, PORT)
    writer.write(
        pack({"type": "REGISTER", "name": name, "pubkey": pub_to_str(private.public_key)})
    )
    await writer.drain()
    reply = await unpack(reader)
    if reply.get("type") != "OK":
        print("[eroare]", reply.get("reason"))
        writer.close()
        return

    print("[sistem] conectat ca", name)
    print("[sistem] amprenta ta:", fingerprint(private.public_key))
    print(HELP)

    client = Client(name, private, reader, writer)
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue()
    start_stdin_thread(loop, queue)
    receiver = asyncio.create_task(client.receive_loop())

    try:
        while not receiver.done():
            line_task = asyncio.create_task(queue.get())
            done, _ = await asyncio.wait(
                {line_task, receiver}, return_when=asyncio.FIRST_COMPLETED
            )
            if line_task not in done:
                line_task.cancel()
                break
            line = line_task.result()
            if line is None or not await client.handle_line(line.strip()):
                break
    finally:
        receiver.cancel()
        writer.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass