import asyncio
import sys
import threading

from nacl.exceptions import CryptoError

from client.keystore import check_known, load_or_create, trust_key
from common.crypto import decrypt, encrypt, fingerprint, pub_from_str, pub_to_str
from common.protocol import pack, unpack

HOST = "localhost"
PORT = 9000

HELP = (
    "Comenzi: /list, /msg <nume> <text>, /join <camera>, /leave, /members, "
    "/group <text>, /fingerprint [nume], /trust <nume>, /quit"
)


class Client:
    def __init__(self, name, private, reader, writer):
        self.name = name
        self.private = private
        self.reader = reader
        self.writer = writer
        self.keys = {}  # nume -> cheie publica
        self.pending = {}  # nume -> Future (cerere GET_KEY in curs)
        self.tasks = set()
        self.untrusted = {}  # nume -> cheie noua, in asteptare de acceptare
        self.room = None  # camera curenta
        self.members_waiter = None  # Future pentru raspunsul MEMBERS

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
        room = msg.get("room")
        tag = f"[{room}]" if room else ""
        if msg.get("offline"):
            tag = "[offline]" + tag
        key = await self.get_key(sender)
        if key is None:
            print(f"{tag}[{sender}] (nu am o cheie de incredere pentru expeditor)")
            return
        try:
            text = decrypt(msg.get("ciphertext", ""), self.private, key)
        except (CryptoError, ValueError):
            print(f"{tag}[{sender}] (mesaj invalid sau modificat, respins)")
            return
        print(f"{tag}[{sender}] {text}")

    async def receive_loop(self):
        try:
            while True:
                msg = await unpack(self.reader)
                kind = msg.get("type")
                if kind == "KEY":
                    peer = msg.get("name")
                    if not peer:
                        continue
                    fut = self.pending.get(peer)
                    try:
                        key = pub_from_str(msg.get("pubkey", ""))
                    except ValueError:
                        key = None
                    if key is not None:
                        status = check_known(self.name, peer, msg["pubkey"])
                        if status == "changed":
                            self.untrusted[peer] = msg["pubkey"]
                            print(f"[ATENTIE] Cheia lui {peer} S-A SCHIMBAT!")
                            print("[ATENTIE] Poate fi un atacator. Amprenta noua:", fingerprint(key))
                            print(f"[ATENTIE] Verific-o cu {peer}. Daca e corecta: /trust {peer}")
                            key = None
                        else:
                            self.keys[peer] = key
                            if status == "new":
                                print(f"[sistem] cheie noua pentru {peer}, amprenta:", fingerprint(key))
                                print("[sistem] verific-o cu el pe alt canal")
                    if fut is not None and not fut.done():
                        fut.set_result(key)
                elif kind in ("MSG", "GROUP_MSG"):
                    task = asyncio.create_task(self.show_message(msg))
                    self.tasks.add(task)
                    task.add_done_callback(self.tasks.discard)
                elif kind == "USERS":
                    print("[sistem] online:", ", ".join(msg.get("users", [])))
                elif kind == "JOINED":
                    self.room = msg.get("room")
                    print(f"[sistem] ai intrat in {self.room}, membri:", ", ".join(msg.get("members", [])))
                elif kind == "LEFT":
                    if self.room == msg.get("room"):
                        self.room = None
                    print("[sistem] ai iesit din", msg.get("room"))
                elif kind == "MEMBERS":
                    waiter = self.members_waiter
                    if waiter is not None and not waiter.done():
                        waiter.set_result(msg.get("members", []))
                elif kind == "QUEUED":
                    print(f"[sistem] {msg.get('to')} e offline, mesajul ajunge cand se conecteaza")
                elif kind == "ERROR":
                    reason = msg.get("reason", "")
                    if self.pending and reason == "utilizator necunoscut":
                        fut = next(iter(self.pending.values()))
                        if not fut.done():
                            fut.set_result(None)
                    elif self.members_waiter is not None and reason == "nu esti in camera":
                        if not self.members_waiter.done():
                            self.members_waiter.set_result(None)
                    else:
                        print("[eroare]", reason)
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            print("[sistem] conexiune inchisa")

    async def send_private(self, to, text):
        key = await self.get_key(to)
        if key is None:
            print("[sistem] utilizator necunoscut")
            return
        ciphertext = encrypt(text, self.private, key)
        await self.send({"type": "MSG", "to": to, "ciphertext": ciphertext})
        print(f"[tu -> {to}] {text}")

    async def get_members(self, room):
        fut = asyncio.get_running_loop().create_future()
        self.members_waiter = fut
        await self.send({"type": "MEMBERS", "room": room})
        try:
            return await asyncio.wait_for(fut, 3)
        except TimeoutError:
            return None
        finally:
            self.members_waiter = None

    async def send_group(self, text):
        if self.room is None:
            print("[sistem] nu esti intr-o camera, foloseste /join <camera>")
            return
        members = await self.get_members(self.room)
        if members is None:
            print("[sistem] nu pot obtine lista membrilor")
            return
        items = []
        for member in members:
            if member == self.name:
                continue
            key = await self.get_key(member)
            if key is None:
                print(f"[sistem] sar peste {member}: nu am o cheie de incredere")
                continue
            items.append({"to": member, "ciphertext": encrypt(text, self.private, key)})
        if not items:
            print("[sistem] nu e nimeni altcineva in camera")
            return
        await self.send({"type": "GROUP_MSG", "room": self.room, "messages": items})
        print(f"[tu -> {self.room}] {text}")

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
        elif line.startswith("/fingerprint "):
            peer = line.split(" ", 1)[1].strip()
            key = await self.get_key(peer)
            if key is None:
                print("[sistem] nu pot obtine o cheie de incredere pentru", peer)
            else:
                print(f"[sistem] amprenta lui {peer}:", fingerprint(key))
                print("[sistem] compar-o cu el pe alt canal (telefon, in persoana)")
        elif line.startswith("/trust "):
            peer = line.split(" ", 1)[1].strip()
            pub = self.untrusted.pop(peer, None)
            if pub is None:
                print("[sistem] nu am nicio cheie noua de acceptat pentru", peer)
            else:
                trust_key(self.name, peer, pub)
                self.keys[peer] = pub_from_str(pub)
                print(f"[sistem] cheie acceptata pentru {peer}, amprenta:", fingerprint(self.keys[peer]))
        elif line.startswith("/join "):
            await self.send({"type": "JOIN", "room": line.split(" ", 1)[1].strip()})
        elif line == "/leave":
            if self.room is None:
                print("[sistem] nu esti intr-o camera")
            else:
                await self.send({"type": "LEAVE", "room": self.room})
        elif line == "/members":
            if self.room is None:
                print("[sistem] nu esti intr-o camera")
            else:
                members = await self.get_members(self.room)
                print("[sistem] membri:", ", ".join(members or []))
        elif line.startswith("/group "):
            await self.send_group(line.split(" ", 1)[1])
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