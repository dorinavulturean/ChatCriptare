"""Demo: trimite prea multe mesaje, serverul trebuie sa ne deconecteze."""
import json
import socket
import struct
import time


def send(sock, msg):
    data = json.dumps(msg).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


sock = socket.create_connection(("127.0.0.1", 9000))
send(sock, {"type": "REGISTER", "name": "atacator", "pubkey": "k"})
time.sleep(0.5)

sent = 0
try:
    for _ in range(200):
        send(sock, {"type": "LIST"})
        sent += 1
except ConnectionError:
    print("serverul m-a deconectat dupa", sent, "mesaje")

time.sleep(1)
sock.settimeout(2)
received = b""
try:
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            print("conexiune inchisa de server")
            break
        received += chunk
except (TimeoutError, ConnectionError):
    pass

print("raspuns primit:", b"prea multe mesaje" in received)
sock.close()