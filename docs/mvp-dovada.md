# Dovada MVP: serverul nu poate citi mesajele

## Ce am testat
Doi clienti (ana, bogdan) se conecteaza la server si isi trimit mesaje criptate cu X25519 + XSalsa20-Poly1305.

## Ce vede serverul
- Cheile **publice** ale utilizatorilor (nu au nevoie sa fie secrete).
- Pentru fiecare mesaj: expeditor, destinatar si **ciphertext** (vezi `captures/server-log.txt`).

## Ce vede cineva care asculta reteaua
Captura Wireshark (`captures/captura-mvp.pcapng`, `captures/wireshark-tcp-stream.png`) arata doar ciphertext in base64. Textul mesajului nu apare in niciun pachet.

## Ce NU ascundem
Numele utilizatorilor, cine vorbeste cu cine si lungimea mesajelor sunt vizibile serverului (metadate).

## Ce garanteaza criptarea
- Confidentialitate: doar destinatarul poate decripta.
- Integritate: un mesaj modificat pe drum e respins (vezi `tests/test_crypto_box.py`).