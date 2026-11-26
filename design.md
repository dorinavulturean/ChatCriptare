# Design: chat criptat end-to-end

## 1. Arhitectura

```
 Client (ana)            Server                   Client (bogdan)
 - cheie privata         - chei publice           - cheie privata
 - cripteaza si          - cutie postala offline  - cripteaza si
   decripteaza             (doar ciphertext)        decripteaza
 - cheile cunoscute      - camere (in memorie)    - cheile cunoscute
        |                       |                        |
        +---- TCP, JSON ------->+<------ TCP, JSON ------+
```

Principiul: **criptarea si decriptarea se fac doar in clienti**. Serverul e un poștas care duce plicuri sigilate: retransmite, pastreaza cheile publice si pune mesajele destinate utilizatorilor offline intr-o cutie postala. Nu are nicio cheie privata.

Alegeri:
- Python + `asyncio`: un singur proces gestioneaza mai multi clienti fara fire de executie.
- PyNaCl (libsodium): nu implementam noi primitive criptografice, doar le compunem.
- Serverul ruleaza in Docker (`docker compose up --build`), clientii pe calculator, fiecare in terminalul lui.

## 2. Transport: cadre

TCP e un sir de bytes fara granite intre mesaje, deci fiecare mesaj e trimis ca un **cadru**:

```
[4 bytes: lungimea, big-endian][continut: un obiect JSON, UTF-8]
```

- Receptorul citeste exact 4 bytes, apoi exact atatia bytes cat spune lungimea (`readexactly`).
- Lungimea se verifica **inainte** de citirea continutului. Maximul e 64 KB, ca sa nu se poata cere alocarea unor cantitati uriase de memorie.
- Continutul trebuie sa fie un obiect JSON; orice alt tip e respins.

Implementare: `common/protocol.py` (`pack`, `unpack`).

## 3. Mesaje (protocol)

Toate mesajele au campul `type`.

| Client trimite | Raspuns / efect |
|---|---|
| `REGISTER` (`name`, `pubkey`) | `OK` sau `ERROR` (nume invalid, nume deja folosit, server plin) |
| `LIST` | `USERS` (`users`) |
| `GET_KEY` (`name`) | `KEY` (`name`, `pubkey`) sau `ERROR` (`utilizator necunoscut`) |
| `MSG` (`to`, `ciphertext`) | Livrat ca `MSG` (`from`, `ciphertext`); daca destinatarul e offline: `QUEUED`; anunturile efemere offline: `ERROR` |
| `JOIN` (`room`) | `JOINED` (`room`, `members`) |
| `LEAVE` (`room`) | `LEFT` (`room`) |
| `MEMBERS` (`room`) | `MEMBERS` (`room`, `members`) |
| `GROUP_MSG` (`room`, `messages`: lista de `{to, ciphertext}`) | Fiecare membru primeste `GROUP_MSG` (`room`, `from`, `ciphertext`) |

Mesajele din cutia postala sunt livrate la conectare, dupa `OK`, ca `MSG` cu `offline: true`. Erorile vin ca `ERROR` (`reason`).

Prima cerere a unui client trebuie sa fie `REGISTER`; altfel conexiunea e inchisa.

## 4. Chei si identitate

- Fiecare utilizator are o pereche de chei **X25519** de identitate, generata la prima rulare. Cheia privata se salveaza in `~/.e2echat/<nume>/private.key` (base64, cu permisiuni restranse acolo unde sistemul de operare le suporta) si **nu paraseste calculatorul**. Numele folosit pentru folder e validat (`[A-Za-z0-9_-]{1,32}`), ca sa nu poata scrie in afara folderului (path traversal).
- La `REGISTER`, clientul trimite cheia publica. Serverul o pastreaza (si pe disc, ca sa putem trimite mesaje catre cineva offline) si o da celor care o cer prin `GET_KEY`.

### Incredere in chei: TOFU si amprenta

Un server malitios sau un atacator ar putea inlocui cheia lui Bogdan cu a lui. Aparare:

1. **TOFU (trust on first use):** prima cheie vazuta pentru un utilizator se salveaza in `~/.e2echat/<nume>/known_keys.json`.
2. **Amprenta:** SHA-256 din cheia publica, primele 32 de caractere hex, in 8 grupuri de 4 (`7F3A-91C2-...`). Doi utilizatori o compara pe alt canal (telefon, in persoana) cu `/fingerprint`.
3. **Schimbare detectata:** daca serverul da o cheie diferita de cea salvata, clientul afiseaza `[ATENTIE]`, **nu trimite si nu decripteaza** cu cheia noua si cere verificarea amprentei. Doar `/trust <nume>` o accepta.

Implementare: `common/crypto.py` (`fingerprint`), `client/keystore.py` (`check_known`, `trust_key`).

## 5. Criptarea mesajelor

Mod de baza (identitate): `Box(cheia_mea_privata, cheia_publica_a_destinatarului)` din PyNaCl:
- schimb de chei X25519 (Diffie-Hellman),
- criptare XSalsa20, autentificare Poly1305,
- nonce aleator de 24 de bytes, pus automat in fata ciphertext-ului.

Pe retea: `ciphertext = base64(nonce || date criptate)`.

Proprietati:
- **Confidentialitate:** doar destinatarul poate decripta.
- **Integritate:** orice byte modificat face decriptarea sa esueze (`CryptoError`), iar clientul respinge mesajul.
- **Autenticitate:** un `Box` valid dovedeste ca a fost creat de cineva care are cheia privata a expeditorului sau a destinatarului.
- Acelasi text da de fiecare data alt ciphertext (nonce aleator).

Testele: `tests/test_crypto_box.py`.

## 6. Chat de grup

- Serverul tine camerele (`camera -> membri`) **in memorie**. Un utilizator intra cu `JOIN` si iese cu `LEAVE`; camera dispare cand nu mai e nimeni, iar la deconectare utilizatorul e scos din toate camerele.
- La `/group text`, clientul cere lista membrilor si cripteaza mesajul **separat pentru fiecare membru** (*fan-out*), cu cheia lui. Trimite un `GROUP_MSG` cu o lista `{to, ciphertext}`.
- Serverul livreaza fiecaruia doar bucata lui. Accepta mesaje doar de la membri, cel mult 50 de destinatari, si doar catre membrii camerei.
- Serverul vede numele camerei si membrii (metadate), nu continutul.

Cost: N ciphertext-uri pentru N membri. Pentru camere mici e simplu si sigur; pentru camere mari ar trebui o schema cu chei de grup.

## 7. Mesaje offline

- Serverul tine chei publice si cutii postale in `data/store.json`. Scrierea se face intr-un fisier temporar urmat de `os.replace`, ca fisierul sa nu ramana corupt daca serverul se opreste la mijloc.
- Daca destinatarul e offline si cunoscut, mesajul (deja criptat de expeditor cu cheia lui) merge in cutie si expeditorul primeste `QUEUED`. La conectare, destinatarul primeste mesajele, iar cutia se goleste.
- Serverul nu poate citi mesajul nici cat sta in cutie.
- Cutia e limitata la 100 de mesaje per utilizator, ca sa nu se poata umple discul.
- Mesajele de grup nu se pun in coada.

## 8. Forward secrecy

**Problema.** Cu cheile de identitate, cine fura `private.key` poate decripta tot traficul inregistrat in trecut.

**Solutie (pentru mesaje 1-la-1 intre utilizatori online):** chei **efemere** X25519, tinute doar in memorie, rotite, iar cele vechi sunt sterse.

### Handshake

Doua mesaje `MSG` obisnuite, cu prefix in `ciphertext`:

```
Ana                          Server                      Bogdan
 |-- MSG eph1:<anunt A1> ------>|--------- MSG eph1 ------->|
 |                              |                           | decripteaza anuntul cu cheia de
 |                              |                           | identitate a Anei, retine A1
 |<-------- MSG eph2 -----------|<-- MSG eph2:<anunt B1> ---|
 | decripteaza anuntul, retine B1                           |
 |== MSG fs1:A1:B1:<ciphertext>  (efemera cu efemera) ======>|
```

- **Anuntul** e cheia publica efemera, criptata cu `Box` de identitate (`cheia de identitate a mea` + `cheia de identitate a ta`). Un atacator nu poate pune o cheie falsa: nu poate crea un `Box` valid.
- **Mesajele** se cripteaza apoi cu `Box(efemera_mea, efemera_ta)`. Formatul: `fs1:<id efemera expeditor>:<id efemera destinatar>:<base64>`, unde id-ul sunt primele 8 caractere hex din SHA-256 al cheii publice efemere.
- La cele doua capete exista cel mult 3 chei efemere (`KEEP = 3`): cea curenta si cateva vechi, pentru mesajele aflate pe drum in momentul unei rotiri. Cele mai vechi se elimina, iar odata eliminate, mesajele criptate cu ele nu mai pot fi citite de nimeni.
- **Rotire:** automat dupa 20 de mesaje (`ROTATE_AFTER`) sau manual cu `/rotate`.
- Un anunt deja vazut e ignorat (nu schimba cheia curenta si nu declanseaza un raspuns), deci un atacator nu poate forta rotiri sau reveniri la chei vechi prin repetarea unui anunt.
- Anunturile `eph1:` si `eph2:` **nu se pun niciodata in cutia postala**: ar ajunge invechite. Daca destinatarul e offline, serverul raspunde `ERROR`.

### Cand nu se aplica
Daca celalalt nu raspunde la handshake (offline sau fara sesiune), clientul trimite in modul de baza (cheia de identitate) si afiseaza `(fara forward secrecy: ...)`. Mesajele de grup si cele din cutia postala folosesc mereu modul de baza.

### Dovada
`tests/test_forward_secrecy.py`: dupa mai multe rotiri, un mesaj vechi **nu mai poate fi decriptat**, nici macar de cineva care are cheile de identitate ale ambilor utilizatori si starea curenta. Un alt test arata contrastul: in modul de baza, cheia de identitate citeste mesajul.

## 9. Model de amenintare

| Cine | Ce poate | Ce il opreste |
|---|---|---|
| Observator pe retea | Vede cadre, adrese, lungimi, cine vorbeste cu cine | Continutul e criptat. Metadatele raman vizibile (nu avem TLS pe canalul client-server) |
| Server curios | Vede metadate, chei publice, ciphertext | Nu are chei private. Poate incerca sa dea o cheie falsa: detectat de TOFU si amprenta |
| Atacator man-in-the-middle | Inlocuieste o cheie publica | Avertisment la schimbare (`[ATENTIE]`), `/trust` doar dupa verificarea amprentei |
| Atacator care modifica un mesaj | Schimba bytes pe drum | Poly1305: mesajul e respins |
| Atacator care fura cheia de identitate | Citeste mesajele din modul de baza (grup, offline) si se poate da drept utilizator de acum inainte | Mesajele cu forward secrecy din trecut raman ilizibile |
| Client rau intentionat | Flood, conexiuni goale, mesaje uriase | Limite si timeout-uri (`docs/hardening.md`) |

## 10. Limitari cunoscute

- **Inregistrarea nu e autentificata.** Oricine poate inregistra numele unui utilizator offline, cu alta cheie. Criptarea ramane sigura (clientii avertizeaza la schimbarea cheii), dar atacatorul primeste mesajele din cutia numelui furat (inca criptate cu cheia veche, deci ilizibile pentru el) si cutia victimei se goleste.
- **Fara TLS** pe conexiunea client-server: un observator de retea vede metadatele.
- **Metadate vizibile serverului:** cine vorbeste cu cine, cand, cat de lung, numele camerelor.
- **Fara protectie la reluare (replay) si fara ordonare** a mesajelor: nu avem contor de mesaje, deci un mesaj inregistrat ar putea fi retrimis.
- **Forward secrecy partiala:** doar mesajele 1-la-1 intre utilizatori online. Sesiunile efemere sunt doar in memorie: dupa restartul unui client se pierd, iar clientul care primeste un mesaj `fs1` fara sesiune cere una noua, dar mesajul trimis intre timp se pierde.
- Rotirea se face dupa numar de mesaje, nu dupa timp.
- Cheia efemera veche e scoasa din dictionar, dar Python nu garanteaza stergerea fizica din RAM.
- **Amprenta se compara manual**, pe alt canal; verificarea ramane la utilizator.
- Camerele de grup exista doar cat timp au membri conectati si nu au chei de grup.
- Un client inactiv 300 de secunde e deconectat (nu avem keepalive).
- Protocolul e propriu si neauditat; pentru un produs real s-ar folosi Signal (X3DH + Double Ratchet) sau Noise.