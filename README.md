# Chat criptat end-to-end

Proiect RC & Securitate 2026, nivel Avansat. Chat in terminal, scris in Python, in care **serverul doar retransmite mesaje criptate si nu are cum sa le citeasca**.

## Ce face

| Functie | Cum |
|---|---|
| Mesaje 1-la-1 criptate end-to-end | X25519 + XSalsa20-Poly1305 (PyNaCl, `Box`) |
| Protectie la man-in-the-middle | Amprenta cheii (SHA-256) si avertisment cand cheia cuiva se schimba |
| Chat de grup | Mesajul e criptat separat pentru fiecare membru |
| Mesaje offline | Serverul pastreaza doar ciphertext, livrat la conectare |
| Forward secrecy | Chei efemere rotite, pentru mesaje 1-la-1 intre utilizatori online |
| Server rezistent | Anti-flood, timeout-uri, limite de dimensiune |

## Cerinte

- Docker Desktop (pentru server)
- Python 3.12 sau mai nou (pentru clienti si teste)

## Cum rulezi

Din radacina proiectului:

```
pip install -r requirements.txt
docker compose up --build
```

Serverul asculta pe portul 9000 si ramane pornit. Logurile se vad in terminal sau in Docker Desktop (Containers, apoi proiectul).

In cate un terminal nou, pentru fiecare utilizator:

```
python -m client.main ana 127.0.0.1
python -m client.main bogdan 127.0.0.1
```

Primul argument e numele (litere, cifre, `_`, `-`, maxim 32 de caractere), al doilea e adresa serverului (implicit `localhost`). Clientii se ruleaza cu `python -m ...`, din radacina proiectului.

La prima rulare, clientul isi genereaza cheile in `~/.e2echat/<nume>/` (pe Windows `C:\Users\<utilizator>\.e2echat\<nume>\`). Cheia privata nu paraseste calculatorul. Serverul isi salveaza datele in `data/store.json` (folderul `data/` e montat ca volum Docker, deci supravietuieste repornirii).

Oprire: `Ctrl+C` in terminalul serverului, apoi `docker compose down`.

## Comenzi in client

| Comanda | Ce face |
|---|---|
| `/list` | Arata cine e online |
| `/msg <nume> <text>` | Mesaj privat, criptat end-to-end |
| `/fingerprint` | Amprenta ta |
| `/fingerprint <nume>` | Amprenta unui utilizator (o compari cu el pe alt canal) |
| `/trust <nume>` | Accepta cheia noua a unui utilizator, dupa ce ai verificat amprenta |
| `/join <camera>`, `/leave`, `/members` | Camere de grup |
| `/group <text>` | Mesaj in camera curenta |
| `/rotate <nume>` | Roteste manual cheile efemere cu un utilizator |
| `/session <nume>` | Arata identificatorii cheilor efemere curente |
| `/quit` | Iesire |

Un mesaj afisat ca `[fs][ana] salut` a venit cu forward secrecy. `[offline]` inseamna ca a fost primit din cutia postala.

## Demo scurt

1. Porneste serverul si doi clienti (`ana`, `bogdan`).
2. Ana: `/msg bogdan salut`. Bogdan vede `[fs][ana] salut`.
3. In logul serverului apar doar linii ca `MSG ana -> bogdan len=...`, niciodata textul. Dovada: `docs/mvp-dovada.md` si `docs/captures/`.
4. Ana: `/session bogdan`, apoi `/rotate bogdan`, apoi din nou `/session bogdan`. Identificatorii s-au schimbat.
5. Bogdan iese. Ana scrie `/msg bogdan test`: mesajul merge in cutia postala si e livrat cand Bogdan revine.

## Teste si CI

```
pytest
ruff check .
```

GitHub Actions (`.github/workflows/ci.yml`) ruleaza `ruff` si `pytest` la fiecare Pull Request. Lucram pe branch-uri, fiecare modificare trece printr-un Pull Request cu review de la celalalt coleg si CI verde, nimic nu se scrie direct pe `main`.

## Structura

```
common/
  protocol.py     cadre (4 bytes lungime + JSON)
  crypto.py       chei, amprenta, Box, sesiuni efemere (forward secrecy)
server/
  main.py         serverul asyncio
  storage.py      chei publice si mesaje offline (data/store.json)
  limits.py       limitare de rata (anti-flood)
client/
  main.py         clientul de terminal
  keystore.py     cheia privata si cheile cunoscute (TOFU)
tests/            teste pytest
tools/flood.py    demo de atac (flood) pentru server
docs/             design, hardening, dovada MVP, postmortem
```

## Documentatie

- `docs/design.md`: arhitectura, protocolul, criptografia, model de amenintare
- `docs/hardening.md`: ce protejeaza serverul si ce limitari raman
- `docs/mvp-dovada.md`: dovada ca serverul nu vede textul mesajelor
- `docs/postmortem.md`: ce a mers, ce nu, ce am invatat
- `CHANGELOG.md`

## Securitate pe scurt

Serverul vede: cine e online, cine scrie cui, cand, cat de lung e mesajul, numele camerelor si cheile publice. **Nu vede continutul mesajelor.** Mesajele modificate pe drum sunt respinse, iar schimbarea cheii cuiva produce un avertisment. Limitarile cunoscute (inregistrare neautentificata, fara TLS, forward secrecy doar pentru mesaje 1-la-1 intre utilizatori online etc.) sunt in `docs/design.md` si `docs/hardening.md`.

## Cum am folosit AI

Am folosit versiunea gratuita a lui Claude, in chat.

**La ce ne-a ajutat**
- Sa intelegem protocolul si biblioteca: ce fac X25519, `Box`, nonce-ul, autentificarea cu Poly1305, ideea de amprenta si de forward secrecy.
- Schelet de cod pentru server, client, stocare si teste, pe care l-am citit, rulat si adaptat.
- Depanare: Docker si WSL (disc plin), Git (conflicte, fisiere blocate), erori de `ruff` si `pytest`.
- Idei de hardening (anti-flood, timeout-uri, limite de dimensiune) si de teste.
- Structura documentatiei.

**Unde a gresit**
- A omis un import (`PrivateKey` in `client/keystore.py`): testele au picat cu `NameError` si au fost prinse de `pytest` si `ruff`.
- A dat instructiuni pentru interfata veche de GitHub (branch protection), cand noi aveam interfata cu Rulesets, si o indicatie veche despre instalarea Npcap.
- Primul script de demo pentru flood se inchidea inainte sa citeasca raspunsul serverului, deci linia `FLOOD` nu aparea in log. Am descoperit asta rulandu-l si am cerut o varianta corectata.
- A explicat cateva modificari ca fragmente de lipit "undeva" in fisiere mari (blocurile `else`, `finally`), ceea ce a dus la importuri duplicate si la indentari gresite. Am trecut la fisiere complete.
- `ruff` (TRY004) sugera `TypeError` in loc de `ValueError`; schimbarea ar fi stricat tratarea erorilor din server. Am ales sa pastram `ValueError` si sa marcam linia cu `# noqa`.

**Ce am verificat noi**
- Am rulat testele si `ruff` la fiecare pas, in CI si local.
- Am testat manual cu mai multi clienti si am facut capturi Wireshark.
- Am citit codul si putem explica fiecare linie.

Nu am dat AI-ului parole, chei private sau date reale. Cheile din demo sunt generate doar pentru test.