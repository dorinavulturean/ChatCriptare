# Hardening: ce protejeaza serverul

Lista de verificare pentru partea de securitate. Constantele sunt in `server/main.py`, `server/limits.py`, `common/protocol.py` si `client/main.py`.

## 1. Protectii implementate

| Atac / risc | Protectie | Valoare | Unde | Test |
|---|---|---|---|---|
| Flood de mesaje | Limitare de rata cu galeata de jetoane; peste limita clientul primeste eroare si e deconectat | 5 mesaje/s in medie, 10 deodata | `server/limits.py`, `server/main.py` | `test_flood_deconecteaza`, `tests/test_limits.py` |
| Conexiuni goale (Slowloris) | Timeout pana la primul mesaj (`REGISTER`) | 10 s | `server/main.py` | `test_register_timeout` |
| Conexiuni uitate | Timeout de inactivitate | 300 s | `server/main.py` | (verificat manual) |
| Client care nu citeste ce primeste | Timeout la trimitere | 5 s | `server/main.py` | (verificat manual) |
| Umplerea serverului | Numar maxim de clienti conectati | 100 | `server/main.py` | (verificat manual) |
| Mesaje uriase | Limita pe cadru; limita pe ciphertext; limita pe textul din client | 64 KB; 8192 caractere; 4000 bytes | `common/protocol.py`, `server/main.py`, `client/main.py` | `test_lungime_prea_mare`, `test_ciphertext_prea_lung` |
| JSON care nu e obiect | Respins la citire | | `common/protocol.py` | `test_json_nu_e_obiect` |
| Umplerea discului prin cutia offline | Maxim de mesaje pe utilizator | 100 | `server/storage.py` | `test_cutia_se_umple` |
| Nume si camere neasteptate | Validare cu expresie regulata | `[A-Za-z0-9_-]{1,32}` | `server/main.py` | `test_nume_duplicat` |
| Path traversal prin nume de utilizator (cheile din `~/.e2echat/<nume>`) | Numele e validat inainte sa devina folder | | `client/keystore.py` | `test_keystore_refuza_nume_periculos` |
| Mesaje de grup abuzive | Doar membrii pot trimite; maxim 50 de destinatari; doar catre membri | | `server/main.py` | `test_grup_nemembru_este_respins` |
| Mesaj modificat pe drum | Autentificare Poly1305 (`Box`) | | `common/crypto.py` | `test_mesaj_modificat_este_respins` |
| Inlocuirea cheii cuiva (MITM) | TOFU, amprenta, avertisment, `/trust` | | `client/keystore.py`, `client/main.py` | `test_cheie_schimbata_e_detectata` |
| Anunt efemer fals | Anuntul e criptat cu cheile de identitate; unul de la impostor e respins | | `common/crypto.py` | `test_anunt_de_la_impostor_este_respins` |
| Anunt efemer reluat | Un anunt deja vazut e ignorat | | `common/crypto.py` | `test_anunt_reluat_este_ignorat` |
| Anunturi efemere invechite | Nu se pun in cutia postala | | `server/main.py` | `test_anunt_efemer_nu_se_pune_in_coada` |
| Cheie privata ajunsa pe GitHub | `.gitignore` (`*.key`, `known_keys.json`, `data/*`); cheile stau in folderul utilizatorului, nu in proiect | | `.gitignore` | |
| Fisier de date corupt la oprire brusca | Scriere intr-un fisier temporar, apoi `os.replace` | | `server/storage.py` | `test_cheie_si_coada_persista` |

## 2. Cum se demonstreaza

**Flood:** cu serverul pornit (`docker compose up --build`), intr-un alt terminal:
```
python tools\flood.py
```
In logul serverului apare `FLOOD atacator deconectat`, iar scriptul afiseaza ca a primit eroarea `prea multe mesaje`.

**Timeout de inregistrare:** o conexiune care nu trimite nimic:
```
python -c "import socket,time; socket.create_connection(('127.0.0.1',9000)); time.sleep(30)"
```
Dupa 10 secunde, logul arata `TIMEOUT None`.

**Teste:** `pytest` ruleaza toate verificarile de mai sus.

## 3. Lista de verificare

- [x] Serverul nu are chei private si nu poate citi mesajele
- [x] Mesajele modificate sunt respinse
- [x] Schimbarea unei chei produce un avertisment
- [x] Limita de rata si deconectare la flood
- [x] Timeout-uri la citire si la trimitere
- [x] Limite de dimensiune (cadru, ciphertext, text, cutie postala, destinatari)
- [x] Validarea numelor si a tipului mesajelor
- [x] Cheile private si datele serverului nu ajung pe Git
- [x] Anunturile efemere sunt autentificate si nu se repeta
- [x] CI cu `ruff` si `pytest` la fiecare Pull Request
- [ ] TLS pe conexiunea client-server (ascunde metadatele de observatorii de retea)
- [ ] Inregistrare autentificata (un nume nu poate fi luat de altcineva)
- [ ] Protectie la reluare si ordonare a mesajelor (contor de mesaje)
- [ ] Keepalive pentru clientii inactivi
- [ ] Forward secrecy si pentru grup si pentru mesajele offline

Cele nebifate sunt limitari cunoscute, descrise in `docs/design.md`.

## 4. Bug bounty

Vulnerabilitatile raportate de alte echipe si ce am reparat:

| Raport | Gravitate | Ce am facut | PR |
|---|---|---|---|
| (se completeaza dupa bug bounty) | | | |

Vulnerabilitatile pe care le-am raportat noi altor echipe:

| Echipa / proiect | Descriere | Gravitate |
|---|---|---|
| (se completeaza dupa bug bounty) | | |