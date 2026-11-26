# Postmortem

## Rezumat

Am construit un chat in terminal cu criptare end-to-end: server care doar retransmite, chei X25519, amprenta si avertisment la schimbarea cheii, chat de grup, mesaje offline, forward secrecy si protectii pentru server, cu Docker, CI si teste. Am inceput in saptamana 8 din 10, deci am avut aproximativ doua saptamani. Produsul e complet pentru nota 10, cu limitarile din `docs/design.md`.

## Ce a mers bine

- **Proiectarea inainte de cod.** Am stabilit de la inceput protocolul (cadre, tipuri de mesaje) si criptarea, deci grupul, mesajele offline si forward secrecy s-au adaugat peste ele fara sa rescriem totul.
- **Fluxul cu Pull Request, review si CI.** `ruff` si `pytest` ne-au prins greseli inainte sa ajunga pe `main` (un import lipsa, importuri duplicate, avertismente de stil).
- **Teste pentru ce conteaza.** Mesajul modificat e respins, un impostor nu poate anunta o cheie, un mesaj vechi nu mai poate fi citit dupa rotiri, iar un client care face flood e deconectat.
- **Biblioteca in loc de criptografie scrisa de noi.** PyNaCl ne-a lasat sa ne concentram pe protocol.
- **Dovada vizuala.** Captura Wireshark si logurile serverului arata ca textul mesajelor nu apare nicaieri.

## Ce nu a mers

- **Mediul de lucru ne-a luat timp:** discul C: aproape plin a blocat actualizarea WSL si pornirea motorului Docker; a trebuit sa facem loc si sa mutam distributii WSL pe alt disc.
- **Greseli de Git:** lipsa unui `.gitignore` la inceput (Visual Studio a incercat sa adauge `.vs/`), un conflict la `common/crypto.py` pentru ca doua versiuni ale fisierului au fost create in paralel, un `index.lock` ramas de la o operatie intrerupta, un fisier de captura blocat de Wireshark la schimbarea branch-ului, un fisier numit gresit (`doker-compose.yml`).
- **Modificari facute pe bucati** in fisiere mari (importuri duplicate, un `finally` cu liniile gresite). Au costat mai mult decat inlocuirea fisierului intreg.
- **Instructiuni invechite sau incomplete primite de la AI** (vezi sectiunea din README), care ne-au costat cateva ocolisuri.
- **Documentatia a ramas pe la sfarsit.** Am avut putin timp pentru ea si pentru bug bounty.
- **Am inceput tarziu**, deci forward secrecy a venit ultima si a fost facuta sub presiunea timpului.

## Ce am invatat

- `git pull` pe `main` **inainte** de fiecare branch nou, ca doi oameni sa nu creeze acelasi fisier din versiuni diferite.
- Fiecare persoana are propriile fisiere; nu lucram amandoi in acelasi fisier.
- Rulam `ruff check .` si `pytest` local inainte de push, ca sa nu descoperim erorile abia in CI.
- Pentru fisiere mari e mai sigur un fisier complet decat fragmente de lipit.
- Un `.gitignore` corect trebuie sa existe din primul commit, ca sa nu ajunga niciodata pe Git chei sau fisiere locale.
- Criptografia nu e doar alegerea algoritmilor, ci si a modului in care ii compui: autentificarea cheilor (amprenta, TOFU) conteaza la fel de mult ca criptarea.
- Un demo de atac trebuie rulat si verificat in log; primul nostru script de flood nu demonstra nimic.
- Un AI e util la explicat si la schelet, dar trebuie verificat: am rulat tot codul si am citit fiecare linie.

## Ce am face diferit

- Am incepe documentatia (README, design) odata cu codul, nu la final.
- Am configura din prima zi `.gitignore`, ruff si CI.
- Am sta de vorba cu profesorul din prima saptamana despre bug bounty, GitHub Classroom si demo-urile pierdute.
- Am proiecta de la inceput sesiunile efemere ca sa aiba forward secrecy si pentru grup si pentru mesajele offline.
- Am adauga TLS pe conexiunea client-server, inregistrare autentificata si un contor de mesaje (protectie la reluare).
- Am adauga keepalive si persistenta sesiunilor efemere dupa restartul clientului.
- Am face o rulare completa a demo-ului pe un calculator curat, nu doar pe cele ale noastre.

## Ce a ramas nefacut

- Forward secrecy pentru grup si mesaje offline.
- Autentificarea inregistrarii.
- Protectie la reluare si ordonarea mesajelor.
- TLS pe conexiune.

Detalii in `docs/design.md` (sectiunea Limitari) si `docs/hardening.md`.