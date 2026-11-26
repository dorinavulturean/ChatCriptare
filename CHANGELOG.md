# Changelog

Format dupa [Keep a Changelog](https://keepachangelog.com/), versionare [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Structura proiectului, `Dockerfile`, `docker-compose.yml` (`docker compose up --build`) si CI cu GitHub Actions (`ruff` si `pytest` la fiecare Pull Request).
- Cadre pentru mesaje (4 bytes cu lungimea, apoi JSON), cu limita de 64 KB.
- Server `asyncio`: inregistrare, lista de utilizatori, cereri de chei publice, retransmitere de mesaje.
- Chei de identitate X25519 pentru fiecare utilizator (PyNaCl), salvate in `~/.e2echat/<nume>/`.
- Criptare si autentificare a mesajelor cu `Box` (X25519 + XSalsa20-Poly1305); mesajele modificate sunt respinse.
- Client de terminal: `/list`, `/msg`, `/fingerprint`, `/quit`.
- Dovada MVP: captura Wireshark si loguri de server care arata doar ciphertext (`docs/mvp-dovada.md`).
- Amprenta cheii, memorarea cheilor la prima intalnire (TOFU) si avertisment cand cheia cuiva se schimba, cu `/trust`.
- Chat de grup: camere (`/join`, `/leave`, `/members`), `/group`, mesaj criptat separat pentru fiecare membru.
- Mesaje offline: cutie postala persistenta in `data/store.json`, livrare la conectare, doar ciphertext.
- Hardening: limitare de rata, timeout-uri, limite de dimensiune, validari, cel mult 100 de clienti si 100 de mesaje offline pe utilizator; script de demonstratie `tools/flood.py`.
- Forward secrecy pentru mesajele 1-la-1 intre utilizatori online: chei efemere autentificate cu cheile de identitate, rotite automat si cu `/rotate`; `/session` pentru inspectie.
- Documentatie: `README.md`, `docs/design.md`, `docs/hardening.md`, `docs/postmortem.md`.

### Known limitations
- Mesajele de grup si cele offline nu au forward secrecy.
- Inregistrarea nu e autentificata; fara TLS; fara protectie la reluare. Detalii in `docs/design.md`.