import base64
import json
import re
from pathlib import Path

from nacl.public import PrivateKey

DEFAULT_DIR = Path.home() / ".e2echat"


def load_or_create(name, base_dir=None):
    """Incarca cheia privata a utilizatorului sau o creeaza la prima rulare."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name):
        raise ValueError("nume invalid")

    folder = Path(base_dir or DEFAULT_DIR) / name
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "private.key"

    if path.exists():
        return PrivateKey(base64.b64decode(path.read_text().strip()))

    private = PrivateKey.generate()
    path.write_text(base64.b64encode(bytes(private)).decode("ascii"))
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return private

def _known_path(name, base_dir=None):
    return Path(base_dir or DEFAULT_DIR) / name / "known_keys.json"


def _load_known(name, base_dir=None):
    path = _known_path(name, base_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except ValueError:
        return {}


def _save_known(name, known, base_dir=None):
    path = _known_path(name, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(known, indent=2))


def check_known(name, peer, pubkey_str, base_dir=None):
    """Compara cheia primita cu cea salvata. Intoarce 'new', 'same' sau 'changed'.

    La prima intalnire ('new') cheia se salveaza. La 'changed' NU se modifica nimic.
    """
    known = _load_known(name, base_dir)
    old = known.get(peer)
    if old is None:
        known[peer] = pubkey_str
        _save_known(name, known, base_dir)
        return "new"
    return "same" if old == pubkey_str else "changed"


def trust_key(name, peer, pubkey_str, base_dir=None):
    """Acceptarea explicita a unei chei noi (dupa verificarea amprentei)."""
    known = _load_known(name, base_dir)
    known[peer] = pubkey_str
    _save_known(name, known, base_dir)