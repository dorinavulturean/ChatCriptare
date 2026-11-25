import base64
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