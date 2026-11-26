import json
import os
from pathlib import Path

MAX_QUEUE = 100  # mesaje maxime in cutia unui utilizator


class Storage:
    """Chei publice si mesaje offline. path=None inseamna doar in memorie (pentru teste)."""

    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.keys = {}
        self.queue = {}
        if self.path is not None and self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.keys = data.get("keys", {})
                self.queue = data.get("queue", {})
            except ValueError:
                pass

    def _save(self):
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"keys": self.keys, "queue": self.queue}), encoding="utf-8")
        os.replace(tmp, self.path)

    def set_key(self, name, pubkey):
        self.keys[name] = pubkey
        self._save()

    def get_key(self, name):
        return self.keys.get(name)

    def enqueue(self, to, item):
        box = self.queue.setdefault(to, [])
        if len(box) >= MAX_QUEUE:
            return False
        box.append(item)
        self._save()
        return True

    def pending(self, name):
        return list(self.queue.get(name, []))

    def clear(self, name):
        if self.queue.pop(name, None) is not None:
            self._save()