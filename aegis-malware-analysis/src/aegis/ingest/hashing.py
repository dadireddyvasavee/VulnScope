"""File hashing. Reads bytes only - never executes anything."""
import hashlib
from pathlib import Path

CHUNK = 1 << 16


def hash_bytes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def hash_file(path: str | Path) -> dict:
    h = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            size += len(chunk)
            for x in h.values():
                x.update(chunk)
    out = {k: v.hexdigest() for k, v in h.items()}
    out["size"] = size
    return out
