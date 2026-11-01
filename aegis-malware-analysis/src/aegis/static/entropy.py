import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). >7.2 often indicates packing/encryption."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def byte_histogram(data: bytes, normalize: bool = True) -> list[float]:
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    if normalize and data:
        return [h / len(data) for h in hist]
    return [float(h) for h in hist]
