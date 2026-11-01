from aegis.ingest.hashing import hash_bytes, hash_file
from aegis.static.entropy import shannon_entropy, byte_histogram


def test_known_hashes():
    h = hash_bytes(b"abc")
    assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert h["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert h["size"] == 3


def test_hash_file_matches_bytes(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello" * 100000)
    assert hash_file(p) == hash_bytes(b"hello" * 100000)


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"A" * 100) == 0
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_histogram_normalized():
    assert abs(sum(byte_histogram(b"abcd")) - 1.0) < 1e-9
