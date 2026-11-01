from aegis.static.pe_parser import parse_pe
from tests.fixtures.make_pe import build_pe, BENIGN_IMPORTS, INJECTOR_IMPORTS


def test_non_pe_rejected():
    r = parse_pe(b"not a pe file at all")
    assert not r.is_pe and "MZ" in r.error


def test_truncated_pe_handled():
    r = parse_pe(b"MZ" + b"\x00" * 10)
    assert not r.is_pe


def test_benign_pe_parsed():
    r = parse_pe(build_pe(BENIGN_IMPORTS))
    assert r.is_pe and r.num_sections == 2
    assert "kernel32.dll" in r.imports and "ExitProcess" in r.imports["kernel32.dll"]
    assert r.suspicious_apis == {}
    assert not any(a.startswith("rwx") for a in r.anomalies)


def test_suspicious_imports_and_anomalies():
    r = parse_pe(build_pe(INJECTOR_IMPORTS, rwx=True, high_entropy=True))
    assert set(r.suspicious_apis["process_injection"]) >= {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
    assert "anti_analysis" in r.suspicious_apis and "persistence" in r.suspicious_apis
    assert "rwx_section:.text" in r.anomalies
    assert "high_entropy_section:.text" in r.anomalies
