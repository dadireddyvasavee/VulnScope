from aegis.pipeline import RULES_DIR
from aegis.yara_engine.engine import YaraEngine, _parse_simple

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_eicar_detected():
    m = YaraEngine(RULES_DIR).scan(EICAR)
    assert [x.rule for x in m] == ["EICAR_Test_File"]


def test_injection_rule_requires_all():
    e = YaraEngine(RULES_DIR)
    assert not e.scan(b"VirtualAllocEx WriteProcessMemory")
    assert any(x.rule == "Suspicious_Process_Injection_APIs"
               for x in e.scan(b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"))


def test_fallback_parser_reads_rules():
    rules = _parse_simple((RULES_DIR / "aegis_core.yar").read_text())
    by = {r["name"]: r for r in rules}
    assert by["Suspicious_Downloader_Strings"]["cond"] == "2"
    assert by["EICAR_Test_File"]["meta"]["severity"] == "info"
