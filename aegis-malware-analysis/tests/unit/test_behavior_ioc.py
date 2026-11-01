import json
from pathlib import Path
from aegis.behavior.sandbox_parser import parse_report, behavior_score
from aegis.reporting.ioc import extract_iocs, refang

FX = Path(__file__).parents[1] / "fixtures"


def test_ransom_like_signals():
    b = parse_report(json.loads((FX / "sandbox_ransom_like.json").read_text()))
    for s in ("shadow_copy_deletion", "encoded_powershell", "registry_persistence",
              "encrypted_extension_writes", "lolbin_execution", "network_activity"):
        assert s in b.signals, s
    assert behavior_score(b) > 0.95


def test_benign_report_low_score():
    b = parse_report(json.loads((FX / "sandbox_benign.json").read_text()))
    assert b.signals == {} and behavior_score(b) == 0


def test_ioc_extraction_defanged_and_filters_private():
    text = ("C2 at hxxp://evil[.]example[.]com/a.php and 8.8.8.8, internal 10.0.0.5, "
            "file payload.exe hash 44d88612fea8a8f36de82e1278abb02f")
    i = extract_iocs(text)
    assert "http://evil.example.com/a.php" in i["urls"]
    assert i["ips"] == ["8.8.8.8"]
    assert "evil.example.com" in i["domains"] and "payload.exe" not in i["domains"]
    assert i["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]


def test_refang():
    assert refang("hxxps://a[.]b") == "https://a.b"
