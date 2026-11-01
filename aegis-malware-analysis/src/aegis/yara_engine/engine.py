"""YARA scanning. Uses yara-python when installed; otherwise a minimal fallback that
supports plain-string rules only (useful for CI). Rules live in /rules."""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class YaraMatch:
    rule: str
    tags: list[str]
    meta: dict
    strings: list[str]


class YaraEngine:
    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)
        files = sorted(self.rules_dir.glob("*.yar"))
        try:
            import yara
            self._backend = "yara"
            self._rules = yara.compile(filepaths={f.stem: str(f) for f in files})
        except ImportError:
            self._backend = "fallback"
            self._rules = [r for f in files for r in _parse_simple(f.read_text())]

    @property
    def backend(self) -> str:
        return self._backend

    def scan(self, data: bytes) -> list[YaraMatch]:
        if self._backend == "yara":
            return [YaraMatch(m.rule, list(m.tags), dict(m.meta),
                              sorted({s.identifier for s in m.strings})) for m in self._rules.match(data=data)]
        out = []
        for rule in self._rules:
            hits = [sid for sid, s in rule["strings"].items() if s in data]
            need = len(rule["strings"]) if rule["cond"] == "all" else int(rule["cond"])
            if len(hits) >= need:
                out.append(YaraMatch(rule["name"], rule["tags"], rule["meta"], sorted(hits)))
        return out


_RULE = re.compile(r"rule\s+(\w+)\s*(?::\s*([\w ]+?))?\s*\{(.*?)\n\}", re.S)


def _parse_simple(text: str) -> list[dict]:
    rules = []
    for name, tags, body in _RULE.findall(text):
        meta = dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', body.split("strings:")[0]))
        strings = {sid: val.encode() for sid, val in re.findall(r'(\$\w+)\s*=\s*"([^"]*)"', body)}
        cm = re.search(r"condition:\s*(all|any|\d+)\s+of", body)
        cond = {"any": "1"}.get(cm.group(1), cm.group(1)) if cm else "all"
        rules.append({"name": name, "tags": tags.split(), "meta": meta, "strings": strings, "cond": cond})
    return rules
