"""IOC extraction from strings / reports with refanging and validation."""
import ipaddress
import re

_IP = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b")
_URL = re.compile(r"\b(?:hxxps?|https?)://[^\s\"'<>]+", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\.\]|\.))+(?:[a-z]{2,24})\b", re.I)
_HASH = {"md5": re.compile(r"\b[a-f0-9]{32}\b", re.I), "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
         "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I)}
_FILE_EXT = {"exe", "dll", "sys", "txt", "log", "dat", "tmp", "bin", "py", "js", "json", "xml", "ps1", "bat"}


def refang(s: str) -> str:
    return s.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http").replace("[:]", ":")


def extract_iocs(text: str) -> dict[str, list[str]]:
    urls = sorted({refang(u).rstrip(".,);]") for u in _URL.findall(text)})
    ips = set()
    for m in _IP.findall(text):
        ip = refang(m)
        try:
            a = ipaddress.ip_address(ip)
            if not (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast):
                ips.add(ip)
        except ValueError:
            pass
    domains = set()
    for m in _DOMAIN.findall(text):
        d = refang(m).lower()
        if d.rsplit(".", 1)[-1] in _FILE_EXT or _IP.fullmatch(d):
            continue
        domains.add(d)
    hashes = {}
    for k in ("sha256", "sha1", "md5"):
        found = set(h.lower() for h in _HASH[k].findall(text))
        hashes[k] = sorted(found)
    return {"urls": urls, "ips": sorted(ips), "domains": sorted(domains), **hashes}
