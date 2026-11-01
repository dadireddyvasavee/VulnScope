"""Builds tiny, harmless, NON-FUNCTIONAL PE32 files in memory for tests.
The code section contains only a RET instruction (or random filler bytes); nothing is ever executed."""
import os
import struct


def build_pe(imports: dict[str, list[str]], rwx: bool = False, high_entropy: bool = False,
             extra: bytes = b"", seed: int = 0) -> bytes:
    FA, SA = 0x200, 0x1000
    text_rva, idata_rva = 0x1000, 0x2000
    text = b"\xc3"
    if high_entropy:
        import random
        rnd = random.Random(seed)
        text += bytes(rnd.getrandbits(8) for _ in range(FA - 1))
    text = (text + extra)[:FA].ljust(FA, b"\x00")

    # ---- import section ----
    dlls = list(imports.items())
    desc_size = 20 * (len(dlls) + 1)
    blob = bytearray(desc_size)
    descs = []
    for dll, funcs in dlls:
        names_rva = []
        for fn in funcs:
            if len(blob) % 2:
                blob += b"\x00"
            names_rva.append(idata_rva + len(blob))
            blob += struct.pack("<H", 0) + fn.encode() + b"\x00"
        while len(blob) % 4:
            blob += b"\x00"
        ilt = idata_rva + len(blob)
        blob += b"".join(struct.pack("<I", r) for r in names_rva) + b"\x00" * 4
        iat = idata_rva + len(blob)
        blob += b"".join(struct.pack("<I", r) for r in names_rva) + b"\x00" * 4
        name = idata_rva + len(blob)
        blob += dll.encode() + b"\x00"
        descs.append((ilt, name, iat))
    for i, (ilt, name, iat) in enumerate(descs):
        blob[i * 20:(i + 1) * 20] = struct.pack("<IIIII", ilt, 0, 0, name, iat)
    raw_idata = -(-max(len(blob), 1) // FA) * FA
    idata = bytes(blob).ljust(raw_idata, b"\x00")

    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 2, 0x5F000000, 0, 0, 0xE0, 0x0102)
    size_image = idata_rva + -(-len(idata) // SA) * SA
    opt = struct.pack("<HBBIIIIIIIII" + "HHHHHH" + "IIII" + "HH" + "IIIIII",
                      0x10B, 14, 0, FA, raw_idata, 0, text_rva, text_rva, idata_rva, 0x400000, SA, FA,
                      6, 0, 0, 0, 6, 0, 0, size_image, FA, 0, 3, 0x8140,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = [(0, 0)] * 16
    dirs[1] = (idata_rva, desc_size)
    opt += b"".join(struct.pack("<II", *d) for d in dirs)
    text_ch = 0xE0000020 if rwx else 0x60000020
    sec = struct.pack("<8sIIIIIIHHI", b".text", FA, text_rva, FA, FA, 0, 0, 0, 0, text_ch)
    sec += struct.pack("<8sIIIIIIHHI", b".idata", len(idata), idata_rva, len(idata), 2 * FA, 0, 0, 0, 0, 0xC0000040)
    header = (dos + b"PE\x00\x00" + coff + opt + sec).ljust(FA, b"\x00")
    return header + text + idata


BENIGN_IMPORTS = {"kernel32.dll": ["GetModuleHandleA", "ExitProcess", "GetCommandLineA"],
                  "user32.dll": ["MessageBoxA"]}
INJECTOR_IMPORTS = {"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                                     "OpenProcess", "IsDebuggerPresent", "LoadLibraryA", "GetProcAddress"],
                    "advapi32.dll": ["RegSetValueExA"]}
