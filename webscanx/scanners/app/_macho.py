"""Bounded Mach-O header reader (thin and fat). Hostile input: every offset is
checked and anything malformed raises ValueError. Static only, never executes."""

from __future__ import annotations

import struct

MAX_SLICES = 16
MAX_CMDS = 4096
_FAT = {0xCAFEBABE: 20, 0xCAFEBABF: 32}      # big-endian magic -> arch entry size
LC_CODE_SIGNATURE, LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x1D, 0x21, 0x2C
MH_PIE = 0x200
CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}


def _thin(data: bytes, base: int, size: int) -> dict:
    sl = data[base:base + size]
    if len(sl) < 28:
        raise ValueError("slice too small for a Mach-O header")
    le = struct.unpack_from("<I", sl, 0)[0]
    be = struct.unpack_from(">I", sl, 0)[0]
    if le in (0xFEEDFACE, 0xFEEDFACF):
        end, is64 = "<", le == 0xFEEDFACF
    elif be in (0xFEEDFACE, 0xFEEDFACF):
        end, is64 = ">", be == 0xFEEDFACF
    else:
        raise ValueError("not a Mach-O slice")
    off = 32 if is64 else 28
    if len(sl) < off:
        raise ValueError("slice too small for a Mach-O header")
    cputype, _sub, _ftype, ncmds, sizeofcmds, flags = struct.unpack_from(end + "6I", sl, 4)
    if ncmds > MAX_CMDS or off + sizeofcmds > len(sl):
        raise ValueError("load commands exceed the file")
    out = {"cpu": CPU.get(cputype, hex(cputype)), "pie": bool(flags & MH_PIE),
           "signed": False, "cryptid": None}
    end_cmds = off + sizeofcmds
    for _ in range(ncmds):
        if off + 8 > end_cmds:
            raise ValueError("truncated load command")
        cmd, cmdsize = struct.unpack_from(end + "II", sl, off)
        if cmdsize < 8 or off + cmdsize > end_cmds:
            raise ValueError("bad load command size")
        if cmd == LC_CODE_SIGNATURE:
            out["signed"] = True
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and cmdsize >= 20:
            out["cryptid"] = struct.unpack_from(end + "I", sl, off + 16)[0]
        off += cmdsize
    return out


def parse(data: bytes) -> dict:
    """{'slices': [...], 'stack_guard': bool}. Raises ValueError if malformed."""
    try:
        if len(data) < 8:
            raise ValueError("file too small")
        magic = struct.unpack_from(">I", data, 0)[0]
        slices = []
        if magic in _FAT:
            n = struct.unpack_from(">I", data, 4)[0]
            if not 1 <= n <= MAX_SLICES:
                raise ValueError("implausible fat architecture count")
            esz = _FAT[magic]
            for i in range(n):
                p = 8 + i * esz
                if p + esz > len(data):
                    raise ValueError("truncated fat header")
                fmt = ">II" if esz == 20 else ">QQ"
                off, size = struct.unpack_from(fmt, data, p + 8)
                if off + size > len(data):
                    raise ValueError("fat slice exceeds the file")
                slices.append(_thin(data, off, size))
        else:
            slices.append(_thin(data, 0, len(data)))
    except struct.error as e:
        raise ValueError(f"malformed Mach-O: {e}") from None
    return {"slices": slices, "stack_guard": b"__stack_chk_guard" in data}


def build(pie=True, signed=True, cryptid=None, stack_guard=True, cpu=0x0100000C) -> bytes:
    """Tiny synthetic 64-bit LE Mach-O for tests."""
    cmds, n = b"", 0
    if signed:
        cmds += struct.pack("<4I", LC_CODE_SIGNATURE, 16, 0, 0)
        n += 1
    if cryptid is not None:
        cmds += struct.pack("<6I", LC_ENCRYPTION_INFO_64, 24, 0, 0, cryptid, 0)
        n += 1
    hdr = struct.pack("<8I", 0xFEEDFACF, cpu, 0, 2, n, len(cmds), MH_PIE if pie else 0, 0)
    return hdr + cmds + (b"__stack_chk_guard\0" if stack_guard else b"")


def demo() -> None:
    r = parse(build())
    assert r["slices"][0] == {"cpu": "arm64", "pie": True, "signed": True, "cryptid": None}
    assert r["stack_guard"]
    r = parse(build(pie=False, signed=False, cryptid=1, stack_guard=False))
    assert not r["slices"][0]["pie"] and not r["slices"][0]["signed"]
    assert r["slices"][0]["cryptid"] == 1 and not r["stack_guard"]
    t = build()
    fat = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">5I", 0x0100000C, 0, 28, len(t), 0)
    fat += t
    assert parse(fat)["slices"][0]["cpu"] == "arm64"
    for bad in (b"", b"\xcf\xfa\xed\xfe" + b"\xff" * 40, t[:20],
                struct.pack(">II", 0xCAFEBABE, 99) + b"\0" * 40):
        try:
            parse(bad)
            raise AssertionError("malformed input must raise")
        except ValueError:
            pass
    print("_macho.py: ok")


if __name__ == "__main__":
    demo()
