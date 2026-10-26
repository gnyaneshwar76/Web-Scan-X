"""Bounded parser for Android binary XML (AndroidManifest.xml, res/xml/*.xml).

Reads the string pool and start/end element chunks only. Every offset and count
is checked against the buffer; any inconsistency raises ValueError. Input is
hostile, so there is no recursion and all loops have hard caps.
"""

from __future__ import annotations

import struct

MAX_STRINGS = 200_000
MAX_ELEMENTS = 50_000
MAX_ATTRS = 256
MAX_DEPTH = 256
MAX_POOL_CHARS = 4_000_000   # total decoded characters per pool

_RES_XML, _POOL, _START, _END = 0x0003, 0x0001, 0x0102, 0x0103
_NONE = 0xFFFFFFFF


def _u16(d, o):
    if o < 0 or o + 2 > len(d):
        raise ValueError("offset out of range")
    return struct.unpack_from("<H", d, o)[0]


def _u32(d, o):
    if o < 0 or o + 4 > len(d):
        raise ValueError("offset out of range")
    return struct.unpack_from("<I", d, o)[0]


def _read_pool(d, pos, size):
    end = pos + size
    hs = _u16(d, pos + 2)
    count, flags, sstart = _u32(d, pos + 8), _u32(d, pos + 16), _u32(d, pos + 20)
    if count > MAX_STRINGS or hs < 28 or pos + hs + count * 4 > end or sstart > size:
        raise ValueError("bad string pool")
    utf8 = bool(flags & 0x100)
    base = pos + sstart
    out, cache, total = [], {}, 0
    for i in range(count):
        o = key = base + _u32(d, pos + hs + i * 4)
        if key in cache:    # many offsets may share one long string; decode once
            out.append(cache[key])
            continue
        if o >= end:
            raise ValueError("string offset out of range")
        if utf8:
            n = d[o]; o += 1
            if n & 0x80:
                o += 1
            n = d[o]; o += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | d[o]; o += 1
            if o + n > end:
                raise ValueError("string out of range")
            s = d[o:o + n].decode("utf-8", "replace")
        else:
            n = _u16(d, o); o += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | _u16(d, o); o += 2
            if o + n * 2 > end:
                raise ValueError("string out of range")
            s = d[o:o + n * 2].decode("utf-16-le", "replace")
        total += len(s)
        if total > MAX_POOL_CHARS:
            raise ValueError("string pool too large")
        cache[key] = s
        out.append(s)
    return out


def parse(data: bytes) -> list[dict]:
    """Return elements in document order: {"name", "attrs": {name: value}, "parent": index|-1}.

    Attribute values are str; booleans become "true"/"false", ints decimal,
    references "@0x7f...". Namespaces are ignored.
    """
    try:
        return _parse(data)
    except (struct.error, IndexError) as e:
        raise ValueError(f"malformed binary XML: {e}") from None


def _parse(d):
    if len(d) < 8 or _u16(d, 0) != _RES_XML:
        raise ValueError("not binary XML")
    total = min(_u32(d, 4), len(d))
    pool, elems, stack = None, [], []
    pos = 8
    while pos + 8 <= total:
        ctype, hs, size = _u16(d, pos), _u16(d, pos + 2), _u32(d, pos + 4)
        if size < 8 or hs > size or pos + size > total:
            raise ValueError("bad chunk size")
        if ctype == _POOL:
            pool = _read_pool(d, pos, size)
        elif ctype == _START:
            if pool is None or size < 36 or len(elems) >= MAX_ELEMENTS or len(stack) >= MAX_DEPTH:
                raise ValueError("bad element")
            ext = pos + hs
            name_i = _u32(d, ext + 4)
            astart, asize, acount = _u16(d, ext + 8), _u16(d, ext + 10), _u16(d, ext + 12)
            if acount > MAX_ATTRS or (acount and asize < 20) or ext + astart + acount * asize > pos + size:
                raise ValueError("bad attributes")
            attrs = {}
            for i in range(acount):
                a = ext + astart + i * asize
                an, raw, dtype, val = _u32(d, a + 4), _u32(d, a + 8), d[a + 15], _u32(d, a + 16)
                if an >= len(pool):
                    raise ValueError("attribute name index out of range")
                if raw != _NONE and raw < len(pool):
                    v = pool[raw]
                elif dtype == 0x03 and val < len(pool):
                    v = pool[val]
                elif dtype == 0x12:
                    v = "true" if val else "false"
                elif dtype == 0x10:
                    v = str(struct.unpack("<i", struct.pack("<I", val))[0])
                elif dtype == 0x11:
                    v = str(val)
                else:
                    v = "@0x%08x" % val
                attrs[pool[an]] = v
            if name_i >= len(pool):
                raise ValueError("element name index out of range")
            elems.append({"name": pool[name_i], "attrs": attrs,
                          "parent": stack[-1] if stack else -1})
            stack.append(len(elems) - 1)
        elif ctype == _END:
            if stack:
                stack.pop()
        pos += size
    if pool is None:
        raise ValueError("no string pool")
    return elems


def demo() -> None:
    def pool_xml(offs, strs):
        hs = 28
        body = (struct.pack("<HHIIIIII", _POOL, hs, hs + 4 * len(offs) + len(strs), len(offs), 0, 0,
                            hs + 4 * len(offs), 0)
                + b"".join(struct.pack("<I", o) for o in offs) + strs)
        return struct.pack("<HHI", _RES_XML, 8, 8 + len(body)) + body

    one = struct.pack("<H", 30_000) + b"A\0" * 30_000 + b"\0\0"
    # 100k offsets at one long string: decoded once (cache), parsed fine, no blow-up
    assert parse(pool_xml([0] * 100_000, one)) == []
    # 150 distinct 30k-char strings (4.5M chars) exceed the pool budget
    try:
        parse(pool_xml([i * len(one) for i in range(150)], one * 150))
        raise AssertionError("must raise")
    except ValueError as e:
        assert "too large" in str(e), e
    print("app/_axml.py: ok")


if __name__ == "__main__":
    demo()
