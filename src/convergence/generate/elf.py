"""Interpreters the kernel loads for a program, which no tracer sees (ADR 0008)."""

from __future__ import annotations

import struct
from pathlib import Path

PT_INTERP = 3


def elf_interpreter(path: str | Path) -> str | None:
    """The ``PT_INTERP`` path of an ELF executable, or None (static, not ELF, unreadable)."""
    try:
        with open(path, "rb") as handle:
            header = handle.read(64)
            if len(header) < 52 or header[:4] != b"\x7fELF":
                return None
            endian = "<" if header[5] == 1 else ">"
            if header[4] == 2:  # 64-bit
                (phoff,) = struct.unpack(endian + "Q", header[32:40])
                phentsize, phnum = struct.unpack(endian + "HH", header[54:58])
                entry = endian + "IIQQQQ"  # type, flags, offset, vaddr, paddr, filesz
            else:
                (phoff,) = struct.unpack(endian + "I", header[28:32])
                phentsize, phnum = struct.unpack(endian + "HH", header[42:46])
                entry = endian + "IIIII"  # type, offset, vaddr, paddr, filesz
            for index in range(min(phnum, 256)):
                handle.seek(phoff + index * phentsize)
                raw = handle.read(struct.calcsize(entry))
                if len(raw) < struct.calcsize(entry):
                    return None
                fields = struct.unpack(entry, raw)
                if fields[0] != PT_INTERP:
                    continue
                offset, size = (fields[2], fields[5]) if header[4] == 2 else (fields[1], fields[4])
                handle.seek(offset)
                return handle.read(min(size, 4096)).split(b"\0", 1)[0].decode(errors="replace")
    except OSError:
        return None
    return None


def shebang_interpreter(path: str | Path) -> str | None:
    """The interpreter named on a ``#!`` line, or None."""
    try:
        with open(path, "rb") as handle:
            first = handle.readline(4096)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    parts = first[2:].strip().split()
    return parts[0].decode(errors="replace") if parts else None
