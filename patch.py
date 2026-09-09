#!/usr/bin/env python
"""
Claude Code Kitty Keyboard Patch
=================================
Fixes: Shifted punctuation arrives unshifted in WezTerm (and other terminals
       using the kitty keyboard protocol with flag 4 / alternate keys).

Root cause: Claude Code requests kitty keyboard flags '5' (progressive + alternate
keys), but its CSI-u decoder ignores the alternate key data that the terminal sends
back. This causes Shift+2 to insert '2' instead of '@', etc.

The patch changes the flags from 5 to 1 in both:
  1. The Bun bytecode string constants (NUL-terminated strings in the .bun section)
  2. The JS source text (also in the .bun section)

Flag 1 = progressive enhancement only (no alternate keys), which makes WezTerm
fall back to sending the actual shifted character.

See: https://github.com/anthropics/claude-code/issues/90067

Usage:
    python patch.py                        # patches claude in default location
    python patch.py "C:\\path\\to\\claude"  # patches a specific binary
"""

import os
import sys
import shutil
import struct
from pathlib import Path

# String constant in bytecode string table: NUL-terminated ">5u"
# Context: preceded by binary metadata, followed by NUL and more binary metadata
# We verify by checking the byte before '>' is NUL (string table entry boundary)
BYTECODE_MARKER = b"\x00>5u\x00"
BYTECODE_REPLACEMENT = b"\x00>1u\x00"

# JS source text pattern
SOURCE_OLD = b'_mr=Mf(">5u")'
SOURCE_NEW = b'_mr=Mf(">1u")'


def find_claude_binary():
    candidates = [
        Path.home() / ".local" / "bin" / "claude",
        Path.home() / ".local" / "bin" / "claude.exe",
    ]
    localappdata = os.environ.get("LOCALAPPDATA", "")
    if localappdata:
        candidates.append(Path(localappdata) / "Programs" / "claude" / "claude.exe")
    for p in candidates:
        if p.exists():
            return p
    return None


def detect_format(data: bytes) -> str:
    if len(data) >= 0x44 and data[:2] == b"MZ":
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_offset + 4 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            return "pe"
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "elf"
    if len(data) >= 4 and data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                                        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    return "unknown"


def find_bun_section(data: bytes, fmt: str):
    """Find the .bun section offset and size in PE or ELF binaries."""
    if fmt == "pe":
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        coff_start = pe_offset + 4
        num_sections = struct.unpack("<H", data[coff_start + 2 : coff_start + 4])[0]
        opt_hdr_size = struct.unpack("<H", data[coff_start + 16 : coff_start + 18])[0]
        section_start = coff_start + 20 + opt_hdr_size
        for i in range(num_sections):
            off = section_start + i * 40
            name = data[off : off + 8].rstrip(b"\x00")
            if name == b".bun":
                raw_size = struct.unpack("<I", data[off + 16 : off + 20])[0]
                raw_offset = struct.unpack("<I", data[off + 20 : off + 24])[0]
                return raw_offset, raw_size

    if fmt == "elf":
        is64 = data[4] == 2
        le = data[5] == 1
        end = "<" if le else ">"
        if is64:
            e_shoff = struct.unpack(f"{end}Q", data[40:48])[0]
            e_shentsize = struct.unpack(f"{end}H", data[58:60])[0]
            e_shnum = struct.unpack(f"{end}H", data[60:62])[0]
            e_shstrndx = struct.unpack(f"{end}H", data[62:64])[0]
        else:
            e_shoff = struct.unpack(f"{end}I", data[32:36])[0]
            e_shentsize = struct.unpack(f"{end}H", data[46:48])[0]
            e_shnum = struct.unpack(f"{end}H", data[48:50])[0]
            e_shstrndx = struct.unpack(f"{end}H", data[50:52])[0]
        # Read section name string table
        strtab_off_field = e_shoff + e_shstrndx * e_shentsize + (24 if is64 else 16)
        strtab_off = struct.unpack(f"{end}{'Q' if is64 else 'I'}",
            data[strtab_off_field : strtab_off_field + (8 if is64 else 4)])[0]
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            name_idx = struct.unpack(f"{end}I", data[sh : sh + 4])[0]
            name_end = data.index(b"\x00", strtab_off + name_idx)
            name = data[strtab_off + name_idx : name_end]
            if name == b".bun":
                off_field = sh + (24 if is64 else 16)
                size_field = sh + (32 if is64 else 20)
                w = 8 if is64 else 4
                sec_off = struct.unpack(f"{end}{'Q' if is64 else 'I'}", data[off_field : off_field + w])[0]
                sec_size = struct.unpack(f"{end}{'Q' if is64 else 'I'}", data[size_field : size_field + w])[0]
                return sec_off, sec_size

    return None, None


def patch(binary_path: Path) -> Path:
    print(f"Reading {binary_path} ...")
    data = bytearray(binary_path.read_bytes())
    size_mb = len(data) / (1024 * 1024)
    print(f"  Size: {size_mb:.1f} MB")

    fmt = detect_format(data)
    fmt_labels = {"pe": "PE (Windows)", "elf": "ELF (Linux)", "macho": "Mach-O (macOS)", "unknown": "unknown"}
    print(f"  Format: {fmt_labels[fmt]}")

    bun_offset, bun_size = find_bun_section(data, fmt)
    if bun_offset:
        print(f"  .bun section: offset 0x{bun_offset:x}, size 0x{bun_size:x}")
    else:
        print("  .bun section: not found (will search entire binary)")

    patched_anything = False

    # --- Patch 1: Bytecode string constant ---
    # Find NUL-terminated ">5u" strings that are NOT inside JS source text.
    # The bytecode string table entry looks like: \x00>5u\x00 (NUL-bounded)
    # The JS source text looks like: Mf(">5u")
    bytecode_positions = []
    start = 0
    while True:
        idx = data.find(BYTECODE_MARKER, start)
        if idx < 0:
            break
        # Check this is NOT inside JS source (preceded by Mf(" or similar)
        context_before = data[max(0, idx - 10) : idx].decode("ascii", errors="replace")
        if 'Mf("' not in context_before:
            bytecode_positions.append(idx)
        start = idx + 1

    if bytecode_positions:
        print(f"\n  Bytecode string table patches:")
        for pos in bytecode_positions:
            print(f"    Offset 0x{pos:x}")
            data[pos : pos + len(BYTECODE_MARKER)] = BYTECODE_REPLACEMENT
            patched_anything = True
        print(f"    Patched {len(bytecode_positions)} string constant(s)")
    else:
        already = data.find(b"\x00>1u\x00")
        if already >= 0:
            ctx = data[max(0, already - 10) : already].decode("ascii", errors="replace")
            if 'Mf("' not in ctx:
                print(f"\n  Bytecode: already patched ('>1u' at 0x{already:x})")
            else:
                print("\n  WARNING: Bytecode string '>5u' not found!")
        else:
            print("\n  WARNING: Bytecode string '>5u' not found!")

    # --- Patch 2: JS source text ---
    source_idx = data.find(SOURCE_OLD)

    if source_idx >= 0:
        print(f"\n  Source text patch:")
        print(f"    Offset 0x{source_idx:x}: {SOURCE_OLD.decode()} -> {SOURCE_NEW.decode()}")
        data[source_idx : source_idx + len(SOURCE_OLD)] = SOURCE_NEW
        patched_anything = True
    else:
        already = data.find(SOURCE_NEW)
        if already >= 0:
            print(f"\n  Source text: already patched at 0x{already:x}")
        else:
            print("\n  WARNING: Source text pattern not found!")

    if not patched_anything:
        print("\n  Nothing to patch -- binary may already be patched or is a different version.")
        return binary_path

    # Save
    backup_path = binary_path.with_suffix(binary_path.suffix + ".bak")
    if not backup_path.exists():
        print(f"\n  Backing up to {backup_path}")
        shutil.copy2(binary_path, backup_path)
    else:
        print(f"\n  Backup already exists at {backup_path}")

    output_path = binary_path.parent / (binary_path.stem + "_patched" + binary_path.suffix)
    output_path.write_bytes(bytes(data))
    print(f"  Patched binary written to {output_path}")
    print(f"  Size: {len(data)} bytes (unchanged)")
    print()
    print("To install:")
    print(f"  1. Close Claude Code completely")
    if sys.platform == "win32":
        print(f"  2. Kill any remaining claude processes:")
        print(f'     Get-Process -Name "claude*" | Stop-Process -Force')
        print(f'  3. copy "{output_path}" "{binary_path}"')
    else:
        print(f"  2. Kill any remaining claude processes:")
        print(f'     pkill -f claude || true')
        print(f'  3. cp "{output_path}" "{binary_path}"')
    print(f"  4. Restart Claude Code")
    print()
    print(f"To revert:")
    if sys.platform == "win32":
        print(f'  copy "{backup_path}" "{binary_path}"')
    else:
        print(f'  cp "{backup_path}" "{binary_path}"')

    return output_path


def main():
    if len(sys.argv) > 1:
        binary_path = Path(sys.argv[1])
    else:
        binary_path = find_claude_binary()
        if binary_path is None:
            print("Could not find Claude Code binary.")
            print("Pass the path as an argument: python patch.py <path-to-claude>")
            sys.exit(1)

    if not binary_path.exists():
        print(f"File not found: {binary_path}")
        sys.exit(1)

    print("Claude Code Kitty Keyboard Patch")
    print("=" * 40)
    print("Fixes shifted punctuation in WezTerm")
    print("(github.com/anthropics/claude-code/issues/90067)")
    print()

    patch(binary_path)


if __name__ == "__main__":
    main()
