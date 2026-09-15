#!/usr/bin/env python3
"""Generate synthetic PE fixtures for the Artifacta test corpus.

All fixtures are inert: they contain only valid PE structures, import tables,
export tables, and data sections. No actual malicious code is executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import random
import struct
import sys
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# PE constants
# ---------------------------------------------------------------------------

MZ_HEADER = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew at offset 60
PE_SIGNATURE = b"PE\x00\x00"

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

# Data directory indices
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_SECURITY = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_ARCHITECTURE = 7
DIR_GLOBALPTR = 8
DIR_TLS = 9
DIR_LOAD_CONFIG = 10
DIR_BOUND_IMPORT = 11
DIR_IAT = 12
DIR_DELAY_IMPORT = 13
DIR_CLR_RUNTIME = 14

SECTION_CHARS = {
    "code": 0x00000020,
    "init_data": 0x00000040,
    "uninit_data": 0x00000080,
    "exec": 0x20000000,
    "read": 0x40000000,
    "write": 0x80000000,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def align(value: int, alignment: int) -> int:
    """Align value up to the next multiple of alignment."""
    if alignment == 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def pad(data: bytes, alignment: int) -> bytes:
    """Pad data to the next alignment boundary."""
    return data + b"\x00" * (align(len(data), alignment) - len(data))


def checksum_bytes(data: bytes) -> int:
    """Compute PE checksum placeholder (not cryptographic)."""
    return sum(data) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# PE Builder
# ---------------------------------------------------------------------------

@dataclass
class SectionConfig:
    name: str
    characteristics: int = SECTION_CHARS["code"] | SECTION_CHARS["init_data"] | SECTION_CHARS["read"] | SECTION_CHARS["exec"]
    data: bytes = b""
    virtual_size: int | None = None
    raw_offset: int | None = None


@dataclass
class ImportEntry:
    dll: str
    functions: list[str] = field(default_factory=list)
    ordinals: list[int] = field(default_factory=list)


@dataclass
class ExportEntry:
    dll: str
    functions: list[str] = field(default_factory=list)
    ordinals: list[int] = field(default_factory=list)


@dataclass
class PEConfig:
    """Configuration for generating a PE file."""
    pe64: bool = True
    machine: int = IMAGE_FILE_MACHINE_AMD64
    dll: bool = False
    subsystem: int = 3  # IMAGE_SUBSYSTEM_WINDOWS_CUI
    section_alignment: int = 0x1000
    file_alignment: int = 0x200
    image_base: int = 0x140000000 if True else 0x00400000
    entry_point_rva: int = 0x1000
    sections: list[SectionConfig] = field(default_factory=list)
    imports: list[ImportEntry] = field(default_factory=list)
    exports: list[ExportEntry] = field(default_factory=list)
    data_directories: dict[int, tuple[int, int]] = field(default_factory=dict)
    tls_callbacks: int = 0
    load_config: bool = False
    relocation_entries: int = 0
    overlay: bytes = b""
    certificate_data: bytes = b""  # WIN_CERTIFICATE stub
    dll_characteristics: int = 0x0000
    data_dirs_to_zero: list[int] = field(default_factory=list)


def build_pe(config: PEConfig) -> bytes:
    """Build a minimal valid PE from config. Returns raw bytes."""
    is_64 = config.pe64
    file_align = config.file_alignment
    sect_align = config.section_alignment
    image_base = config.image_base if is_64 else (config.image_base & 0xFFFFFFFF)

    # --- DOS Header ---
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 64)  # e_lfanew

    # --- COFF + Optional header placeholder ---
    # We'll build everything into a buffer and fixup offsets at the end.
    buf = bytearray()

    # Start with DOS header
    buf += dos_header

    # PE Signature
    buf += PE_SIGNATURE

    # COFF File Header (20 bytes)
    coff_offset = len(buf)
    num_sections = len(config.sections)
    optional_header_size = (112 + 16 * 8) if is_64 else (96 + 16 * 8)  # base + 16 data dirs
    # If there are more data dirs needed, extend
    max_dir_idx = max(config.data_directories.keys()) if config.data_directories else -1
    if max_dir_idx >= 16:
        extra_dirs = max_dir_idx - 15
        optional_header_size += extra_dirs * 8
    # Round optional header to file alignment
    optional_header_size = align(optional_header_size, file_align)
    size_of_headers = align(64 + 4 + 20 + optional_header_size, file_align)
    # COFF header
    characteristics = 0x0002 if config.dll else 0x0102  # DLL or EXECUTABLE_IMAGE
    if is_64:
        characteristics |= 0x0020  # LARGE_ADDRESS_AWARE
    buf += struct.pack("<HHIIIHH",
        config.machine,
        num_sections,
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        optional_header_size,
        characteristics,
    )

    # Optional Header
    opt_start = len(buf)
    magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC if is_64 else IMAGE_NT_OPTIONAL_HDR32_MAGIC
    buf += struct.pack("<H", magic)

    if is_64:
        # PE64 optional header (112 bytes base)
        buf += struct.pack("<BBBB",
            1,  # MajorLinkerVersion
            0,  # MinorLinkerVersion
            0,  # SizeOfCode (filled later)
            0,  # SizeOfInitializedData
        )
        buf += struct.pack("<IIIII",
            0,  # SizeOfUninitializedData
            config.entry_point_rva,  # AddressOfEntryPoint
            0,  # BaseOfCode
        )
        buf += struct.pack("<Q", image_base)  # ImageBase
        buf += struct.pack("<IIII",
            sect_align,  # SectionAlignment
            file_align,  # FileAlignment
            6,  # MajorOperatingSystemVersion
            0,  # MinorOperatingSystemVersion
        )
        buf += struct.pack("<IIHH",
            0,  # MajorImageVersion
            0,  # MinorImageVersion
            6,  # MajorSubsystemVersion
            0,  # MinorSubsystemVersion
        )
        buf += struct.pack("<II",
            0,  # Win32VersionValue
            size_of_headers,  # SizeOfImage
        )
        buf += struct.pack("<II",
            size_of_headers,  # SizeOfHeaders (headers only)
            0,  # CheckSum
        )
        buf += struct.pack("<HHI",
            config.subsystem,  # Subsystem
            config.dll_characteristics,  # DllCharacteristics
        )
        # Stack/Heap sizes
        buf += struct.pack("<QQQQ",
            0x100000, 0x1000,  # Stack Reserve/Commit
            0x100000, 0x1000,  # Heap Reserve/Commit
        )
    else:
        # PE32 optional header (96 bytes base)
        buf += struct.pack("<BBBB",
            1, 0, 0, 0,
        )
        buf += struct.pack("<IIIII",
            0,
            config.entry_point_rva,
            0,  # BaseOfCode
            0,  # BaseOfData
        )
        buf += struct.pack("<I", image_base)
        buf += struct.pack("<IIII",
            sect_align,
            file_align,
            6, 0,
        )
        buf += struct.pack("<IIHH",
            0, 0, 6, 0,
        )
        buf += struct.pack("<III",
            0,  # Win32VersionValue
            size_of_headers,
            size_of_headers,
        )
        buf += struct.pack("<I", 0)  # CheckSum
        buf += struct.pack("<HHI",
            config.subsystem,
            config.dll_characteristics,
            0x100000,  # SizeOfStackReserve
        )
        buf += struct.pack("<III",
            0x1000,  # SizeOfStackCommit
            0x100000,  # SizeOfHeapReserve
            0x1000,  # SizeOfHeapCommit
        )

    # Data directories (16 entries, 8 bytes each)
    dir_start = len(buf)
    data_dir_count = 16
    if max_dir_idx >= 16:
        data_dir_count = max_dir_idx + 1
    for i in range(data_dir_count):
        if i in config.data_directories:
            rva, size = config.data_directories[i]
            buf += struct.pack("<II", rva, size)
        elif i in config.data_dirs_to_zero:
            buf += struct.pack("<II", 0, 0)
        else:
            buf += struct.pack("<II", 0, 0)

    # Pad optional header to file alignment
    while len(buf) % file_align != 0:
        buf += b"\x00"

    # --- Section Headers ---
    sect_headers_start = len(buf)
    for sec in config.sections:
        name_bytes = sec.name.encode("ascii")[:8].ljust(8, b"\x00")
        vsize = sec.virtual_size if sec.virtual_size is not None else len(sec.data)
        buf += name_bytes
        buf += struct.pack("<IIIIIIHHI",
            vsize,  # VirtualSize
            0,  # VirtualAddress (fixed later)
            len(sec.data) if sec.raw_offset is None else 0,  # SizeOfRawData
            sec.raw_offset if sec.raw_offset is not None else 0,  # PointerToRawData
            0,  # PointerToRelocations
            0,  # PointerToLinenumbers
            0,  # NumberOfRelocations
            0,  # NumberOfLinenumbers
            sec.characteristics,
        )

    # Pad to file alignment
    while len(buf) % file_align != 0:
        buf += b"\x00"

    # --- Section Data ---
    # Compute section RVAs
    current_rva = align(size_of_headers, sect_align)
    section_data_list: list[tuple[bytes, int]] = []  # (data, rva)
    for i, sec in enumerate(config.sections):
        raw_data = sec.data
        raw_data = pad(raw_data, file_align)
        rva = align(current_rva, sect_align)
        section_data_list.append((raw_data, rva))
        # Fix up section header
        header_offset = sect_headers_start + i * 40
        struct.pack_into("<II", buf, header_offset + 8, vsize if sec.virtual_size is not None else len(sec.data))
        struct.pack_into("<I", buf, header_offset + 12, rva)
        struct.pack_into("<I", buf, header_offset + 16, len(raw_data))
        if sec.raw_offset is None:
            struct.pack_into("<I", buf, header_offset + 20, len(buf) + 0)  # Will be set after
        current_rva = rva + len(raw_data)

    # Update SizeOfImage
    size_of_image = align(current_rva, sect_align)
    if is_64:
        struct.pack_into("<I", buf, opt_start + 56, size_of_image)
    else:
        struct.pack_into("<I", buf, opt_start + 56, size_of_image)

    # Fix section raw offsets (after headers)
    raw_offset_base = align(len(buf), file_align)
    for i, sec in enumerate(config.sections):
        header_offset = sect_headers_start + i * 40
        if sec.raw_offset is None:
            struct.pack_into("<I", buf, header_offset + 20, raw_offset_base + i * align(len(sec.data), file_align))

    # Append section data
    for raw_data, rva in section_data_list:
        buf += raw_data

    # Pad to file alignment after sections
    while len(buf) % file_align != 0:
        buf += b"\x00"

    # --- Build Import Table ---
    if config.imports:
        import_rva = current_rva  # Will be in a dedicated section or at end
        # Create import section
        import_data = _build_import_data(config.imports, image_base, is_64, import_rva)
        import_section_rva = align(current_rva, sect_align)
        import_section_offset = len(buf)
        buf += pad(import_data, file_align)
        # Add section header
        sect_name = b".idata\x00\x00"
        characteristics = SECTION_CHARS["init_data"] | SECTION_CHARS["read"] | SECTION_CHARS["write"]
        buf_sec_header = bytearray(40)
        buf_sec_header[0:8] = sect_name
        struct.pack_into("<II", buf_sec_header, 8, len(import_data))
        struct.pack_into("<I", buf_sec_header, 12, import_section_rva)
        struct.pack_into("<I", buf_sec_header, 16, align(len(import_data), file_align))
        struct.pack_into("<I", buf_sec_header, 20, import_section_offset)
        struct.pack_into("<I", buf_sec_header + 36, 0, characteristics)

        # Insert section header before section data
        # Actually, we need to restructure: build headers first, then sections
        # For simplicity, let's rebuild entirely with imports in a section
        # We'll use a two-pass approach
        pass

    # --- Build Export Table ---
    if config.exports:
        export_data = _build_export_data(config.exports, image_base, is_64)
        export_section_rva = align(current_rva, sect_align)
        export_section_offset = len(buf)
        buf += pad(export_data, file_align)
        pass

    return bytes(buf)


def _build_import_data(imports: list[ImportEntry], image_base: int, is_64: bool, base_rva: int) -> bytes:
    """Build import directory table + ILT + IAT + name strings."""
    # This is a simplified builder
    data = bytearray()
    # Each import descriptor is 20 bytes, terminated by 20 zeros
    # For now, return a minimal stub
    return bytes(data)


def _build_export_data(exports: list[ExportEntry], image_base: int, is_64: bool) -> bytes:
    """Build export directory table."""
    return b"\x00" * 64  # stub


# ---------------------------------------------------------------------------
# Better approach: raw byte construction per fixture
# ---------------------------------------------------------------------------

class PEBuilder:
    """Low-level PE byte builder."""

    def __init__(self, pe64: bool = True, machine: int = IMAGE_FILE_MACHINE_AMD64):
        self.pe64 = pe64
        self.machine = machine
        self.image_base = 0x140000000 if pe64 else 0x00400000
        self.section_alignment = 0x1000
        self.file_alignment = 0x200
        self.subsystem = 3  # CONSOLE
        self.dll_characteristics = 0
        self.dll = False
        self.entry_point_rva = 0x1000

        self.sections: list[tuple[str, int, bytes, int]] = []  # (name, chars, data, vsize_override)
        self.imports: list[tuple[str, list[tuple[str | None, int | None]]]] = []
        self.exports: list[tuple[str, list[str]]] = []
        self.data_dirs: dict[int, tuple[int, int]] = {}
        self.overlay = b""
        self.cert_data = b""

    def set_image_base(self, base: int):
        self.image_base = base
        return self

    def set_alignment(self, sect: int, file: int):
        self.section_alignment = sect
        self.file_alignment = file
        return self

    def set_subsystem(self, s: int):
        self.subsystem = s
        return self

    def set_dll_characteristics(self, dc: int):
        self.dll_characteristics = dc
        return self

    def set_entry_point(self, rva: int):
        self.entry_point_rva = rva
        return self

    def add_section(self, name: str, characteristics: int, data: bytes, vsize: int = 0):
        self.sections.append((name, characteristics, data, vsize))
        return self

    def add_import(self, dll: str, functions: list[tuple[str | None, int | None]]):
        self.imports.append((dll, functions))
        return self

    def add_export(self, dll: str, functions: list[str]):
        self.exports.append((dll, functions))
        return self

    def set_data_dir(self, index: int, rva: int, size: int):
        self.data_dirs[index] = (rva, size)
        return self

    def build(self) -> bytes:
        fa = self.file_alignment
        sa = self.section_alignment
        is64 = self.pe64
        ib = self.image_base if is64 else (self.image_base & 0xFFFFFFFF)

        # Compute sizes
        opt_hdr_base = 112 if is64 else 96
        num_data_dirs = max(16, (max(self.data_dirs.keys()) + 1) if self.data_dirs else 16)
        opt_hdr_size = opt_hdr_base + num_data_dirs * 8
        headers_size = align(64 + 4 + 20 + opt_hdr_size, fa)

        # Section data layout
        section_payloads: list[tuple[str, int, bytes, int, int]] = []  # (name, chars, data, rva, raw_offset)

        # Import section
        import_section_data = b""
        import_section_rva = 0
        if self.imports:
            import_section_data = self._build_import_section()
            import_section_rva = headers_size  # first section starts at headers_size

        # Export section
        export_section_data = b""
        export_section_rva = 0

        # Build all sections
        all_sections: list[tuple[str, int, bytes, int]] = []  # (name, chars, data, vsize)
        if self.imports:
            all_sections.append((".idata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"] | SECTION_CHARS["write"], import_section_data, 0))
        if self.exports:
            export_section_data = self._build_export_section()
            all_sections.append((".edata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], export_section_data, 0))
        for name, chars, data, vsize in self.sections:
            all_sections.append((name, chars, data, vsize if vsize else len(data)))

        num_sections = len(all_sections)

        # Compute RVAs and raw offsets
        current_rva = headers_size
        current_raw = headers_size
        for i, (name, chars, data, vsize) in enumerate(all_sections):
            rva = align(current_rva, sa)
            raw_off = align(current_raw, fa)
            padded_data = pad(data, fa)
            section_payloads.append((name, chars, padded_data, rva, raw_off))
            current_rva = rva + len(padded_data)
            current_raw = raw_off + len(padded_data)

        size_of_image = align(current_rva, sa)

        # Fix import directory RVA if imports exist
        if self.imports and section_payloads:
            import_dir_rva = section_payloads[0][3]  # RVA of .idata section
            import_dir_size = len(self.imports) * 20 + 20  # descriptors + terminator
            self.data_dirs[DIR_IMPORT] = (import_dir_rva, import_dir_size)

            # Patch RVAs in the import section data: add section_rva to all internal offsets
            idata = bytearray(section_payloads[0][2])
            num_dlls_imp = len(self.imports)
            idt_size_imp = (num_dlls_imp + 1) * 20
            ilt_size_imp = sum((len(fns) + 1) * (8 if is64 else 4) for _, fns in self.imports)
            # Patch import descriptor RVAs
            for di in range(num_dlls_imp):
                # Patch OriginalFirstThunk (ILT RVA)
                oft_off = di * 20 + 0
                old_oft = struct.unpack_from("<I", idata, oft_off)[0]
                if old_oft != 0:
                    struct.pack_into("<I", idata, oft_off, old_oft + import_dir_rva)
                # Patch Name RVA
                name_rva_off = di * 20 + 12
                old_name_rva = struct.unpack_from("<I", idata, name_rva_off)[0]
                struct.pack_into("<I", idata, name_rva_off, old_name_rva + import_dir_rva)
                # Patch FirstThunk RVA (IAT)
                ft_off = di * 20 + 16
                old_ft = struct.unpack_from("<I", idata, ft_off)[0]
                struct.pack_into("<I", idata, ft_off, old_ft + import_dir_rva)
            # Patch ILT entries (OriginalFirstThunk is 0, we use ILT area)
            # ILT starts at idt_size_imp
            ilt_base = idt_size_imp
            iat_base = idt_size_imp + ilt_size_imp
            ptr_size = 8 if is64 else 4
            for di, (_, fns) in enumerate(self.imports):
                for fi in range(len(fns)):
                    entry_off = ilt_base + di * (len(fns) + 1) * ptr_size + fi * ptr_size
                    old_val = struct.unpack_from("<Q" if is64 else "<I", idata, entry_off)[0]
                    if old_val != 0 and not (old_val >> (63 if is64 else 31)):  # Not ordinal import
                        struct.pack_into("<Q" if is64 else "<I", idata, entry_off, old_val + import_dir_rva)
                    # IAT
                    iat_entry_off = iat_base + di * (len(fns) + 1) * ptr_size + fi * ptr_size
                    old_iat = struct.unpack_from("<Q" if is64 else "<I", idata, iat_entry_off)[0]
                    if old_iat != 0 and not (old_iat >> (63 if is64 else 31)):
                        struct.pack_into("<Q" if is64 else "<I", idata, iat_entry_off, old_iat + import_dir_rva)
            # Patch IAT directory
            self.data_dirs[DIR_IAT] = (import_dir_rva + iat_base, ilt_size_imp)

            # Write patched data back
            section_payloads[0] = (section_payloads[0][0], section_payloads[0][1], bytes(idata), section_payloads[0][3], section_payloads[0][4])

        # Fix export directory RVA if exports exist
        if self.exports and len(section_payloads) > (1 if self.imports else 0):
            idx = 1 if self.imports else 0
            if idx < len(section_payloads):
                export_dir_rva = section_payloads[idx][3]
                self.data_dirs[DIR_EXPORT] = (export_dir_rva, len(section_payloads[idx][2]))

        # --- Build headers ---
        # Compute total file size needed
        file_size = align(current_raw, fa) if section_payloads else headers_size
        buf = bytearray(file_size)

        # DOS Header
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 60, 64)

        # PE Signature at offset 64
        buf[64:68] = PE_SIGNATURE

        # COFF Header at offset 68
        coff_off = 68
        characteristics = 0x0002 if self.dll else 0x0102
        if is64:
            characteristics |= 0x0020
        struct.pack_into("<HHIIIHH", buf, coff_off,
            self.machine, num_sections, 0, 0, 0,
            opt_hdr_size, characteristics)

        # Optional Header
        opt_off = coff_off + 20
        magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC if is64 else IMAGE_NT_OPTIONAL_HDR32_MAGIC
        struct.pack_into("<H", buf, opt_off, magic)

        if is64:
            struct.pack_into("<BBBB", buf, opt_off+2, 1, 0, 0, 0)
            struct.pack_into("<III", buf, opt_off+6, 0, 0, 0)
            struct.pack_into("<II", buf, opt_off+18, self.entry_point_rva, 0)
            struct.pack_into("<Q", buf, opt_off+24, ib)
            struct.pack_into("<II", buf, opt_off+32, sa, fa)
            struct.pack_into("<II", buf, opt_off+40, 6, 0)
            struct.pack_into("<II", buf, opt_off+44, 0, 0)
            struct.pack_into("<II", buf, opt_off+48, 6, 0)
            struct.pack_into("<III", buf, opt_off+52, 0, size_of_image, headers_size)
            struct.pack_into("<I", buf, opt_off+64, 0)
            struct.pack_into("<HH", buf, opt_off+68, self.subsystem, self.dll_characteristics)
            struct.pack_into("<QQQQ", buf, opt_off+72, 0x100000, 0x1000, 0x100000, 0x1000)
            struct.pack_into("<II", buf, opt_off+104, 0, num_data_dirs)
            # Data directories start at opt_off + 112
            dd_off = opt_off + 112
        else:
            struct.pack_into("<BBBB", buf, opt_off+2, 1, 0, 0, 0)
            struct.pack_into("<IIII", buf, opt_off+6, 0, 0, 0, 0)
            struct.pack_into("<III", buf, opt_off+22, self.entry_point_rva, 0, 0)
            struct.pack_into("<I", buf, opt_off+34, ib)
            struct.pack_into("<II", buf, opt_off+38, sa, fa)
            struct.pack_into("<II", buf, opt_off+46, 6, 0)
            struct.pack_into("<II", buf, opt_off+50, 0, 0)
            struct.pack_into("<II", buf, opt_off+54, 6, 0)
            struct.pack_into("<III", buf, opt_off+58, 0, size_of_image, headers_size)
            struct.pack_into("<I", buf, opt_off+70, 0)
            struct.pack_into("<HH", buf, opt_off+74, self.subsystem, self.dll_characteristics)
            struct.pack_into("<IIII", buf, opt_off+78, 0x100000, 0x1000, 0x100000, 0x1000)
            struct.pack_into("<II", buf, opt_off+92, 0, num_data_dirs)
            dd_off = opt_off + 96

        # Data directories
        for i in range(num_data_dirs):
            if i in self.data_dirs:
                rva, size = self.data_dirs[i]
                struct.pack_into("<II", buf, dd_off + i * 8, rva, size)
            else:
                struct.pack_into("<II", buf, dd_off + i * 8, 0, 0)

        # Section Headers
        sect_hdr_off = opt_off + opt_hdr_size
        for i, (name, chars, padded_data, rva, raw_off) in enumerate(section_payloads):
            off = sect_hdr_off + i * 40
            name_bytes = name.encode("ascii")[:8].ljust(8, b"\x00")
            buf[off:off+8] = name_bytes
            struct.pack_into("<III", buf, off+8, len(padded_data), rva, len(padded_data))
            struct.pack_into("<I", buf, off+20, raw_off)
            struct.pack_into("<HHI", buf, off+32, 0, 0, 0)
            struct.pack_into("<I", buf, off+36, chars)

        # Section data
        for name, chars, padded_data, rva, raw_off in section_payloads:
            buf[raw_off:raw_off+len(padded_data)] = padded_data

        return bytes(buf) + self.overlay

    def _build_import_section(self) -> bytes:
        """Build .idata section with import directory, ILT, IAT, and name strings."""
        num_dlls = len(self.imports)
        # Import directory table: (num_dlls + 1) * 20 bytes
        # ILT: num_dlls entries, each null-terminated, plus extra null entries
        # IAT: same structure
        # Name strings: null-terminated DLL names
        # Hint/Name table: hint(2) + name + null

        # Pre-compute sizes
        idt_size = (num_dlls + 1) * 20  # import directory table
        ilt_size = 0
        name_strings = bytearray()
        hint_names = bytearray()

        for dll_name, funcs in self.imports:
            # Each DLL needs a null terminator entry in ILT
            ilt_size += (len(funcs) + 1) * (8 if self.pe64 else 4)
            # DLL name string
            name_strings += dll_name.encode("ascii") + b"\x00"
            # Hint/name entries
            for fn_name, ordinal in funcs:
                if fn_name is not None:
                    hint = struct.pack("<H", 1)  # hint
                    name_bytes = fn_name.encode("ascii") + b"\x00"
                    hint_names += hint + name_bytes
                else:
                    # Ordinal import: high bit set
                    hint_names += struct.pack("<H", ordinal | 0x8000)

        total_idata = idt_size + ilt_size * 2 + len(name_strings) + len(hint_names)
        # Pad to alignment
        total_idata = align(total_idata, self.file_alignment)
        section_data = bytearray(total_idata)

        # Build import directory entries
        current_offset = 0
        ilt_offset = idt_size
        iat_offset = ilt_size + idt_size
        name_offset = iat_offset + ilt_size
        hint_name_offset = name_offset + len(name_strings)

        name_str_pos = 0
        hn_pos = 0

        for dll_idx, (dll_name, funcs) in enumerate(self.imports):
            # Import Descriptor
            dll_name_rva = name_offset + name_str_pos  # RVA will be patched
            ilt_rva_for_dll = ilt_offset + dll_idx * (len(funcs) + 1) * (8 if self.pe64 else 4)
            iat_rva_for_dll = iat_offset + dll_idx * (len(funcs) + 1) * (8 if self.pe64 else 4)
            struct.pack_into("<IIIII", section_data, current_offset + dll_idx * 20,
                ilt_rva_for_dll,  # OriginalFirstThunk (points to ILT)
                0,  # TimeDateStamp
                0,  # ForwarderChain
                dll_name_rva,  # Name RVA
                iat_rva_for_dll,  # FirstThunk (points to IAT)
            )
            name_str_pos += len(dll_name) + 1

        # Terminator descriptor
        struct.pack_into("<IIIII", section_data, current_offset + num_dlls * 20, 0, 0, 0, 0, 0)

        # Build ILT and IAT entries
        ilt_pos = idt_size
        iat_pos = idt_size + ilt_size
        hn_pos_global = 0  # cumulative position across all DLLs
        for dll_idx, (dll_name, funcs) in enumerate(self.imports):
            for fn_name, ordinal in self.imports[dll_idx][1]:
                if fn_name is not None:
                    # Hint/Name entry RVA
                    hn_rva = hint_name_offset + hn_pos_global
                    if self.pe64:
                        struct.pack_into("<Q", section_data, ilt_pos, hn_rva)
                        struct.pack_into("<Q", section_data, iat_pos, hn_rva)
                    else:
                        struct.pack_into("<I", section_data, ilt_pos, hn_rva)
                        struct.pack_into("<I", section_data, iat_pos, hn_rva)
                    ilt_pos += 8 if self.pe64 else 4
                    iat_pos += 8 if self.pe64 else 4
                    hn_pos_global += 2 + len(fn_name.encode("ascii")) + 1
                else:
                    # Ordinal import
                    ordinal_flag = (1 << (63 if self.pe64 else 31)) | ordinal
                    if self.pe64:
                        struct.pack_into("<Q", section_data, ilt_pos, ordinal_flag)
                        struct.pack_into("<Q", section_data, iat_pos, ordinal_flag)
                    else:
                        struct.pack_into("<I", section_data, ilt_pos, ordinal_flag & 0xFFFFFFFF)
                        struct.pack_into("<I", section_data, iat_pos, ordinal_flag & 0xFFFFFFFF)
                    ilt_pos += 8 if self.pe64 else 4
                    iat_pos += 8 if self.pe64 else 4
            # Null terminator
            if self.pe64:
                struct.pack_into("<Q", section_data, ilt_pos, 0)
                struct.pack_into("<Q", section_data, iat_pos, 0)
            else:
                struct.pack_into("<I", section_data, ilt_pos, 0)
                struct.pack_into("<I", section_data, iat_pos, 0)
            ilt_pos += 8 if self.pe64 else 4
            iat_pos += 8 if self.pe64 else 4

        # Copy name strings
        name_str_pos = 0
        for dll_name, _ in self.imports:
            section_data[name_offset + name_str_pos:name_offset + name_str_pos + len(dll_name)] = dll_name.encode("ascii")
            name_str_pos += len(dll_name) + 1

        # Copy hint/name data
        hn_pos = 0
        for dll_name, funcs in self.imports:
            for fn_name, ordinal in funcs:
                if fn_name is not None:
                    hint_bytes = struct.pack("<H", 1) + fn_name.encode("ascii") + b"\x00"
                    section_data[hint_name_offset + hn_pos:hint_name_offset + hn_pos + len(hint_bytes)] = hint_bytes
                    hn_pos += len(hint_bytes)

        return bytes(section_data)

    def _build_export_section(self) -> bytes:
        """Build .edata section with export directory."""
        dll_name = self.exports[0][0] if self.exports else "unknown.dll"
        funcs = self.exports[0][1] if self.exports else []
        num_funcs = len(funcs)
        num_names = len(funcs)
        ordinal_base = 1

        # Export Directory Table layout:
        # 0: Characteristics (4)
        # 4: TimeDateStamp (4)
        # 8: MajorVersion (2)
        # 10: MinorVersion (2)
        # 12: Name RVA (4)
        # 16: Base (4)
        # 20: NumberOfFunctions (4)
        # 24: NumberOfNames (4)
        # 28: AddressOfFunctions (4)
        # = 32 bytes base

        # Tables follow the 32-byte header:
        # EAT (AddressOfFunctions): num_funcs * 4
        # Name Pointer Table: num_names * 4
        # Ordinal Table: num_funcs * 2
        # Then name strings

        eat_offset = 32
        npt_offset = eat_offset + num_funcs * 4
        ot_offset = npt_offset + num_names * 4
        name_strings_offset = ot_offset + num_funcs * 2

        # Build function name strings
        fn_name_data = b""
        fn_name_rvas = []
        for fn in funcs:
            fn_name_rvas.append(name_strings_offset + len(fn_name_data) + 0x1000)  # + section RVA offset
            fn_name_data += fn.encode("ascii") + b"\x00"

        dll_name_rva = name_strings_offset + len(fn_name_data) + 0x1000
        dll_name_data = dll_name.encode("ascii") + b"\x00"

        total = name_strings_offset + len(fn_name_data) + len(dll_name_data)
        total = align(total, self.file_alignment)
        data = bytearray(total)

        # Export Directory Header (32 bytes)
        data[0:4] = struct.pack("<I", 0)  # Characteristics
        data[4:8] = struct.pack("<I", 0)  # TimeDateStamp
        data[8:10] = struct.pack("<H", 0)  # MajorVersion
        data[10:12] = struct.pack("<H", 0)  # MinorVersion
        data[12:16] = struct.pack("<I", dll_name_rva)  # Name RVA
        data[16:20] = struct.pack("<I", ordinal_base)  # Base
        data[20:24] = struct.pack("<I", num_funcs)  # NumberOfFunctions
        data[24:28] = struct.pack("<I", num_names)  # NumberOfNames
        data[28:32] = struct.pack("<I", 0x1000 + eat_offset)  # AddressOfFunctions RVA

        # Export Address Table
        for i in range(num_funcs):
            data[eat_offset + i * 4:eat_offset + i * 4 + 4] = struct.pack("<I", 0x1000 + eat_offset + i * 4)

        # Name Pointer Table
        for i, rva in enumerate(fn_name_rvas):
            data[npt_offset + i * 4:npt_offset + i * 4 + 4] = struct.pack("<I", rva)

        # Ordinal Table
        for i in range(num_funcs):
            data[ot_offset + i * 2:ot_offset + i * 2 + 2] = struct.pack("<H", i)

        # Name strings
        pos = name_strings_offset
        for fn in funcs:
            fn_bytes = fn.encode("ascii") + b"\x00"
            data[pos:pos + len(fn_bytes)] = fn_bytes
            pos += len(fn_bytes)

        # DLL name
        data[pos:pos + len(dll_name_data)] = dll_name_data

        return bytes(data)


# ---------------------------------------------------------------------------
# Fixture definitions
# ---------------------------------------------------------------------------

def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def deterministic_bytes(length: int, seed: int) -> bytes:
    """Generate deterministic pseudo-random bytes."""
    r = _rng(seed)
    return bytes(r.randint(0, 255) for _ in range(length))


def zero_bytes(length: int) -> bytes:
    return b"\x00" * length


# ---------------------------------------------------------------------------
# Individual fixture generators
# ---------------------------------------------------------------------------

def gen_11_pe32_minimal() -> bytes:
    pe = PEBuilder(pe64=False, machine=IMAGE_FILE_MACHINE_I386)
    pe.image_base = 0x00400000
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_12_pe64_minimal() -> bytes:
    pe = PEBuilder(pe64=True, machine=IMAGE_FILE_MACHINE_AMD64)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_13_pe32_plus() -> bytes:
    """PE32+ (PE64 magic in a PE32-style context)."""
    pe = PEBuilder(pe64=True, machine=IMAGE_FILE_MACHINE_AMD64)
    pe.image_base = 0x00400000  # Low image base typical of PE32+
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_14_unusual_alignment() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.set_alignment(sect=0x200, file=0x100)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x300))
    return pe.build()


def gen_15_truncated_header() -> bytes:
    """Truncated optional header - should fail safely."""
    pe = PEBuilder(pe64=True)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x100))
    raw = pe.build()
    # Truncate after DOS header + PE sig + partial COFF header
    return raw[:80]


def gen_16_corrupt_directory() -> bytes:
    """Invalid directory entry pointing beyond EOF."""
    pe = PEBuilder(pe64=True)
    pe.set_data_dir(DIR_IMPORT, 0x50000, 0x1000)  # Points way beyond file
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_17_msvc_like() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None), ("GetModuleHandleA", None), ("VirtualAlloc", None)])
    pe.add_import("msvcrt.dll", [("printf", None), ("malloc", None), ("free", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x400))
    return pe.build()


def gen_18_mingw_like() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("libgcc_s_seh-1.dll", [("__gcc_deregister_frame_info", None)])
    pe.add_import("msvcrt.dll", [("main", None), ("__main", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x400))
    return pe.build()


def gen_19_rust_like() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None), ("GetProcessHeap", None)])
    pe.add_import("msvcrt.dll", [("__rust_alloc", None), ("__rust_dealloc", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x400))
    return pe.build()


def gen_20_go_like() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None), ("VirtualAlloc", None)])
    pe.add_import("msvcrt.dll", [("runtime.main", None), ("runtime.gopanic", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x400))
    return pe.build()


def _build_clr_header(version: str = "v2.0") -> bytes:
    """Build a minimal IMAGE_COR20_HEADER with BSJB metadata root."""
    major_runtime = 2 if "v2" in version else 4
    minor_runtime = 0
    flags = 0x03  # ILONLY | REQUIRED_32BIT
    metadata_rva = 0x2000 + 72  # BSJB starts right after CLR header
    metadata_size = 12  # BSJB signature (4) + version (8)
    # IMAGE_COR20_HEADER layout (18 DWORDs = 72 bytes):
    # cb + MajorRuntimeVersion + MinorRuntimeVersion +
    # MetaData RVA + MetaData Size + Flags +
    # EntryPointToken + Resources RVA + Resources Size +
    # StrongNameSignature + CodeManagerTable RVA + CodeManagerTable Size +
    # VTableFixups RVA + VTableFixups Size +
    # ExportAddressTableJumps RVA + ExportAddressTableJumps Size +
    # ManagedNativeHeader RVA + ManagedNativeHeader Size
    buf = struct.pack("<IIIIIIIIIIIIIIIIII",
        72,                    # cb
        major_runtime,         # MajorRuntimeVersion
        minor_runtime,         # MinorRuntimeVersion
        metadata_rva,          # MetaData RVA
        metadata_size,         # MetaData Size
        flags,                 # Flags
        0,                     # EntryPointToken
        0,                     # Resources RVA
        0,                     # Resources Size
        0,                     # StrongNameSignature
        0, 0,                  # CodeManagerTable RVA+Size
        0, 0,                  # VTableFixups RVA+Size
        0, 0,                  # ExportAddressTableJumps RVA+Size
        0, 0,                  # ManagedNativeHeader RVA+Size
    )
    assert len(buf) == 72, f"CLR header is {len(buf)} bytes, expected 72"
    return buf


def gen_21_dotnet_v2() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("mscoree.dll", [("_CorExeMain", None)])
    pe.set_data_dir(DIR_CLR_RUNTIME, 0x2000, 0x48)
    # CLR header (72 bytes) followed by BSJB metadata
    clr_header = _build_clr_header("v2.0")
    bsjb = b"BSJB" + struct.pack("<HH", 1, 1)  # Signature + major/minor version
    text_data = clr_header + bsjb + zero_bytes(0x400 - len(clr_header) - len(bsjb))
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], text_data)
    return pe.build()


def gen_22_dotnet_v4() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("mscoree.dll", [("_CorExeMain", None)])
    pe.set_data_dir(DIR_CLR_RUNTIME, 0x2000, 0x48)
    clr_header = _build_clr_header("v4.0")
    bsjb = b"BSJB" + struct.pack("<HH", 1, 1)
    text_data = clr_header + bsjb + zero_bytes(0x400 - len(clr_header) - len(bsjb))
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], text_data)
    return pe.build()


def gen_23_qt_network() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("Qt5Core.dll", [("QCoreApplication::exec", None)])
    pe.add_import("Qt5Network.dll", [("QNetworkAccessManager::get", None)])
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x400))
    return pe.build()


def gen_24_qt_widgets() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("Qt5Core.dll", [("QCoreApplication::exec", None)])
    pe.add_import("Qt5Widgets.dll", [("QApplication::exec", None)])
    pe.add_import("Qt5Gui.dll", [("QApplication::exec", None)])
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x400))
    return pe.build()


def gen_25_unsigned_normal() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_26_selfsigned_cert() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    # Add certificate table entry
    cert_stub = b"\x00\x02" + struct.pack("<H", 0) + b"\x00" * 128  # WIN_CERTIFICATE stub
    pe.set_data_dir(DIR_SECURITY, 0x1000, len(cert_stub))
    raw = pe.build()
    # Append cert data at EOF (aligned)
    cert_offset = align(len(raw), pe.file_alignment)
    raw_padded = raw + b"\x00" * (cert_offset - len(raw))
    return raw_padded + pad(cert_stub, pe.file_alignment)


def gen_27_invalid_digest() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_28_invalid_cms() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    # Add malformed CMS signature
    cert_stub = b"\x00\x02" + b"\x00\x01" + b"\xDE\xAD" * 64  # Invalid CMS
    pe.set_data_dir(DIR_SECURITY, 0x1000, len(cert_stub))
    raw = pe.build()
    cert_offset = align(len(raw), pe.file_alignment)
    raw_padded = raw + b"\x00" * (cert_offset - len(raw))
    return raw_padded + pad(cert_stub, pe.file_alignment)


def gen_29_multiple_certs() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    cert1 = b"\x00\x02" + struct.pack("<H", 0) + b"\x00" * 128
    cert2 = b"\x00\x02" + struct.pack("<H", 0) + b"\x00" * 128
    combined = cert1 + cert2
    pe.set_data_dir(DIR_SECURITY, 0x1000, len(combined))
    raw = pe.build()
    cert_offset = align(len(raw), pe.file_alignment)
    raw_padded = raw + b"\x00" * (cert_offset - len(raw))
    return raw_padded + pad(combined, pe.file_alignment)


def gen_30_no_certificate_table() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    pe.set_data_dir(DIR_SECURITY, 0, 0)
    return pe.build()


def gen_31_writable_executable() -> bytes:
    pe = PEBuilder(pe64=True)
    chars = SECTION_CHARS["code"] | SECTION_CHARS["init_data"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"] | SECTION_CHARS["write"]
    pe.add_section(".text", chars, zero_bytes(0x200))
    return pe.build()


def gen_32_high_entropy_section() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], deterministic_bytes(0x400, seed=42))
    return pe.build()


def gen_33_high_entropy_resource() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_section(".rsrc", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], deterministic_bytes(0x600, seed=99))
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_34_overlay_data() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    pe.overlay = deterministic_bytes(0x300, seed=77)
    return pe.build()


def gen_35_certificate_tail() -> bytes:
    """Certificate data appended after EOF marker."""
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    raw = pe.build()
    # Append extra data after aligned end
    cert_offset = align(len(raw), pe.file_alignment)
    return raw + b"\x00" * (cert_offset - len(raw)) + deterministic_bytes(256, seed=33)


def gen_36_unusual_section_names() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_section(".abc123!", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    pe.add_section("UPX0", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], zero_bytes(0x200))
    pe.add_section("ndata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_37_tls_callbacks() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.set_data_dir(DIR_TLS, 0x3000, 0x18)  # TLS directory placeholder
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_38_load_config() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.set_data_dir(DIR_LOAD_CONFIG, 0x3000, 0x58)  # LOAD_CONFIG_DIRECTORY placeholder
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_39_relocations() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.set_data_dir(DIR_BASERELOC, 0x3000, 0x0C)  # Base relocation block
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_40_export_table() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.dll = True
    pe.add_export("mylib.dll", ["ExportedFunc1", "ExportedFunc2", "ExportedFunc3"])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_41_no_imports() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_42_large_import_table() -> bytes:
    pe = PEBuilder(pe64=True)
    funcs = [(f"Func{i:03d}", None) for i in range(50)]
    pe.add_import("kernel32.dll", funcs[:25])
    pe.add_import("user32.dll", funcs[25:])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x400))
    return pe.build()


def gen_43_process_injection() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [
        ("VirtualAllocEx", None),
        ("WriteProcessMemory", None),
        ("CreateRemoteThread", None),
        ("OpenProcess", None),
    ])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_44_near_miss_injection() -> bytes:
    """Has VirtualAllocEx and WriteProcessMemory but missing CreateRemoteThread."""
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [
        ("VirtualAllocEx", None),
        ("WriteProcessMemory", None),
        ("OpenProcess", None),
    ])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_45_run_persistence() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("advapi32.dll", [
        ("RegOpenKeyExA", None),
        ("RegSetValueExA", None),
        ("RegCloseKey", None),
    ])
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_46_service_persistence() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("advapi32.dll", [
        ("OpenSCManagerA", None),
        ("CreateServiceA", None),
        ("StartServiceA", None),
        ("CloseServiceHandle", None),
    ])
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_47_network_exec() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("urlmon.dll", [("URLDownloadToFileA", None)])
    pe.add_import("shell32.dll", [("ShellExecuteA", None)])
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_48_network_only() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("urlmon.dll", [("URLDownloadToFileA", None)])
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_49_exec_only() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("shell32.dll", [("ShellExecuteA", None)])
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_50_admin_manifest() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.set_dll_characteristics(0x0020)  # ASLR compatible
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    # Embed manifest as a resource (simplified: just string in .rsrc)
    manifest = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
        '<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">'
        '<security>'
        '<requestedPrivileges>'
        '<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>'
        '</requestedPrivileges>'
        '</security>'
        '</trustInfo>'
        '</assembly>'
    )
    pe.add_section(".rsrc", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], manifest.encode("ascii"))
    return pe.build()


def gen_51_entropy_noise() -> bytes:
    pe = PEBuilder(pe64=True)
    r = _rng(101)
    strings_data = b""
    for _ in range(20):
        length = r.randint(4, 16)
        s = bytes(r.randint(0x20, 0x7E) for _ in range(length))
        strings_data += s + b"\x00"
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], strings_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_52_false_dll_domain() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.dll = True
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_53_false_exe_domain() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.dll = False
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_54_unicode_strings() -> bytes:
    pe = PEBuilder(pe64=True)
    unicode_data = "Hello World\x00Test String\x00Another\x00".encode("utf-16-le")
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], unicode_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_55_ipv4_indicator() -> bytes:
    pe = PEBuilder(pe64=True)
    ip_data = b"192.168.1.100\x0010.0.0.1\x00255.255.255.0\x00"
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], ip_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_56_invalid_ipv4() -> bytes:
    pe = PEBuilder(pe64=True)
    ip_data = b"999.999.999.999\x00256.1.1.1\x00300.0.0.1\x00"
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], ip_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_57_registry_paths() -> bytes:
    pe = PEBuilder(pe64=True)
    reg_data = (
        b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\x00"
        b"HKLM\\SYSTEM\\CurrentControlSet\\Services\x00"
    )
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], reg_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_58_windows_paths() -> bytes:
    pe = PEBuilder(pe64=True)
    path_data = (
        b"C:\\Windows\\System32\\cmd.exe\x00"
        b"C:\\Users\\Default\\AppData\\Local\\Temp\x00"
        b"D:\\downloads\\setup.exe\x00"
    )
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], path_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_59_yara_positive() -> bytes:
    """Contains a known YARA match pattern (e.g., common malware string)."""
    pe = PEBuilder(pe64=True)
    pattern_data = (
        b"MZ" + b"\x90" * 10 +  # MZ header pattern
        b"\x00" * 50 +
        b"TRIVARNA{" + b"\x00" * 20 + b"}\x00" +  # Flag format
        b"http://evil.example.com/malware.exe\x00"  # Suspicious URL
    )
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], pattern_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_60_yara_negative() -> bytes:
    """No YARA matches - clean fixture."""
    pe = PEBuilder(pe64=True)
    clean_data = b"Hello World\x00Standard application\x00"
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], clean_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    pe.add_import("kernel32.dll", [("ExitProcess", None)])
    return pe.build()


def gen_61_section_oob() -> bytes:
    """Section points beyond EOF."""
    pe = PEBuilder(pe64=True)
    # Create minimal PE then corrupt the section data
    raw = bytearray(pe.build())
    # Modify section header to point way beyond file
    sect_hdr_off = 68 + 20 + 112 + 16 * 8  # coff + optional + dirs
    struct.pack_into("<I", raw, sect_hdr_off + 20, 0x100000)  # PointerToRawData
    return bytes(raw)


def gen_62_directory_oob() -> bytes:
    """Directory entry beyond EOF."""
    pe = PEBuilder(pe64=True)
    pe.set_data_dir(DIR_IMPORT, 0x100000, 0x1000)  # Way beyond file
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_63_enormous_counts() -> bytes:
    """Huge import/section counts that should fail validation."""
    pe = PEBuilder(pe64=True)
    # Only 1 section but with huge declared count in COFF header
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    raw = bytearray(pe.build())
    # Patch COFF header: set NumberOfSections to 0xFFFF
    struct.pack_into("<H", raw, 70, 0xFFFF)
    return bytes(raw)


def gen_64_overlapping_sections() -> bytes:
    """Overlapping section ranges."""
    pe = PEBuilder(pe64=True)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x400))
    pe.add_section(".data", SECTION_CHARS["init_data"] | SECTION_CHARS["read"] | SECTION_CHARS["write"], zero_bytes(0x400))
    raw = bytearray(pe.build())
    # Overlap: make section 2 start before section 1 ends
    sect_hdr_off = 68 + 20 + 112 + 16 * 8
    struct.pack_into("<I", raw, sect_hdr_off + 40 + 12, 0x1000)  # Same RVA as section 1
    return bytes(raw)


def gen_65_compare_v1() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None), ("GetModuleHandleA", None)])
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], b"version=1.0\x00http://example.com/v1\x00")
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_66_compare_v2() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [("ExitProcess", None), ("GetModuleHandleA", None), ("CreateProcessW", None)])
    pe.add_import("winhttp.dll", [("WinHttpSendRequest", None)])
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], b"version=2.0\x00http://example.com/v2\x00powershell.exe\x00")
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


def gen_67_xor_clue() -> bytes:
    """XOR-encoded data pattern."""
    pe = PEBuilder(pe64=True)
    # XOR-encoded string: "FLAG{test}" with key 0x5A
    key = 0x5A
    original = b"FLAG{test}"
    encoded = bytes(b ^ key for b in original)
    xor_data = struct.pack("<B", key) + b"\x00" * 3 + encoded + b"\x00"
    pe.add_section(".rdata", SECTION_CHARS["init_data"] | SECTION_CHARS["read"], xor_data)
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    pe.add_import("kernel32.dll", [("IsDebuggerPresent", None)])
    return pe.build()


def gen_68_anti_debug() -> bytes:
    pe = PEBuilder(pe64=True)
    pe.add_import("kernel32.dll", [
        ("IsDebuggerPresent", None),
        ("CheckRemoteDebuggerPresent", None),
        ("OutputDebugStringA", None),
    ])
    pe.add_section(".text", SECTION_CHARS["code"] | SECTION_CHARS["exec"] | SECTION_CHARS["read"], zero_bytes(0x200))
    return pe.build()


# ---------------------------------------------------------------------------
# Registry of all fixtures
# ---------------------------------------------------------------------------

FIXTURES: list[tuple[str, str, str, Any, list[str], str]] = [
    # (filename, category, generator_fn, expected, notes)
    ("11_pe32_minimal.exe", "PE format", gen_11_pe32_minimal,
     ["PE32", "minimal structure", "single .text section"],
     "Bare minimum PE32 with empty .text section."),
    ("12_pe64_minimal.exe", "PE format", gen_12_pe64_minimal,
     ["PE64", "minimal structure", "single .text section"],
     "Bare minimum PE64 with empty .text section."),
    ("13_pe32_plus.exe", "PE format", gen_13_pe32_plus,
     ["PE64", "PE32+ magic", "low image base"],
     "PE32+ with low image base typical of PE32+ binaries."),
    ("14_unusual_alignment.exe", "PE format", gen_14_unusual_alignment,
     ["PE64", "non-standard alignment", "section=0x200 file=0x100"],
     "Non-standard section and file alignment values."),
    ("15_truncated_header.exe", "PE format", gen_15_truncated_header,
     ["truncated headers", "should fail safely", "must not crash parser"],
     "Truncated optional header; parser should reject safely."),
    ("16_corrupt_directory.exe", "PE format", gen_16_corrupt_directory,
     ["PE64", "corrupt import directory", "directory points beyond EOF"],
     "Import directory entry points far beyond file end."),

    ("17_msvc_like.exe", "compiler", gen_17_msvc_like,
     ["PE64", "MSVC-style imports", "kernel32 + msvcrt"],
     "Simulates MSVC-compiled binary import pattern."),
    ("18_mingw_like.exe", "compiler", gen_18_mingw_like,
     ["PE64", "MinGW-style imports", "libgcc + msvcrt"],
     "Simulates MinGW-compiled binary import pattern."),
    ("19_rust_like.exe", "compiler", gen_19_rust_like,
     ["PE64", "Rust-like imports", "kernel32 + msvcrt rust symbols"],
     "Simulates Rust binary import pattern."),
    ("20_go_like.exe", "compiler", gen_20_go_like,
     ["PE64", "Go-like imports", "runtime.main, runtime.gopanic"],
     "Simulates Go binary import pattern."),
    ("21_dotnet_v2.exe", "compiler", gen_21_dotnet_v2,
     ["PE64", "CLR header present", ".NET v2 style", "mscoree.dll!_CorExeMain"],
     "Simulates .NET v2 CLR executable."),
    ("22_dotnet_v4.exe", "compiler", gen_22_dotnet_v4,
     ["PE64", "CLR header present", ".NET v4 style", "mscoree.dll!_CorExeMain"],
     "Simulates .NET v4 CLR executable."),
    ("23_qt_network.exe", "compiler", gen_23_qt_network,
     ["PE64", "Qt imports", "Qt5Core + Qt5Network"],
     "Simulates Qt application with network imports."),
    ("24_qt_widgets.exe", "compiler", gen_24_qt_widgets,
     ["PE64", "Qt imports", "Qt5Core + Qt5Widgets + Qt5Gui"],
     "Simulates Qt application with widget imports."),

    ("25_unsigned_normal.exe", "signature", gen_25_unsigned_normal,
     ["PE64", "no Authenticode certificate", "unsigned"],
     "Normal unsigned PE executable."),
    ("26_selfsigned_cert.exe", "signature", gen_26_selfsigned_cert,
     ["PE64", "embedded certificate table", "self-signed stub"],
     "Has WIN_CERTIFICATE stub; self-signed, not trusted."),
    ("27_invalid_digest.exe", "signature", gen_27_invalid_digest,
     ["PE64", "invalid image digest", "no certificate table"],
     "Missing certificate table; digest should be invalid."),
    ("28_invalid_cms.exe", "signature", gen_28_invalid_cms,
     ["PE64", "malformed CMS signature", "invalid certificate data"],
     "Contains malformed CMS signature data."),
    ("29_multiple_certs.exe", "signature", gen_29_multiple_certs,
     ["PE64", "multiple WIN_CERTIFICATE entries", "certificate chain"],
     "Multiple certificate entries appended after sections."),
    ("30_no_certificate_table.exe", "signature", gen_30_no_certificate_table,
     ["PE64", "explicitly no certificate table", "SECURITY directory zeroed"],
     "Security directory explicitly zeroed."),

    ("31_writable_executable.exe", "structural", gen_31_writable_executable,
     ["PE64", "W+X section permissions", "writable executable section"],
     "Section has both write and execute permissions."),
    ("32_high_entropy_section.exe", "structural", gen_32_high_entropy_section,
     ["PE64", "high entropy .text section"],
     ".text section contains high-entropy deterministic data."),
    ("33_high_entropy_resource.exe", "structural", gen_33_high_entropy_resource,
     ["PE64", "high entropy .rsrc section"],
     ".rsrc section contains high-entropy deterministic data."),
    ("34_overlay_data.exe", "structural", gen_34_overlay_data,
     ["PE64", "overlay data present", "data appended after sections"],
     "Extra data appended after last section."),
    ("35_certificate_tail.exe", "structural", gen_35_certificate_tail,
     ["PE64", "certificate data after EOF", "tail certificate"],
     "Certificate-like data appended after aligned EOF."),
    ("36_unusual_section_names.exe", "structural", gen_36_unusual_section_names,
     ["PE64", "unusual section names", ".abc123!, UPX0, ndata"],
     "Non-standard section names."),
    ("37_tls_callbacks.exe", "structural", gen_37_tls_callbacks,
     ["PE64", "TLS directory present", "TLS callback array"],
     "TLS directory entry present."),
    ("38_load_config.exe", "structural", gen_38_load_config,
     ["PE64", "Load Config directory present"],
     "Load Config directory entry present."),
    ("39_relocations.exe", "structural", gen_39_relocations,
     ["PE64", "Base Relocation directory present"],
     "Base relocation directory entry present."),
    ("40_export_table.exe", "structural", gen_40_export_table,
     ["PE64", "DLL with exports", "3 exported functions"],
     "DLL with export table."),
    ("41_no_imports.exe", "structural", gen_41_no_imports,
     ["PE64", "no imports", "empty import directory"],
     "PE with no import table."),
    ("42_large_import_table.exe", "structural", gen_42_large_import_table,
     ["PE64", "50 imported functions", "2 DLLs"],
     "Large import table with 50 functions across 2 DLLs."),

    ("43_process_injection.exe", "capability", gen_43_process_injection,
     ["PE64", "process injection imports", "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread"],
     "INERT: import strings only. No actual injection code."),
    ("44_near_miss_injection.exe", "capability", gen_44_near_miss_injection,
     ["PE64", "partial injection imports", "missing CreateRemoteThread"],
     "INERT: similar to 43 but missing one key function."),
    ("45_run_persistence.exe", "capability", gen_45_run_persistence,
     ["PE64", "run key registry APIs", "RegOpenKeyExA+RegSetValueExA"],
     "INERT: import strings only. No actual persistence code."),
    ("46_service_persistence.exe", "capability", gen_46_service_persistence,
     ["PE64", "service persistence imports", "OpenSCManagerA+CreateServiceA"],
     "INERT: import strings only. No actual service creation."),
    ("47_network_exec.exe", "capability", gen_47_network_exec,
     ["PE64", "network download + execution", "URLDownloadToFileA+ShellExecuteA"],
     "INERT: import strings only. No actual network activity."),
    ("48_network_only.exe", "capability", gen_48_network_only,
     ["PE64", "network download without execution", "URLDownloadToFileA only"],
     "INERT: download capability without execution."),
    ("49_exec_only.exe", "capability", gen_49_exec_only,
     ["PE64", "execution without network", "ShellExecuteA only"],
     "INERT: execution capability without network."),
    ("50_admin_manifest.exe", "capability", gen_50_admin_manifest,
     ["PE64", "requireAdministrator manifest", "elevation request"],
     "INERT: manifest requests admin elevation."),

    ("51_entropy_noise.exe", "edge-case", gen_51_entropy_noise,
     ["PE64", "random dotted strings", "entropy noise"],
     "Section contains random printable strings."),
    ("52_false_dll_domain.exe", "edge-case", gen_52_false_dll_domain,
     ["PE64", "DLL domain", "executable set as DLL"],
     "PE marked as DLL (IMAGE_FILE_DLL)."),
    ("53_false_exe_domain.exe", "edge-case", gen_53_false_exe_domain,
     ["PE64", "EXE domain", "executable marked as EXE"],
     "Standard executable marking."),
    ("54_unicode_strings.exe", "edge-case", gen_54_unicode_strings,
     ["PE64", "Unicode strings present"],
     "Section contains UTF-16LE strings."),
    ("55_ipv4_indicator.exe", "edge-case", gen_55_ipv4_indicator,
     ["PE64", "IPv4 addresses embedded", "192.168.1.100, 10.0.0.1"],
     "Contains embedded IPv4 address strings."),
    ("56_invalid_ipv4.exe", "edge-case", gen_56_invalid_ipv4,
     ["PE64", "invalid IPv4 addresses", "999.999.999.999"],
     "Contains obviously invalid IPv4 address strings."),
    ("57_registry_paths.exe", "edge-case", gen_57_registry_paths,
     ["PE64", "registry path strings", "HKLM/HKCU paths"],
     "Contains Windows registry path strings."),
    ("58_windows_paths.exe", "edge-case", gen_58_windows_paths,
     ["PE64", "Windows file paths", "C:\\, D:\\ paths"],
     "Contains Windows file system path strings."),

    ("59_yara_positive.exe", "yara", gen_59_yara_positive,
     ["PE64", "YARA match pattern", "flag format + suspicious URL"],
     "Contains strings that should trigger YARA rules."),
    ("60_yara_negative.exe", "yara", gen_60_yara_negative,
     ["PE64", "clean fixture", "no YARA matches expected"],
     "Clean fixture with no suspicious patterns."),

    ("61_section_oob.exe", "malformed", gen_61_section_oob,
     ["PE64", "section points beyond EOF", "anomaly", "must not crash"],
     "Section header points far beyond file end."),
    ("62_directory_oob.exe", "malformed", gen_62_directory_oob,
     ["PE64", "directory beyond EOF", "anomaly", "must not crash"],
     "Directory entry points beyond file end."),
    ("63_enormous_counts.exe", "malformed", gen_63_enormous_counts,
     ["PE64", "huge section count in COFF", "anomaly", "must not crash"],
     "COFF header declares 0xFFFF sections."),
    ("64_overlapping_sections.exe", "malformed", gen_64_overlapping_sections,
     ["PE64", "overlapping section ranges", "anomaly", "must not crash"],
     "Two sections have overlapping virtual addresses."),

    ("65_compare_v1.exe", "comparison", gen_65_compare_v1,
     ["PE64", "baseline imports/strings", "version=1.0", "/v1 URL"],
     "Version 1 baseline for artifact comparison."),
    ("66_compare_v2.exe", "comparison", gen_66_compare_v2,
     ["PE64", "adds CreateProcessW", "adds WinHttpSendRequest", "version=2.0", "/v2 URL", "adds powershell.exe string"],
     "Version 2 with additional imports/strings for diff testing."),

    ("67_xor_clue.exe", "ctf-re", gen_67_xor_clue,
     ["PE64", "XOR-encoded data pattern", "key 0x5A", "IsDebuggerPresent"],
     "Contains XOR-encoded data with key visible nearby."),
    ("68_anti_debug.exe", "ctf-re", gen_68_anti_debug,
     ["PE64", "anti-debug imports", "IsDebuggerPresent+CheckRemoteDebuggerPresent"],
     "INERT: anti-debug import strings only."),
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def file_hash(data: bytes) -> tuple[str, str]:
    sha = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return sha, md5


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1] / "testfiles")
    parser.add_argument("--manifest-only", action="store_true", help="Print manifest JSON without writing files")
    args = parser.parse_args()

    output_dir = args.output_dir
    if not args.manifest_only:
        output_dir.mkdir(parents=True, exist_ok=True)

    manifest_entries = []

    for filename, category, gen_fn, expected, notes in FIXTURES:
        try:
            data = gen_fn()
        except Exception as e:
            print(f"ERROR generating {filename}: {e}", file=sys.stderr)
            continue

        sha, md5 = file_hash(data)
        size = len(data)

        entry = {
            "file": filename,
            "category": category,
            "size": size,
            "sha256": sha,
            "md5": md5,
            "expected": expected,
            "notes": notes,
        }
        manifest_entries.append(entry)

        if not args.manifest_only:
            filepath = output_dir / filename
            filepath.write_bytes(data)
            print(f"  Generated: {filename} ({size} bytes)", file=sys.stderr)

    # Output manifest
    print(json.dumps(manifest_entries, indent=2))

    print(f"\nGenerated {len(manifest_entries)} fixtures", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
