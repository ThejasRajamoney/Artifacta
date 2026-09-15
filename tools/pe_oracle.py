"""Compare Artifacta's core PE observations with pefile without executing input."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

import pefile


def fixture_bytes(path: pathlib.Path) -> bytes:
    stored = path.read_bytes()
    return bytes.fromhex(stored.decode("ascii")) if path.suffix == ".hex" else stored


def pefile_contract(path: pathlib.Path) -> dict[str, object]:
    pe = pefile.PE(data=fixture_bytes(path), fast_load=False)
    sections = [
        {
            "name": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
            "virtual_address": section.VirtualAddress,
            "virtual_size": section.Misc_VirtualSize,
            "raw_offset": section.PointerToRawData,
            "raw_size": section.SizeOfRawData,
        }
        for section in pe.sections
    ]
    imports: list[dict[str, object]] = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode("ascii", errors="replace")
        for item in descriptor.imports:
            imports.append(
                {
                    "dll": dll,
                    "function": item.name.decode("ascii", errors="replace") if item.name else None,
                    "ordinal": item.ordinal if item.name is None else None,
                }
            )
    return {
        "pe_kind": "pe64" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "pe32",
        "machine": pe.FILE_HEADER.Machine,
        "entry_point_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "sections": sections,
        "imports": imports,
    }


def artifacta_contract(root: pathlib.Path, path: pathlib.Path) -> dict[str, object]:
    command = [
        "cargo",
        "run",
        "--quiet",
        "-p",
        "tf-pe",
        "--features",
        "dev-tools",
        "--example",
        "pe_contract",
        "--",
        str(path),
    ]
    result = subprocess.run(command, cwd=root, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=pathlib.Path)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    failures = 0
    for supplied in arguments.paths:
        path = supplied if supplied.is_absolute() else arguments.root / supplied
        try:
            expected = pefile_contract(path)
            observed = artifacta_contract(arguments.root, path)
        except (pefile.PEFormatError, subprocess.CalledProcessError) as error:
            print(f"SKIP {path.name}: one parser rejected the file: {error}", file=sys.stderr)
            continue
        if expected != observed:
            failures += 1
            print(f"DIFF {path.name}")
            print(json.dumps({"pefile": expected, "artifacta": observed}, indent=2, sort_keys=True))
        else:
            print(f"MATCH {path.name}: {len(expected['sections'])} sections, {len(expected['imports'])} imports")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
