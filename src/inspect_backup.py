"""
Safe structural inspection of a UniFi backup file.

Run this FIRST to understand what you have before running full analysis.
Does not decrypt, does not dump data, does not display secrets.
Tells you: file size, format guess (.unf vs .unifi), and if zip-based, contents.
"""

from __future__ import annotations
import sys
import zipfile
from pathlib import Path


UNF_MAGIC = b"\x00"  # .unf files start with AES ciphertext (no magic)
ZIP_MAGIC = b"PK\x03\x04"


def inspect(path: Path) -> None:
    if not path.exists():
        print(f"  [error] File not found: {path}")
        return

    size = path.stat().st_size
    print(f"  File: {path.name}")
    print(f"  Size: {size:,} bytes ({size / 1024 / 1024:.2f} MB)")

    with open(path, "rb") as f:
        head = f.read(16)

    if head.startswith(ZIP_MAGIC):
        print("  Format: ZIP container (likely .unifi console-level backup)")
        print()
        print("  Contents:")
        try:
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    flag = ""
                    if info.filename.endswith(".unf"):
                        flag = "  <-- site backup (our phase 1 parser)"
                    elif ".sql" in info.filename.lower():
                        flag = "  <-- UCore PostgreSQL dump (phase 1.5)"
                    elif info.filename.endswith(".json"):
                        flag = "  <-- metadata"
                    print(
                        f"    {info.filename:<60}  "
                        f"{info.file_size:>12,} bytes{flag}"
                    )
        except zipfile.BadZipFile:
            print("    [error] Not a valid ZIP despite magic bytes.")
    elif size % 16 == 0:
        print("  Format: Encrypted blob (likely .unf single-site backup)")
        print("  Block-size-aligned: yes (consistent with AES-CBC)")
        print("  -> Run parser.py analyze to decrypt and inspect.")
    else:
        print("  Format: Unknown.")
        print(f"  First 16 bytes (hex): {head.hex()}")
        print("  -> Not a standard .unf or .unifi backup. Investigate manually.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python inspect_backup.py <path-to-backup>")
        sys.exit(1)
    inspect(Path(sys.argv[1]))
