"""pre-commit hook: fail a commit when staged files contain Indian identifiers.

Defaults to the high-precision types (Aadhaar and GSTIN are checksum-validated; PAN is
format-validated). Matched values are masked in the output so the hook itself never writes a
full identifier into CI logs. Add ``bharatid: ignore`` to a line to allow it (e.g. test data).
"""
import argparse
import sys
from typing import List, Optional, Sequence, Tuple

from . import ALL_TYPES, scan

DEFAULT_TYPES = ("aadhaar", "gstin", "pan")
IGNORE_MARK = "bharatid: ignore"


def mask(value: str) -> str:
    """Keep only the last two characters: 'ABCPE1234F' -> '********4F'."""
    keep = value[-2:]
    return "*" * max(len(value) - 2, 0) + keep


def check_file(path: str, types: Sequence[str]) -> List[Tuple[int, str, str]]:
    """Return (line_number, type, masked_value) for each finding in a text file."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    if b"\0" in raw[:8192]:                      # binary file
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        if IGNORE_MARK in line:
            continue
        for m in scan(line, types):
            found.append((n, m.type, mask(m.text)))
    return found


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="bharatid-hook", description=__doc__)
    ap.add_argument("filenames", nargs="*")
    ap.add_argument("--types", default=",".join(DEFAULT_TYPES),
                    help=f"comma-separated subset of: {', '.join(ALL_TYPES)}")
    a = ap.parse_args(argv)
    types = [t for t in a.types.split(",") if t]
    bad = 0
    for path in a.filenames:
        for line, kind, masked in check_file(path, types):
            print(f"{path}:{line}: {kind} {masked}")
            bad += 1
    if bad:
        print(f"\nbharatid: {bad} identifier(s) found. Remove them, or add "
              f"'{IGNORE_MARK}' to the line if it is test data.", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
