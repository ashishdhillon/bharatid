"""indic-pii scan|redact [FILE|-]  (JSON findings, or redacted text)."""
import argparse
import json
import sys

from . import redact, scan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="indic-pii")
    ap.add_argument("cmd", choices=["scan", "redact"])
    ap.add_argument("file", nargs="?", default="-")
    ap.add_argument("--types", help="comma-separated subset, e.g. aadhaar,pan")
    a = ap.parse_args(argv)
    text = sys.stdin.read() if a.file == "-" else open(a.file, encoding="utf-8").read()
    types = a.types.split(",") if a.types else None
    if a.cmd == "redact":
        sys.stdout.write(redact(text, types))
        return 0
    ms = scan(text, types)
    print(json.dumps([m.__dict__ for m in ms], indent=2))
    return 1 if ms else 0


if __name__ == "__main__":
    sys.exit(main())
