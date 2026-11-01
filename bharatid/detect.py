"""Find and redact Indian PII in free text."""
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional

from . import validators as v


@dataclass(frozen=True)
class Match:
    type: str
    start: int
    end: int
    text: str
    validated: bool      # True when a checksum (not just a format) confirmed it


_P = lambda pat, flags=0: re.compile(pat, flags)
_B = r"(?<![A-Za-z0-9])"      # left word-ish boundary
_E = r"(?![A-Za-z0-9])"

_RX = {
    "aadhaar": _P(r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"),
    "gstin": _P(_B + r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]" + _E),
    "pan": _P(_B + r"[A-Z]{5}\d{4}[A-Z]" + _E),
    "tan": _P(_B + r"[A-Z]{4}\d{5}[A-Z]" + _E),
    "ifsc": _P(_B + r"[A-Z]{4}0[A-Z0-9]{6}" + _E),
    "epic": _P(_B + r"[A-Z]{3}\d{7}" + _E),
    "passport": _P(_B + r"[A-PR-WY][1-9]\d{6}" + _E),
    "driving_licence": _P(_B + r"[A-Z]{2}[ -]?\d{2}[ -]?(?:19|20)\d{2}\d{7}" + _E),
    "vehicle_plate": _P(_B + r"(?:[A-Z]{2}[ -]?\d{1,2}[ -]?(?:[A-Z][ -]?){1,3}\d{4}|\d{2}[ -]?BH[ -]?\d{4}[ -]?[A-HJ-NP-Z]{1,2})" + _E),
    "upi": _P(r"(?<![\w.@-])[A-Za-z0-9._-]{2,64}@[A-Za-z]{2,32}(?![\w.@-])"),
    "mobile": _P(r"(?<![\d+])(?:\+91[\s-]?|91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
    "pincode": _P(r"(?i)\b(?:pin(?:\s?code)?|postal code)\b\W{0,3}([1-9]\d{5})(?!\d)"),
    "bank_account": _P(r"(?i)\b(?:a/c|acc(?:ount)?)(?:\s*(?:no|number|num|#))?\.?\W{0,3}(\d{9,18})(?!\d)"),
}
_CHECK = {
    "aadhaar": v.is_valid_aadhaar, "gstin": v.is_valid_gstin, "pan": v.is_valid_pan, "tan": v.is_valid_tan,
    "ifsc": v.is_valid_ifsc, "epic": v.is_valid_epic, "passport": v.is_valid_passport,
    "driving_licence": v.is_valid_driving_licence, "vehicle_plate": v.is_valid_vehicle_plate, "upi": v.is_valid_upi,
}
CHECKSUMMED = {"aadhaar", "gstin"}
PRIORITY = ["gstin", "aadhaar", "driving_licence", "pan", "tan", "ifsc", "upi", "vehicle_plate", "epic",
            "passport", "mobile", "pincode", "bank_account"]
ALL_TYPES = tuple(PRIORITY)


def scan(text: str, types: Optional[Iterable[str]] = None) -> List[Match]:
    """Return non-overlapping matches. Candidates must pass their validator; when two types overlap
    the earlier type in PRIORITY wins (e.g. a GSTIN beats the PAN inside it)."""
    want = set(types) if types is not None else set(ALL_TYPES)
    unknown = want - set(ALL_TYPES)
    if unknown:
        raise ValueError(f"unknown types: {sorted(unknown)}")
    found: List[Match] = []
    for t in PRIORITY:
        if t not in want:
            continue
        for m in _RX[t].finditer(text):
            if t in ("pincode", "bank_account"):
                s, e, raw = m.start(1), m.end(1), m.group(1)
                ok = True
            else:
                s, e, raw = m.start(), m.end(), m.group()
                ok = _CHECK[t](raw) if t in _CHECK else True
            if ok:
                found.append(Match(t, s, e, raw, t in CHECKSUMMED))
    rank = {t: i for i, t in enumerate(PRIORITY)}
    found.sort(key=lambda m: (rank[m.type], m.start))
    kept: List[Match] = []
    for m in found:
        if not any(m.start < k.end and k.start < m.end for k in kept):
            kept.append(m)
    return sorted(kept, key=lambda m: m.start)


def redact(text: str, types: Optional[Iterable[str]] = None, label: str = "[{TYPE}]") -> str:
    out, pos = [], 0
    for m in scan(text, types):
        out.append(text[pos:m.start]); out.append(label.replace("{TYPE}", m.type.upper())); pos = m.end
    out.append(text[pos:])
    return "".join(out)
