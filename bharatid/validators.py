"""Validators for Indian identifiers. Pure functions, no dependencies.

Checksum-validated: Aadhaar (Verhoeff), GSTIN (base-36 Luhn-style mod 36).
Structure-validated: PAN, TAN, IFSC, EPIC (voter ID), passport, driving licence, vehicle plate, UPI.
A structural pass means "well-formed", not "issued"; only the checksum ones can reject typos."""
import re
import string

# ---------------------------------------------------------------- Verhoeff (Aadhaar)
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def is_valid_aadhaar(s: str) -> bool:
    d = re.sub(r"[\s-]", "", s)
    return bool(re.fullmatch(r"[2-9]\d{11}", d)) and verhoeff_valid(d)


# ---------------------------------------------------------------- GSTIN
_B36 = string.digits + string.ascii_uppercase
GST_STATE_CODES = {f"{i:02d}" for i in range(1, 39) if i != 25} | {"97", "99"}


def gstin_check_char(first14: str) -> str:
    total = 0
    for i, c in enumerate(first14):
        v = _B36.index(c) * (1 if i % 2 == 0 else 2)
        total += v // 36 + v % 36
    return _B36[(36 - total % 36) % 36]


_GSTIN = re.compile(r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]")


def is_valid_gstin(s: str) -> bool:
    s = s.strip().upper()
    return (bool(_GSTIN.fullmatch(s)) and s[:2] in GST_STATE_CODES and is_valid_pan(s[2:12])
            and gstin_check_char(s[:14]) == s[14])


# ---------------------------------------------------------------- structure-only IDs
PAN_ENTITY = "ABCFGHLJPT"   # 4th character: A assoc, B body, C company, F firm, G govt, H HUF, L local, J juridical, P person, T trust


def is_valid_pan(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{3}[%s][A-Z][0-9]{4}[A-Z]" % PAN_ENTITY, s.strip()))


def is_valid_tan(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{4}[0-9]{5}[A-Z]", s.strip()))


def is_valid_ifsc(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", s.strip()))


def is_valid_epic(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{3}[0-9]{7}", s.strip()))


def is_valid_passport(s: str) -> bool:
    return bool(re.fullmatch(r"[A-PR-WY][1-9][0-9]{6}", s.strip().upper()))


RTO_STATES = {"AN", "AP", "AR", "AS", "BR", "CG", "CH", "DD", "DL", "DN", "GA", "GJ", "HP", "HR", "JH", "JK",
              "KA", "KL", "LA", "LD", "MH", "ML", "MN", "MP", "MZ", "NL", "OD", "OR", "PB", "PY", "RJ", "SK",
              "TN", "TR", "TS", "UK", "UP", "WB"}

_PLATE = re.compile(r"([A-Z]{2})[ -]?(\d{1,2})[ -]?((?:[A-Z][ -]?){1,3})(\d{4})")
_BH_PLATE = re.compile(r"(\d{2})[ -]?BH[ -]?(\d{4})[ -]?([A-HJ-NP-Z]{1,2})")   # Bharat series


def is_valid_vehicle_plate(s: str) -> bool:
    s = s.strip().upper()
    m = _PLATE.fullmatch(s)
    if m:
        return m.group(1) in RTO_STATES and int(m.group(2)) > 0
    return bool(_BH_PLATE.fullmatch(s))


_DL = re.compile(r"([A-Z]{2})[ -]?(\d{2})[ -]?((?:19|20)\d{2})(\d{7})")


def is_valid_driving_licence(s: str) -> bool:
    m = _DL.fullmatch(s.strip().upper())
    return bool(m) and m.group(1) in RTO_STATES and 1950 <= int(m.group(3)) <= 2035


UPI_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm", "upi", "apl", "pthdfc",
    "ptaxis", "ptyes", "ptsbi", "fbl", "ikwik", "jupiter", "freecharge", "airtel", "postbank", "sbi",
    "hdfcbank", "icici", "axisbank", "kotak", "yesbank", "idfcbank", "pnb", "boi", "cnrb", "unionbank",
    "aubank", "federal", "rbl", "indus", "abfspay", "waicici", "wahdfcbank", "waaxis", "wasbi", "ezetap",
}


def is_valid_upi(s: str) -> bool:
    m = re.fullmatch(r"([A-Za-z0-9._-]{2,64})@([A-Za-z]{2,32})", s.strip())
    return bool(m) and m.group(2).lower() in UPI_HANDLES
