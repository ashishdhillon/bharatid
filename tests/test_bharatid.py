import json
import pytest
from bharatid import (ALL_TYPES, gstin_check_char, is_valid_aadhaar, is_valid_driving_licence,
                       is_valid_epic, is_valid_gstin, is_valid_ifsc, is_valid_pan, is_valid_passport,
                       is_valid_tan, is_valid_upi, is_valid_vehicle_plate, redact, scan,
                       verhoeff_check_digit)
from bharatid import cli


def aadhaar(prefix="23456789012"):
    return prefix + verhoeff_check_digit(prefix)


def gstin(first14="27AAPFU0939F1Z"):
    return first14 + gstin_check_char(first14)


def kinds(text, **kw):
    return [m.type for m in scan(text, **kw)]


def test_aadhaar():
    a = aadhaar()
    assert is_valid_aadhaar(a) and is_valid_aadhaar(f"{a[:4]} {a[4:8]} {a[8:]}") and is_valid_aadhaar(f"{a[:4]}-{a[4:8]}-{a[8:]}")
    bad = a[:-1] + str((int(a[-1]) + 1) % 10)
    assert not is_valid_aadhaar(bad)
    assert not is_valid_aadhaar("123456789012")          # cannot start with 0 or 1
    assert kinds(f"id {a}") == ["aadhaar"] and scan(f"id {a}")[0].validated
    assert kinds(f"id {bad}") == []


def test_gstin_known_public_samples_and_roundtrip():
    assert is_valid_gstin("27AAPFU0939F1ZV") and is_valid_gstin("29AAGCB7383J1Z4")
    assert is_valid_gstin(gstin("07ABCPE1234F1Z"))
    assert not is_valid_gstin("27AAPFU0939F1ZW")          # wrong check character
    assert not is_valid_gstin(gstin("98ABCPE1234F1Z"))    # state code 98 does not exist
    assert not is_valid_gstin(gstin("07ABCZE1234F1Z"))    # embedded PAN has an invalid 4th letter


def test_gstin_beats_embedded_pan():
    g = gstin()
    assert kinds(f"GSTIN {g}") == ["gstin"]


def test_pan_tan_ifsc_epic_passport():
    assert is_valid_pan("ABCPD1234E") and not is_valid_pan("ABCZD1234E") and not is_valid_pan("abcpd1234e")
    assert is_valid_tan("DELA12345B") and not is_valid_tan("DELA1234B5")
    assert is_valid_ifsc("SBIN0001234") and not is_valid_ifsc("SBIN1001234")
    assert is_valid_epic("ABC1234567") and not is_valid_epic("AB12345678")
    assert is_valid_passport("K1234567") and not is_valid_passport("Q1234567") and not is_valid_passport("K0234567")


def test_vehicle_and_dl():
    for ok in ["MH12AB1234", "DL 8C AB 1234", "KA-01-AB-1234", "22 BH 1234 AA"]:
        assert is_valid_vehicle_plate(ok), ok
    assert not is_valid_vehicle_plate("ZZ12AB1234")        # not an RTO state code
    assert is_valid_driving_licence("DL-0420110149646") and is_valid_driving_licence("MH1220191234567")
    assert not is_valid_driving_licence("ZZ0420110149646")
    assert not is_valid_driving_licence("DL-0419400149646")  # year before 1950


def test_upi_needs_known_handle():
    assert is_valid_upi("ravi.k@okhdfcbank") and is_valid_upi("9876543210@ybl")
    assert not is_valid_upi("name@gmail")
    assert kinds("pay to ravi.k@okhdfcbank now") == ["upi"]
    assert kinds("mail a.b@example.com") == []             # ordinary emails are not UPI IDs


def test_mobile_pincode_account_cues():
    assert kinds("call +91 98765 43210") == ["mobile"] and kinds("call 9876543210") == ["mobile"]
    assert kinds("order 5876543210") == ["mobile"] or kinds("order 5876543210") == []
    assert kinds("PIN code 110001") == ["pincode"] and kinds("code 110001") == []
    assert kinds("A/c No: 123456789012") == ["bank_account"] and kinds("ref 123456789012") == []


def test_redact_and_types_filter():
    a = aadhaar()
    t = f"Aadhaar {a}, PAN ABCPD1234E"
    assert redact(t) == "Aadhaar [AADHAAR], PAN [PAN]"
    assert redact(t, types=["pan"]) == f"Aadhaar {a}, PAN [PAN]"
    assert redact("nothing here") == "nothing here"
    with pytest.raises(ValueError):
        scan("x", types=["ssn"])


def test_no_overlap_and_all_types_listed():
    t = f"{gstin()} {aadhaar()} ABCPD1234E"
    ms = scan(t)
    assert all(a.end <= b.start for a, b in zip(ms, ms[1:]))
    assert set(ALL_TYPES) >= {"aadhaar", "gstin", "pan", "ifsc", "upi", "mobile"}


def test_cli(tmp_path, capsys):
    f = tmp_path / "t.txt"
    f.write_text("PAN ABCPD1234E")
    assert cli.main(["scan", str(f)]) == 1
    assert json.loads(capsys.readouterr().out)[0]["type"] == "pan"
    assert cli.main(["redact", str(f)]) == 0
    assert capsys.readouterr().out == "PAN [PAN]"
    f.write_text("hello")
    assert cli.main(["scan", str(f)]) == 0
