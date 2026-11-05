from bharatid import verhoeff_check_digit
from bharatid import hook


def aadhaar(prefix="23456789012"):
    return prefix + verhoeff_check_digit(prefix)


def test_mask_keeps_only_last_two():
    assert hook.mask("ABCPE1234F") == "********4F"


def test_flags_valid_ids_and_masks_output(tmp_path, capsys):
    a = aadhaar()
    f = tmp_path / "notes.txt"
    f.write_text(f"ok line\naadhaar: {a}\npan ABCPE1234F\n")
    assert hook.main([str(f)]) == 1
    out = capsys.readouterr().out
    assert "notes.txt:2: aadhaar" in out and "notes.txt:3: pan" in out
    assert a not in out and "ABCPE1234F" not in out      # never echoes full values


def test_clean_file_and_ignore_marker(tmp_path):
    a = aadhaar()
    clean = tmp_path / "a.txt"; clean.write_text("nothing here, 12 apples\n")
    allowed = tmp_path / "b.txt"; allowed.write_text(f"{a}  # bharatid: ignore\n")
    assert hook.main([str(clean), str(allowed)]) == 0


def test_invalid_checksum_not_flagged(tmp_path):
    a = aadhaar()
    wrong = a[:-1] + str((int(a[-1]) + 1) % 10)
    f = tmp_path / "c.txt"; f.write_text(f"{wrong}\n")
    assert hook.main([str(f)]) == 0


def test_binary_and_missing_files_skipped(tmp_path):
    b = tmp_path / "x.bin"; b.write_bytes(b"\0\1\2" + aadhaar().encode())
    assert hook.main([str(b), str(tmp_path / "missing.txt")]) == 0


def test_types_option(tmp_path):
    f = tmp_path / "d.txt"; f.write_text("ABCPE1234F\n")
    assert hook.main(["--types", "aadhaar", str(f)]) == 0
    assert hook.main(["--types", "pan", str(f)]) == 1
