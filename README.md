# bharatid

Detect, validate and redact **Indian identifiers** in text. Zero dependencies, pure Python 3.9+.
Built for LLM guardrails, log scrubbing and data-loss prevention, where a bare regex for "12 digits"
or "5 letters, 4 digits, 1 letter" flags far too much.

| Identifier | Check | Notes |
|---|---|---|
| Aadhaar | **Verhoeff checksum** + first digit 2-9 | rejects ~90% of random 12-digit numbers |
| GSTIN | **Base-36 checksum** + valid state code + valid embedded PAN | beats the PAN inside it when both match |
| PAN | structure (4th letter = entity type) | no public checksum |
| TAN, IFSC, EPIC (voter ID), passport | structure | IFSC bank/branch not looked up |
| Driving licence | structure + RTO state code + year 1950-2035 | |
| Vehicle plate | structure + RTO state code (incl. Bharat series) | |
| UPI ID | `handle@psp` with a known PSP handle | ordinary emails are not matched |
| Mobile | 10 digits starting 6-9, optional +91 / 0 | |
| PIN code, bank account | **only with a cue word** ("PIN code", "A/c no") | bare 6- or 12-digit numbers are ignored |

**Related project:** the PyPI package `indic-pii` (by a different author) also detects Indian PII, with
confidence scores and optional spaCy NER for names. `bharatid` is a different design: zero
dependencies, checksum-first validation (Aadhaar, GSTIN), and extra identifiers (GSTIN, TAN, vehicle
plates). Pick whichever fits; they are not drop-in compatible.

"Valid" means well-formed (and checksum-correct where a checksum exists). It does **not** mean the
number was issued to anyone.

## Install and use

```bash
pip install bharatid
```

```python
from bharatid import scan, redact, is_valid_aadhaar, is_valid_gstin

text = "Aadhaar 2345 6789 0124, PAN ABCPD1234E, call +91 98765 43210"
for m in scan(text):
    print(m.type, m.text, m.validated)      # validated=True when a checksum confirmed it

redact(text)          # 'Aadhaar [AADHAAR], PAN [PAN], call [MOBILE]'
redact(text, types=["aadhaar"])
is_valid_gstin("27AAPFU0939F1ZV")           # True
```

CLI: `echo "PAN ABCPD1234E" | bharatid scan` (exit code 1 when something is found), `bharatid redact FILE`.

## How well does it avoid false alarms?

On 15,140 real, mostly English LLM prompts (public in-the-wild jailbreak dataset, MIT licence), it
produced 10 matches in total (8 mobile, 1 voter-ID-shaped, 1 Aadhaar-valid). The data has no PII labels,
so this is a false-alarm sanity check, not a precision measurement. Reproduce with
`scripts/fp_sanity.py`.

## Limits

- Format and checksum validation cannot tell a real identifier from a coincidentally valid one.
- Mobile-number and voter-ID shapes are common in unrelated text.
- No names, addresses or free-text detection. Pair it with an NER tool if you need those.
- Not legal advice or a compliance guarantee. Test on your own data.

MIT licensed.
