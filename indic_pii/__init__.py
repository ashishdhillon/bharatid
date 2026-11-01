"""indic-pii: detect and validate Indian identifiers (Aadhaar, PAN, GSTIN, IFSC, UPI, ...)."""
from .detect import ALL_TYPES, Match, redact, scan
from .validators import (is_valid_aadhaar, is_valid_driving_licence, is_valid_epic, is_valid_gstin,
                         is_valid_ifsc, is_valid_pan, is_valid_passport, is_valid_tan, is_valid_upi,
                         is_valid_vehicle_plate, gstin_check_char, verhoeff_check_digit, verhoeff_valid)

__version__ = "0.1.0"
__all__ = ["scan", "redact", "Match", "ALL_TYPES", "is_valid_aadhaar", "is_valid_gstin", "is_valid_pan",
           "is_valid_tan", "is_valid_ifsc", "is_valid_epic", "is_valid_passport", "is_valid_upi",
           "is_valid_vehicle_plate", "is_valid_driving_licence", "gstin_check_char", "verhoeff_check_digit",
           "verhoeff_valid"]
