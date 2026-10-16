from __future__ import annotations

import logging
import re
from functools import lru_cache

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# PCRE allows \x{N}, \x{NN}, ... up to 8 hex digits for arbitrary codepoints.
# Python's re only supports \xNN, and only for 0..0xFF in byte patterns.
# CRS uses \x{...} exclusively for byte classes (\x{00}-\x{ff}), so a 1-2
# digit substitution is safe for the entire CRS corpus. Anything longer is
# left untouched on purpose: it will fail to compile and show up in logs,
# which is better than silently mangling it.
_PCRE_HEX_BRACE = re.compile(r"\\x\{([0-9A-Fa-f]{1,2})\}")


def _translate_pcre_hex_escapes(pattern: str) -> str:
    """Replace PCRE's \\x{NN} braced hex escapes with Python's \\xNN form."""
    return _PCRE_HEX_BRACE.sub(
        lambda m: "\\x" + m.group(1).zfill(2).lower(),
        pattern,
    )


def _translate_perl_regex(pattern: str) -> str:
    """Translate Perl-specific regex syntax to Python-compatible syntax.

    Args:
        pattern: Perl regex pattern

    Returns:
        Python-compatible regex pattern
    """
    # PCRE braced hex escapes: \x{ff} -> \xff
    pattern = _translate_pcre_hex_escapes(pattern)

    # Perl's \z matches end of string only (no trailing newline)
    # Python's $ matches end of string or before final newline
    # For compatibility, we translate \z to \Z (which is closer to Perl's \z)
    pattern = pattern.replace(r"\z", r"\Z")

    # Python requires inline flags (?i) (?m) etc to be at the start
    # CRS often has patterns like ^(?i)pattern which fail in Python
    # We need to move inline flags to the beginning

    # Match inline flags like (?i) (?m) (?s) (?x) or combinations (?im)
    flag_pattern = r"(\(\?[imsxauL]+\))"
    flags_match = re.search(flag_pattern, pattern)

    if flags_match and flags_match.start() > 0:
        # Flags are not at the start, move them
        flags = flags_match.group(1)
        # Remove flags from current position
        pattern_without_flags = (
            pattern[: flags_match.start()] + pattern[flags_match.end() :]
        )
        # Put flags at the beginning
        pattern = flags + pattern_without_flags

    return pattern


# CRS has ~600 unique regex patterns; the old 128-entry cache thrashes
# during a full load and re-compiles the same patterns repeatedly.
@lru_cache(maxsize=None)
def compile_regex(pattern: str) -> re.Pattern:
    """Compile a regex pattern with Perl compatibility translation.

    Args:
        pattern: Regex pattern (may contain Perl-specific syntax)

    Returns:
        Compiled regex pattern object
    """
    logging.debug("Compiling regex: %s", pattern)

    # Translate Perl-specific syntax
    translated = _translate_perl_regex(pattern)

    if translated != pattern:
        logging.debug("Translated regex: %s", translated)

    return re.compile(translated)
