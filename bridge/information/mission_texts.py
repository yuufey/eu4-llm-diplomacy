"""Decode captured localization bytes without pretending to evaluate scripts."""
from __future__ import annotations

import re

from bridge.native_text import decode_native_text, validate_native_text_codec

MAX_TEMPLATE_BYTES = 8192
_TOKENS = re.compile(r"\[[^\]\r\n]{1,256}\]|\$[^$\r\n]{1,256}\$")


def decode_template(value_hex, codec):
    """Return a literal value or an explicitly unresolved native template.

    The codec is supplied by the operator session. Dollar parameters and
    bracket expressions have later engine evaluation stages; marker-bearing
    text remains unresolved even when it does not match a recognized token.
    """
    validate_native_text_codec(codec)
    if (not isinstance(value_hex, str) or len(value_hex) > MAX_TEMPLATE_BYTES*2
            or len(value_hex)%2 or re.fullmatch(r"[0-9a-fA-F]*",value_hex) is None):
        return {"status":"unknown", "reason":"LOCALIZATION_BYTES_INVALID"}
    raw=bytes.fromhex(value_hex)
    try:
        text=decode_native_text(raw,codec,max_bytes=MAX_TEMPLATE_BYTES,max_bytes_limit=MAX_TEMPLATE_BYTES)
    except ValueError:
        return {"status":"unknown", "reason":"LOCALIZATION_TEXT_DECODE_FAILED", "raw_template_hex":value_hex, "codec":codec}
    result={"raw_template_hex":value_hex, "codec":codec, "dynamic_substitution_evaluated":False}
    if any(marker in text for marker in "[]$"):
        result.update(status="unknown",reason="DYNAMIC_LOCALIZATION_UNRESOLVED",template=text,
                      unresolved_tokens=list(dict.fromkeys(_TOKENS.findall(text))),
                      unresolved_markers=[marker for marker in "[]$" if marker in text])
    else:
        result.update(status="known",text=text)
    return result
