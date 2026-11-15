"""Project copied message inputs without claiming a rendered battle window."""
from __future__ import annotations

from bridge.native_text import decode_native_text_hex


def project_template(decoded: dict) -> dict:
    message = decoded.get("message_template")
    if message is None:
        captured_version = decoded.get("wire", {}).get("version", 0) >= 4
        return {
            "status": "unknown" if captured_version else "unsupported",
            "reason": ("MESSAGE_TEMPLATE_CAPTURE_UNAVAILABLE" if captured_version
                       else "MESSAGE_TEMPLATE_NOT_CAPTURED"),
        }

    def text(raw_hex: str, limit: int) -> dict:
        try:
            value = decode_native_text_hex(raw_hex, codec="eu4_escape", max_bytes=limit)
        except (ValueError, UnicodeError):
            return {"status": "unknown", "reason": "BATTLE_TEXT_DECODE_FAILED"}
        return {"status": "known", "value": value}

    if message.get("source_kind") == "formatter_container_before_cleanup":
        # The formatter container is captured before message cleanup and has
        # only the ordered linked key/value pairs.  It does not contain the
        # message date, message flags, or auxiliary text; keep those inputs
        # explicitly unavailable instead of treating zero/empty as evidence.
        pairs = [dict(pair, index=index,
                      key=text(pair["key_raw_hex"], 128),
                      value=text(pair["value_raw_hex"], 8192))
                 for index, pair in enumerate(message["pairs"])]
        return {"status": "known", "value": {
            "source_kind": "formatter_container_before_cleanup",
            "message_metadata_present": False,
            "native_date": None,
            "raw_flag_8c": None,
            "raw_flag_8d": None,
            "raw_container_word_10": message["raw_container_word_10"],
            "raw_container_flag_14": message["raw_container_flag_14"],
            "pair_count": message["pair_count"],
            "pairs": pairs,
            "auxiliary_text": {
                "status": "unsupported",
                "reason": "MESSAGE_METADATA_NOT_CAPTURED",
            },
            "basis": "copied_native_formatter_container_before_cleanup",
            "full_display_complete": False,
            "runtime_popup_verified": False,
        }}

    if message["native_date"] != decoded["observation"]["result"]["raw_date"]:
        return {"status": "unknown", "reason": "MESSAGE_TEMPLATE_DATE_MISMATCH"}

    # A list preserves insertion order and duplicate keys.  The copied values
    # are inputs to the native window formatter, not a concatenated raw_text.
    pairs = [dict(pair, index=index,
                  key=text(pair["key_raw_hex"], 128),
                  value=text(pair["value_raw_hex"], 8192))
             for index, pair in enumerate(message["pairs"])]
    return {"status": "known", "value": {
        "native_date": message["native_date"],
        "raw_flag_8c": message["raw_flag_8c"],
        "raw_flag_8d": message["raw_flag_8d"],
        "raw_header_word_20": message["raw_header_word_20"],
        "raw_header_flag_24": message["raw_header_flag_24"],
        "pair_count": message["pair_count"],
        "pairs": pairs,
        "auxiliary_text": {
            "raw_hex": message["auxiliary_text_hex"],
            "decoded": text(message["auxiliary_text_hex"], 8192),
        },
        "basis": "copied_native_message_template_inputs",
        "full_display_complete": False,
        "runtime_popup_verified": False,
    }}
