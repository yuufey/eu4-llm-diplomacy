"""Explicit codecs and incomplete script syntax must not create display text."""
import pytest

from bridge.information.mission_texts import decode_template


def test_native_chinese_escape_sample_and_empty_value():
    decoded=decode_template("10e389103e6510fa8b10fc6610955e","eu4_escape")
    assert decoded["status"] == "known" and decoded["text"] == "解放诺曼底"
    assert decode_template("","eu4_escape")["text"] == ""


def test_wrong_codec_is_not_guessed_from_native_bytes():
    assert decode_template("10e389103e6510fa8b10fc6610955e","utf8")["reason"] == "LOCALIZATION_TEXT_DECODE_FAILED"
    with pytest.raises(ValueError):
        decode_template("4142",None)


@pytest.mark.parametrize("value", ["[Root.GetName]","$COUNTRY$","unfinished [Root.GetName","dollar $","empty []"])
def test_substitutions_and_unbalanced_markers_keep_templates_unknown(value):
    result=decode_template(value.encode().hex(),"utf8")
    assert result["status"] == "unknown" and "text" not in result
    assert result["template"] == value


@pytest.mark.parametrize("raw", ["0","xx",None,"00ff","10e3"])
def test_bad_hex_embedded_nul_or_truncated_escape_never_yields_text(raw):
    assert decode_template(raw,"eu4_escape")["status"] == "unknown"


def test_formatting_bytes_are_retained_as_native_text():
    result=decode_template("§YName§! £adm£".encode().hex(),"utf8")
    assert result["status"] == "known" and result["text"] == "§YName§! £adm£"
