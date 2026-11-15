"""Read the small set of static NDiplomacy constants used by peace rules.

Numeric table values and dotted numeric assignments are resolved in the
effective configuration file order. Other expressions retain unknown values.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from . import static_data as _static
from .model import canonical
from .strait_definitions import (
    DEFAULT_MAX_FILE_BYTES,
    StraitDefinitionIndex,
    _IndexState,
    _path_under,
)


PEACE_RULE_KEYS = (
    "WAR_REPARATIONS_FACTOR",
    "WAR_REPARATIONS_YEARS",
    "ANNUL_TREATIES_YEARS",
    "PO_TRADE_POWER_AMOUNT",
    "TRUCE_YEARS",
    "SCALED_TRUCE_YEARS",
    "INTEGRATE_UNION_MIN_YEARS",
    "INTEGRATE_VASSAL_MIN_YEARS",
    "DIPLOANNEX_LIBERTY_THRESHOLD",
)
_MAX_DEFINE_FILES = 2048
_MAX_TOTAL_DEFINE_BYTES = 12 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER = re.compile(r"(?:0[xX][0-9A-Fa-f]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)")


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    line: int


def _long_bracket(text: str, start: int) -> tuple[str, int] | None:
    if start >= len(text) or text[start] != "[":
        return None
    cursor = start + 1
    while cursor < len(text) and text[cursor] == "=":
        cursor += 1
    if cursor < len(text) and text[cursor] == "[":
        return text[start + 1:cursor], cursor + 1
    return None


def _lex(text: str) -> list[_Token]:
    """Tokenize enough Lua to distinguish code from comments and strings."""
    tokens: list[_Token] = []
    i, line = 0, 1
    while i < len(text):
        char = text[i]
        if char.isspace():
            if char == "\n":
                line += 1
            i += 1
            continue
        if text.startswith("--", i):
            opener = _long_bracket(text, i + 2)
            if opener is None:
                end = text.find("\n", i + 2)
                i = len(text) if end < 0 else end
                continue
            equals, body_start = opener
            closer = "]" + equals + "]"
            end = text.find(closer, body_start)
            if end < 0:
                raise ValueError("UNTERMINATED_LONG_COMMENT")
            line += text.count("\n", i, end + len(closer))
            i = end + len(closer)
            continue
        if char in "'\"":
            quote, start_line = char, line
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    if i + 1 < len(text):
                        if text[i + 1] == "\n":
                            line += 1
                        i += 2
                        continue
                if text[i] == quote:
                    i += 1
                    break
                if text[i] == "\n":
                    line += 1
                i += 1
            else:
                raise ValueError("UNTERMINATED_STRING")
            tokens.append(_Token("string", "", start_line))
            continue
        opener = _long_bracket(text, i)
        if opener is not None:
            equals, body_start = opener
            closer = "]" + equals + "]"
            end = text.find(closer, body_start)
            if end < 0:
                raise ValueError("UNTERMINATED_LONG_STRING")
            tokens.append(_Token("string", "", line))
            line += text.count("\n", i, end + len(closer))
            i = end + len(closer)
            continue
        match = _IDENTIFIER.match(text, i)
        if match:
            tokens.append(_Token("id", match.group(0), line))
            i = match.end()
            continue
        match = _NUMBER.match(text, i)
        if match:
            tokens.append(_Token("number", match.group(0), line))
            i = match.end()
            continue
        if text.startswith(("...", "..", "==", "~=", "<=", ">=", "//", "<<", ">>"), i):
            operator = next(op for op in ("...", "..", "==", "~=", "<=", ">=", "//", "<<", ">>") if text.startswith(op, i))
            tokens.append(_Token("symbol", operator, line))
            i += len(operator)
            continue
        tokens.append(_Token("symbol", char, line))
        i += 1
    return tokens


def _block_depths(tokens: Sequence[_Token]) -> list[int]:
    stack: list[str] = []
    depths: list[int] = []
    for token in tokens:
        depths.append(len(stack))
        if token.kind != "id":
            continue
        value = token.value
        if value in {"if", "function", "repeat"}:
            stack.append(value)
        elif value in {"for", "while"}:
            stack.append("loop_pending")
        elif value == "do":
            if stack and stack[-1] == "loop_pending":
                stack[-1] = "loop"
            else:
                stack.append("do")
        elif value == "until":
            if stack and stack[-1] == "repeat":
                stack.pop()
        elif value == "end":
            if stack and stack[-1] != "repeat":
                stack.pop()
    return depths


def _delimiter_depths(tokens: Sequence[_Token]) -> list[tuple[int, int, int]]:
    braces = parens = brackets = 0
    result: list[tuple[int, int, int]] = []
    for token in tokens:
        result.append((braces, parens, brackets))
        if token.kind != "symbol":
            continue
        if token.value == "{":
            braces += 1
        elif token.value == "}":
            braces = max(0, braces - 1)
        elif token.value == "(":
            parens += 1
        elif token.value == ")":
            parens = max(0, parens - 1)
        elif token.value == "[":
            brackets += 1
        elif token.value == "]":
            brackets = max(0, brackets - 1)
    return result


def _matching_brace(tokens: Sequence[_Token], start: int) -> int | None:
    if start >= len(tokens) or tokens[start].value != "{":
        return None
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].value == "{":
            depth += 1
        elif tokens[index].value == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _table_fields(tokens: Sequence[_Token], opening: int, closing: int) -> list[tuple[str, int, int]]:
    """Return direct identifier-key fields as (key, value_start, value_end)."""
    fields: list[tuple[str, int, int]] = []
    i = opening + 1
    while i < closing:
        if tokens[i].value in {",", ";"}:
            i += 1
            continue
        if tokens[i].kind == "id" and i + 1 < closing and tokens[i + 1].value == "=":
            key = tokens[i].value
            value_start = i + 2
            j = value_start
            braces = parens = brackets = 0
            while j < closing:
                value = tokens[j].value
                if value == "{":
                    braces += 1
                elif value == "}":
                    if braces == 0 and parens == 0 and brackets == 0:
                        break
                    braces -= 1
                elif value == "(":
                    parens += 1
                elif value == ")":
                    parens = max(0, parens - 1)
                elif value == "[":
                    brackets += 1
                elif value == "]":
                    brackets = max(0, brackets - 1)
                elif value in {",", ";"} and braces == 0 and parens == 0 and brackets == 0:
                    break
                j += 1
            fields.append((key, value_start, j))
            i = j + 1 if j < closing and tokens[j].value in {",", ";"} else max(j, i + 1)
            continue
        # Skip an unsupported direct field without interpreting its contents.
        j = i
        braces = parens = brackets = 0
        while j < closing:
            value = tokens[j].value
            if value == "{":
                braces += 1
            elif value == "}":
                if braces == 0 and parens == 0 and brackets == 0:
                    break
                braces -= 1
            elif value == "(":
                parens += 1
            elif value == ")":
                parens = max(0, parens - 1)
            elif value == "[":
                brackets += 1
            elif value == "]":
                brackets = max(0, brackets - 1)
            elif value in {",", ";"} and braces == 0 and parens == 0 and brackets == 0:
                break
            j += 1
        i = j + 1 if j < closing else closing
    return fields


def _number_literal(tokens: Sequence[_Token], start: int, end: int) -> tuple[int | float | None, str | None]:
    if start >= end:
        return None, "empty numeric assignment"
    sign = 1
    if tokens[start].value in {"+", "-"}:
        sign = -1 if tokens[start].value == "-" else 1
        start += 1
    if start >= end or start + 1 != end or tokens[start].kind != "number":
        return None, "assignment is not a single numeric literal"
    raw = tokens[start].value
    try:
        if raw.lower().startswith("0x"):
            value: int | float = int(raw, 16)
        elif any(char in raw for char in ".eE"):
            value = float(raw)
        else:
            value = int(raw, 10)
        value *= sign
    except (ValueError, OverflowError):
        return None, "numeric literal is invalid"
    if isinstance(value, float) and not math.isfinite(value):
        return None, "numeric literal is not finite"
    return value, None


def _dotted_rhs_end(tokens: Sequence[_Token], start: int) -> int:
    """Find the end of a dotted assignment expression conservatively."""
    if start >= len(tokens):
        return start
    first_line = tokens[start].line
    depth = 0
    for index in range(start, len(tokens)):
        token = tokens[index]
        if index > start and depth == 0 and token.line > first_line:
            return index
        if token.value in {"(", "{", "["}:
            depth += 1
        elif token.value in {")", "}", "]"}:
            if depth == 0:
                return index
            depth -= 1
        elif token.value == ";" and depth == 0:
            return index
    return len(tokens)


class PeaceRuleIndex:
    """Expose effective static values for the P06 peace-rule constants."""

    def __init__(
        self,
        game_root: str | Path | None = None,
        user_data: str | Path | None = None,
        enabled_mods: Sequence[str | Path | Mapping[str, Any]] | None = None,
        *,
        keys: Sequence[str] = PEACE_RULE_KEYS,
    ) -> None:
        if isinstance(keys, str) or not keys or any(
                not isinstance(key, str) or _IDENTIFIER.fullmatch(key) is None for key in keys):
            raise ValueError("keys must contain NDiplomacy constant names")
        self.keys = tuple(dict.fromkeys(keys))
        # Reuse the version and mod-layer resolver for the selected defines files.
        self._stack = object.__new__(StraitDefinitionIndex)
        self._stack.game_root = (
            Path(game_root) if game_root is not None
            else _static.StaticTradeSource._configured_path("game_root")
        )
        self._stack.user_data = (
            Path(user_data) if user_data is not None
            else _static.StaticTradeSource._configured_path("user_data")
        )
        self._stack._explicit_enabled_mods = enabled_mods is not None
        if enabled_mods is None:
            self._stack.enabled_mods = None
        elif isinstance(enabled_mods, (str, Path)):
            self._stack.enabled_mods = [enabled_mods]
        else:
            self._stack.enabled_mods = list(enabled_mods)
        self._stack.max_file_bytes = DEFAULT_MAX_FILE_BYTES
        self._stack._state = _IndexState(compatibility=_static._StaticState())
        self._stack._load_version()
        self._stack._load_mods()

    @staticmethod
    def _reason(code: str, message: str) -> dict[str, str]:
        return {"code": code, "message": message}

    def _effective_files(self, *, directory_path='common/defines', suffix='.lua',
                         root_path='common/defines.lua') -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        resolved: dict[str, dict[str, Any]] = {}
        failures: list[dict[str, str]] = []
        for layer_index, layer in enumerate(self._stack._state.layers):
            current: dict[str, dict[str, Any]] = {}
            try:
                root_file = self._stack._safe_candidate(layer, root_path) if root_path else None
                if root_file is not None and root_file.exists():
                    if not root_file.is_file():
                        failures.append(self._reason("DEFINE_PATH_NOT_FILE", str(root_file)))
                    else:
                        current[root_path] = {
                            "relative": root_path, "path": root_file,
                            "source_kind": layer.kind, "source": layer.source,
                            "layer_index": layer_index,
                        }
                directory = self._stack._safe_candidate(layer, directory_path)
                if directory.exists():
                    if not directory.is_dir():
                        failures.append(self._reason("DEFINE_PATH_NOT_DIRECTORY", str(directory)))
                    else:
                        entries = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
                        for entry in entries:
                            if entry.suffix.casefold() != suffix or not entry.is_file():
                                continue
                            relative = f"{directory_path}/{entry.name}"
                            candidate = self._stack._safe_candidate(layer, relative)
                            current[relative.casefold()] = {
                                "relative": relative, "path": candidate,
                                "source_kind": layer.kind, "source": layer.source,
                                "layer_index": layer_index,
                            }
            except Exception as exc:
                failures.append(self._reason("DEFINE_DIRECTORY_UNAVAILABLE", str(exc)))
            if layer_index:
                for replace_path in layer.replace_paths:
                    for key in list(resolved):
                        if _path_under(resolved[key]["relative"], replace_path):
                            del resolved[key]
            resolved.update(current)
            if len(resolved) > _MAX_DEFINE_FILES:
                failures.append(self._reason(
                    "DEFINE_FILE_COUNT_LIMIT", f"effective defines files exceed {_MAX_DEFINE_FILES}"
                ))
                break
        files = list(resolved.values())
        files.sort(key=lambda item: (
            0 if root_path and item["relative"].casefold() == root_path.casefold() else 1,
            item["relative"].casefold(),
            item["relative"],
        ))
        return files, failures

    @staticmethod
    def _set_unknown(
        values: dict[str, int | float | None],
        reasons: dict[str, dict[str, str]],
        key: str,
        code: str,
        message: str,
    ) -> None:
        values[key] = None
        reasons[key] = {"code": code, "message": message}

    def _read_root_assignment(
        self,
        tokens: Sequence[_Token],
        opening: int,
        closing: int,
        values: dict[str, int | float | None],
        reasons: dict[str, dict[str, str]],
        relative: str,
        conditional: bool,
    ) -> None:
        for key in self.keys:
            self._set_unknown(values, reasons, key, "DEFINE_NOT_FOUND", f"{key} is absent from the latest NDefines table")
        if conditional:
            for key in self.keys:
                self._set_unknown(values, reasons, key, "CONDITIONAL_ASSIGNMENT", f"conditional NDefines assignment in {relative}")
            return
        if opening >= closing or tokens[opening].value != "{" or _matching_brace(tokens, opening) != closing:
            for key in self.keys:
                self._set_unknown(values, reasons, key, "UNSUPPORTED_NDEFINES_SHAPE", f"NDefines assignment in {relative} is not a literal table")
            return
        diplomacy_fields = [field for field in _table_fields(tokens, opening, closing) if field[0] == "NDiplomacy"]
        for _name, value_start, value_end in diplomacy_fields:
            for key in self.keys:
                self._set_unknown(values, reasons, key, "DEFINE_NOT_FOUND", f"{key} is absent from the latest NDiplomacy table")
            if value_start >= value_end or tokens[value_start].value != "{":
                for key in self.keys:
                    self._set_unknown(values, reasons, key, "UNSUPPORTED_NDIPLOMACY_SHAPE", f"NDiplomacy in {relative} is not a literal table")
                continue
            diplomacy_end = _matching_brace(tokens, value_start)
            if diplomacy_end is None or diplomacy_end + 1 > value_end:
                for key in self.keys:
                    self._set_unknown(values, reasons, key, "UNSUPPORTED_NDIPLOMACY_SHAPE", f"NDiplomacy table in {relative} is malformed")
                continue
            for field_name, rhs_start, rhs_end in _table_fields(tokens, value_start, diplomacy_end):
                if field_name not in values:
                    continue
                literal, error = _number_literal(tokens, rhs_start, rhs_end)
                if error:
                    self._set_unknown(values, reasons, field_name, "DEFINE_EXPRESSION_UNSUPPORTED", f"{field_name} in {relative}: {error}")
                else:
                    values[field_name] = literal
                    reasons.pop(field_name, None)

    def _parse_file(
        self,
        raw: bytes,
        relative: str,
        values: dict[str, int | float | None],
        reasons: dict[str, dict[str, str]],
    ) -> None:
        text = raw.decode("utf-8-sig")
        tokens = _lex(text)
        block_depths = _block_depths(tokens)
        delimiter_depths = _delimiter_depths(tokens)
        count = len(tokens)
        for index in range(count):
            token = tokens[index]
            if token.kind != "id" or token.value != "NDefines":
                continue
            if index and tokens[index - 1].value in {".", ":", "local"}:
                continue
            if delimiter_depths[index] != (0, 0, 0):
                continue
            if index + 1 < count and tokens[index + 1].value == "=" and (index + 2 >= count or tokens[index + 2].value != "."):
                start = index + 2
                if start < count and tokens[start].value == "{":
                    closing = _matching_brace(tokens, start)
                    if closing is None:
                        self._read_root_assignment(tokens, start, count, values, reasons, relative, block_depths[index] > 0)
                    else:
                        self._read_root_assignment(tokens, start, closing, values, reasons, relative, block_depths[index] > 0)
                else:
                    for key in self.keys:
                        self._set_unknown(values, reasons, key, "UNSUPPORTED_NDEFINES_SHAPE", f"NDefines assignment in {relative} is not a literal table")
                continue
            if index + 3 < count and [tokens[index + offset].value for offset in (1, 2, 3)] == [".", "NDiplomacy", "="]:
                for key in self.keys:
                    self._set_unknown(values, reasons, key, "UNSUPPORTED_NDIPLOMACY_SHAPE", f"NDiplomacy replacement in {relative} is not a supported direct constant assignment")
                continue
            if index + 5 >= count:
                continue
            if not (
                tokens[index + 1].value == "."
                and tokens[index + 2].kind == "id" and tokens[index + 2].value == "NDiplomacy"
                and tokens[index + 3].value == "."
                and tokens[index + 4].kind == "id" and tokens[index + 4].value in values
                and tokens[index + 5].value == "="
            ):
                continue
            key = tokens[index + 4].value
            rhs_start = index + 6
            if block_depths[index] > 0:
                self._set_unknown(values, reasons, key, "CONDITIONAL_ASSIGNMENT", f"{key} is assigned inside control flow in {relative}")
                continue
            rhs_end = _dotted_rhs_end(tokens, rhs_start)
            literal, error = _number_literal(tokens, rhs_start, rhs_end)
            if error:
                self._set_unknown(values, reasons, key, "DEFINE_EXPRESSION_UNSUPPORTED", f"{key} in {relative}: {error}")
            else:
                values[key] = literal
                reasons.pop(key, None)

    def read(self) -> dict[str, Any]:
        values: dict[str, int | float | None] = {key: None for key in self.keys}
        reasons: dict[str, dict[str, str]] = {
            key: self._reason("DEFINE_NOT_FOUND", f"no effective numeric definition was found for {key}")
            for key in self.keys
        }
        state = self._stack._state
        compat = state.compatibility
        config_files = [dict(item) for item in compat.configuration_files]
        enabled_mods = [{
            "descriptor": str(item.descriptor),
            "descriptor_sha256": item.descriptor_sha256,
            "name": item.name,
            "root": item.root_label,
            "replace_paths": list(item.replace_paths),
        } for item in state.mods]
        configuration_sha256 = hashlib.sha256(canonical({
            "configuration_files": config_files,
            "enabled_mods": [
                {"descriptor": str(mod.descriptor), "root": str(mod.root), "replace_paths": list(mod.replace_paths)}
                for mod in state.mods
            ],
        }).encode("utf-8")).hexdigest()
        source: dict[str, Any] = {
            "game_root": str(self._stack.game_root) if self._stack.game_root is not None else None,
            "game_version": state.game_version,
            "configuration_sha256": configuration_sha256,
            "configuration_files": config_files,
            "enabled_mods": enabled_mods,
            "definition_files": [],
        }
        files, discovery_errors = self._effective_files()
        discovery_errors = [*state.errors, *compat.errors, *discovery_errors]
        if discovery_errors:
            message = "; ".join(item["message"] for item in discovery_errors)
            for key in self.keys:
                self._set_unknown(values, reasons, key, discovery_errors[0]["code"], message)
            source["discovery_errors"] = discovery_errors
            return {"values": values, "source": source, "reasons": reasons}
        total_bytes = 0
        loaded: list[tuple[dict[str, Any], bytes]] = []
        input_errors: list[str] = []
        for item in files:
            try:
                raw = self._stack._read_bounded(item["path"], self._stack.max_file_bytes)
            except Exception as exc:
                message = f"{item['relative']}: {exc}"
                for key in self.keys:
                    self._set_unknown(values, reasons, key, "DEFINE_INPUT_UNAVAILABLE", message)
                source["definition_files"].append({
                    "relative": item["relative"], "path": str(item["path"]),
                    "source_kind": item["source_kind"], "source": item["source"],
                    "sha256": None, "error": message,
                })
                input_errors.append(message)
                continue
            total_bytes += len(raw)
            if total_bytes > _MAX_TOTAL_DEFINE_BYTES:
                message = f"selected defines input exceeds {_MAX_TOTAL_DEFINE_BYTES} bytes"
                for key in self.keys:
                    self._set_unknown(values, reasons, key, "DEFINE_TOTAL_SIZE_LIMIT", message)
                return {"values": values, "source": source, "reasons": reasons}
            digest = hashlib.sha256(raw).hexdigest()
            record = {
                "relative": item["relative"], "path": str(item["path"]),
                "source_kind": item["source_kind"], "source": item["source"],
                "bytes": len(raw), "sha256": digest,
            }
            source["definition_files"].append(record)
            loaded.append((item, raw))
        if input_errors:
            message = "; ".join(input_errors)
            for key in self.keys:
                self._set_unknown(values, reasons, key, "DEFINE_INPUT_UNAVAILABLE", message)
            return {"values": values, "source": source, "reasons": reasons}
        for item, raw in loaded:
            try:
                self._parse_file(raw, item["relative"], values, reasons)
            except (UnicodeError, ValueError) as exc:
                for key in self.keys:
                    self._set_unknown(values, reasons, key, "DEFINE_FILE_UNPARSEABLE", f"{item['relative']}: {exc}")
        source["definitions_sha256"] = hashlib.sha256(json.dumps(
            [{key: item.get(key) for key in ("relative", "source_kind", "source", "sha256")} for item in source["definition_files"]],
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        return {"values": values, "source": source, "reasons": reasons}


__all__ = ["PEACE_RULE_KEYS", "PeaceRuleIndex"]
