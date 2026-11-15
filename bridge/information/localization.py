"""Bounded, explicit-codec index of EU4 localisation files.

The index is a static file reader.  It reuses :class:`MissionDefinitionIndex`
for the verified game version, enabled-mod configuration and ``replace_path``
records, but it does not read a running game or infer the active UI language.
Callers must supply both the language header (for example ``l_english``) and
the value codec.  A later enabled layer is selected only when that ordered
configuration is available; same-layer duplicates remain unknown.

The file payload is retained as bounded text and provenance, never as a full
raw-file cache.  Every lookup rechecks the relevant file/configuration hashes
and directory memberships.  A changed source makes the current lookup
unavailable and never returns the previous cached value.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from bridge.native_text import EU4_ESCAPE_CODEC, decode_native_text

from .mission_definitions import MissionDefinitionIndex
from .model import InformationError, canonical


LOCALISATION_RELATIVE = "localisation"
SUPPORTED_VERSIONS = ("1.37.4",)
ENCODING_UTF8 = "utf8"
ENCODING_EU4_ESCAPE_CP1252 = "eu4_escape_cp1252"
SUPPORTED_ENCODINGS = (ENCODING_UTF8, ENCODING_EU4_ESCAPE_CP1252)

DEFAULT_MAX_FILE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024
DEFAULT_MAX_FILES = 4096
MAX_LINE_BYTES = 1024 * 1024
MAX_KEY_CHARS = 256
MAX_VALUE_BYTES = 8192
MAX_QUERY_KEYS = 4096
MAX_DYNAMIC_TOKEN_CHARS = 256
MAX_DYNAMIC_TOKENS = 256

_LANGUAGE_RE = re.compile(r"l_[A-Za-z0-9_]+\Z")
_HEADER_RE = re.compile(r"^\s*(?P<header>l_[A-Za-z0-9_]+)\s*:\s*(?:#.*)?\Z")
_ENTRY_PREFIX_RE = re.compile(
    r"^\s*(?P<key>[^\s:#{}=]+)\s*:\s*"
    r"(?:(?P<version>[+-]?\d+)\s+)?(?P<quote>\")"
)


def _error(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _hash_file(path: Path, limit: int) -> tuple[str, int]:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"file exceeds {limit} bytes: {path} ({size})")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(chunk)
            if total > limit:
                raise ValueError(f"file exceeds {limit} bytes: {path}")
            digest.update(chunk)
    return digest.hexdigest(), total


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _normalise_relative(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("relative path must be a string")
    text = value.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if not text or text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise ValueError(f"absolute or empty relative path: {value!r}")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"path escape or empty component: {value!r}")
    return "/".join(parts)


def _under(relative: str, prefix: str) -> bool:
    return not prefix or relative == prefix or relative.startswith(prefix + "/")


def _localisation_replace_prefix(value: str) -> str | None:
    """Return a safe path below ``localisation``, or ``None`` for other paths."""

    text = value.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    if text == LOCALISATION_RELATIVE:
        return ""
    if text.startswith(LOCALISATION_RELATIVE + "/"):
        remainder = text[len(LOCALISATION_RELATIVE) + 1:]
        return _normalise_relative(remainder)
    # Reject an escape-looking replace_path even when it is not a localisation
    # path.  Silent path traversal would make the static scope ambiguous.
    if ".." in text.split("/"):
        raise ValueError(f"replace_path escapes its declared root: {value!r}")
    return None


def _directory_members(directory: Path, root: Path, max_members: int) -> tuple[str, ...] | None:
    """Return a bounded recursive member manifest, including directories."""

    if not directory.exists():
        return None
    if not directory.is_dir() or not _is_under(directory, root):
        raise ValueError(f"localisation directory escapes layer root: {directory}")
    members: list[str] = []
    for item in directory.rglob("*"):
        if len(members) >= max_members:
            raise ValueError(f"directory has more than {max_members} members: {directory}")
        relative = item.relative_to(directory).as_posix()
        _normalise_relative(relative)
        if item.is_symlink():
            target = item.resolve(strict=False)
            if not _is_under(target, root):
                raise ValueError(f"localisation member escapes layer root: {item}")
        members.append(relative)
    return tuple(sorted(members))


def _scan_dynamic_tokens(value: str) -> tuple[list[str], list[str]]:
    """Find dynamic placeholders and malformed marker fragments.

    EU4 localisation can defer replacement with either a bracketed scope
    expression (``[Root.GetName]``) or a dollar token (``$NAME$``).  The
    index deliberately does not interpret either expression.  A marker with
    no matching terminator is retained as an unresolved fragment so callers
    cannot mistake a truncated template for a static value.
    """

    tokens: list[str] = []
    malformed: list[str] = []

    def add_unique(target: list[str], value: str) -> None:
        if len(target) < MAX_DYNAMIC_TOKENS and value not in target:
            target.append(value)

    cursor = 0
    while cursor < len(value):
        marker = value[cursor]
        if marker == "[":
            close = value.find("]", cursor + 1)
            if close < 0:
                add_unique(malformed, value[cursor:cursor + MAX_DYNAMIC_TOKEN_CHARS + 1])
                cursor += 1
                continue
            body = value[cursor + 1:close]
            token = value[cursor:close + 1]
            if (
                not body
                or len(body) > MAX_DYNAMIC_TOKEN_CHARS
                or "[" in body
                or "\r" in body
                or "\n" in body
            ):
                add_unique(malformed, token[:MAX_DYNAMIC_TOKEN_CHARS + 2])
            else:
                add_unique(tokens, token)
            cursor = close + 1
            continue
        if marker == "]":
            add_unique(malformed, marker)
            cursor += 1
            continue
        if marker == "$":
            close = value.find("$", cursor + 1)
            if close < 0:
                add_unique(malformed, value[cursor:cursor + MAX_DYNAMIC_TOKEN_CHARS + 1])
                cursor += 1
                continue
            body = value[cursor + 1:close]
            token = value[cursor:close + 1]
            if (
                not body
                or len(body) > MAX_DYNAMIC_TOKEN_CHARS
                or "\r" in body
                or "\n" in body
            ):
                add_unique(malformed, token[:MAX_DYNAMIC_TOKEN_CHARS + 2])
            else:
                add_unique(tokens, token)
            cursor = close + 1
            continue
        cursor += 1

    return tokens[:MAX_DYNAMIC_TOKENS], malformed[:MAX_DYNAMIC_TOKENS]


def _dynamic_tokens(value: str) -> list[str]:
    """Return valid, uninterpreted ``[...]`` and ``$...$`` placeholders."""

    return _scan_dynamic_tokens(value)[0]


def _cp1252_bytes(value: str) -> bytes:
    """Encode the observed UTF-8-file representation used by EU4 escapes.

    CP1252 leaves C1 code points undefined.  The game localisation files in
    the verified Chinese stack contain those code points after UTF-8 decoding;
    the original byte ordinal is therefore retained for 0x80..0x9f.  Other
    unrepresentable characters fail closed instead of being transliterated.
    """

    output = bytearray()
    for char in value:
        codepoint = ord(char)
        if 0x80 <= codepoint <= 0x9F:
            output.append(codepoint)
            continue
        try:
            encoded = char.encode("cp1252")
        except UnicodeEncodeError as exc:
            raise ValueError(f"value contains a character not representable in cp1252: U+{codepoint:04X}") from exc
        output.extend(encoded)
    return bytes(output)


def _decode_value(value: str, encoding: str) -> str:
    if encoding == ENCODING_UTF8:
        # The file parser already performed strict UTF-8 decoding.  Re-encode
        # and decode once more to make the explicit value contract visible.
        return value.encode("utf-8", errors="strict").decode("utf-8", errors="strict")
    if encoding == ENCODING_EU4_ESCAPE_CP1252:
        return decode_native_text(
            _cp1252_bytes(value), EU4_ESCAPE_CODEC,
            max_bytes=MAX_VALUE_BYTES, max_bytes_limit=MAX_VALUE_BYTES,
        )
    raise ValueError(f"unsupported localisation value encoding: {encoding!r}")


def _parse_quoted_value(line: str, start: int) -> tuple[str, int] | None:
    """Return raw value and closing-quote position for a bounded line.

    Clausewitz localisation data in the shipped files occasionally contains a
    literal, unescaped quote inside a value.  The parser therefore chooses the
    final unescaped quote whose suffix is only whitespace or a comment, while
    still treating ``\"`` as part of the value.
    """

    candidates: list[int] = []
    cursor = start
    while cursor < len(line):
        if line[cursor] == "\\":
            cursor += 2
            continue
        if line[cursor] == '"':
            candidates.append(cursor)
        cursor += 1
    for close in reversed(candidates):
        trailing = line[close + 1:].strip()
        if not trailing or trailing.startswith("#"):
            return line[start:close], close
    return None


@dataclass
class _LocalisationEntry:
    key: str
    raw_value: str
    raw_line: str
    line: int
    version: str | None
    language: str
    language_header_line: int
    line_sha256: str
    file_relative: str
    file_path: Path
    file_sha256: str
    file_size: int
    layer: str
    layer_order: int
    source_kind: str
    source_label: str
    dynamic_tokens: tuple[str, ...] = ()
    malformed_dynamic_markers: tuple[str, ...] = ()


@dataclass
class _LocalisationFile:
    relative: str
    path: Path
    layer: str
    layer_order: int
    source_kind: str
    source_label: str
    sha256: str
    size: int
    entries: list[_LocalisationEntry] = field(default_factory=list)
    language_headers: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _Layer:
    name: str
    order: int
    root: Path
    directory: Path
    source_kind: str
    source_label: str
    replace_paths: tuple[str, ...]
    directory_members: tuple[str, ...] | None = None
    files: list[_LocalisationFile] = field(default_factory=list)


class LocalizationIndex:
    """Read a bounded, statically resolved localisation index.

    ``lookup`` returns raw provenance and an explicit value status.  It never
    substitutes dynamic tokens.  ``eu4_escape_cp1252`` is a caller-selected
    codec for the UTF-8 file representation observed in the enabled Chinese
    stack; it is not inferred from bytes.
    """

    def __init__(
        self,
        game_root: str | Path | None = None,
        user_data: str | Path | None = None,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> None:
        for name, value in (
            ("max_file_bytes", max_file_bytes),
            ("max_total_bytes", max_total_bytes),
            ("max_files", max_files),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_files = max_files
        # Localisation uses only version and mod/replace_path configuration.
        # A full mission AST can be hundreds of MB and has no role in looking
        # up text keys. Keep only its small configuration manifest here.
        configuration = MissionDefinitionIndex(game_root, user_data, load_definitions=False)
        self._mission_context = configuration.context()
        self.game_root = Path(game_root) if game_root is not None else None
        self.user_data = Path(user_data) if user_data is not None else None
        self._fatal_errors: list[dict[str, str]] = []
        self._warnings: list[dict[str, str]] = []
        self._tracked_config: dict[Path, str | None] = {}
        self._layers: list[_Layer] = []
        self._effective_files: dict[str, _LocalisationFile] = {}
        self._entries: dict[tuple[str, str], list[_LocalisationEntry]] = {}
        self._same_layer_duplicates: dict[tuple[str, str], list[_LocalisationEntry]] = {}
        self._total_bytes = 0
        self._total_file_count = 0
        self._build()

    def _record_fatal(self, code: str, message: str) -> None:
        if not any(item.get("code") == code and item.get("message") == message for item in self._fatal_errors):
            self._fatal_errors.append(_error(code, message))

    def _mission_value_path(self, name: str) -> Path | None:
        value = self._mission_context.get(name)
        return Path(value) if isinstance(value, str) and value else None

    def _build(self) -> None:
        # The static mission index has a wider scope than localisation.  Only
        # configuration/version/mod-stack failures make this source unusable;
        # missing mission definitions themselves do not hide a valid
        # localisation directory in a fixture or installation.
        relevant_codes = {
            "GAME_ROOT_UNAVAILABLE", "GAME_VERSION_UNAVAILABLE",
            "UNSUPPORTED_GAME_VERSION", "ENABLED_MOD_CONFIG_UNAVAILABLE",
            "ENABLED_MOD_CONFIG_INVALID", "ENABLED_MOD_UNSUPPORTED",
        }
        for reason in self._mission_context.get("reasons", []):
            if isinstance(reason, Mapping) and reason.get("code") in relevant_codes:
                self._record_fatal(str(reason["code"]), str(reason.get("message", "")))
        if self.game_root is None:
            self.game_root = self._mission_value_path("game_root")
        if self.user_data is None:
            self.user_data = self._mission_value_path("user_data")
        if self.game_root is None:
            self._record_fatal("GAME_ROOT_UNAVAILABLE", "EU4 game root is not configured")
            return
        if self._mission_context.get("game_version") not in SUPPORTED_VERSIONS:
            self._record_fatal(
                "UNSUPPORTED_GAME_VERSION",
                f"localisation is verified for {SUPPORTED_VERSIONS}, got {self._mission_context.get('game_version')!r}",
            )
        configuration = self._mission_context.get("configuration_files", [])
        if not isinstance(configuration, list):
            self._record_fatal("CONFIGURATION_UNAVAILABLE", "MissionDefinitionIndex returned no configuration manifest")
        else:
            for item in configuration:
                if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
                    self._record_fatal("CONFIGURATION_UNAVAILABLE", "invalid configuration manifest entry")
                    continue
                self._tracked_config[Path(item["path"])] = item.get("sha256") if isinstance(item.get("sha256"), str) else None

        base_root = self.game_root
        self._add_layer(
            name="basegame", order=0, root=base_root,
            source_kind="basegame", source_label="basegame", replace_paths=(),
        )
        mods = self._mission_context.get("enabled_mods", [])
        if not isinstance(mods, list):
            self._record_fatal("ENABLED_MOD_CONFIG_INVALID", "enabled_mods is not a list")
            return
        seen_mods: set[str] = set()
        for order, mod in enumerate(mods, start=1):
            if not isinstance(mod, Mapping) or not isinstance(mod.get("root"), str):
                self._record_fatal("ENABLED_MOD_UNSUPPORTED", f"invalid enabled mod record: {mod!r}")
                continue
            root = Path(str(mod["root"]))
            identity = str(root.resolve()).casefold()
            if identity in seen_mods:
                self._record_fatal("LOCALISATION_MOD_STACK_AMBIGUOUS", f"enabled mod appears more than once: {root}")
            seen_mods.add(identity)
            raw_replacements = mod.get("replace_paths", [])
            if not isinstance(raw_replacements, list):
                self._record_fatal("ENABLED_MOD_UNSUPPORTED", f"replace_paths is not a list: {root}")
                replacements: tuple[str, ...] = ()
            else:
                replacements = tuple(str(value) for value in raw_replacements)
            self._add_layer(
                name=f"enabled_mod[{order - 1}]", order=order, root=root,
                source_kind="enabled_mod", source_label=str(mod.get("descriptor") or root),
                replace_paths=replacements,
            )
        self._resolve_effective_files()

    def _add_layer(
        self, *, name: str, order: int, root: Path, source_kind: str,
        source_label: str, replace_paths: Sequence[str],
    ) -> None:
        directory = root / LOCALISATION_RELATIVE
        try:
            members = _directory_members(directory, root, self.max_files)
        except Exception as exc:
            self._record_fatal("LOCALISATION_DIRECTORY_INVALID", f"{directory}: {exc}")
            members = None
        layer = _Layer(
            name=name, order=order, root=root, directory=directory,
            source_kind=source_kind, source_label=source_label,
            replace_paths=tuple(replace_paths), directory_members=members,
        )
        self._layers.append(layer)
        if source_kind == "basegame" and members is None:
            self._record_fatal("LOCALISATION_DIRECTORY_MISSING", f"base localisation directory not found: {directory}")
            return
        if members is None:
            return
        files: list[Path] = []
        seen: set[str] = set()
        for item in sorted(directory.rglob("*"), key=lambda value: value.as_posix().casefold()):
            if not item.is_file() or item.suffix.casefold() not in {".yml", ".yaml"}:
                continue
            if item.is_symlink() and not _is_under(item.resolve(strict=False), root):
                self._record_fatal("LOCALISATION_PATH_ESCAPE", f"localisation file escapes layer root: {item}")
                continue
            try:
                relative_tail = _normalise_relative(item.relative_to(directory).as_posix())
            except Exception as exc:
                self._record_fatal("LOCALISATION_PATH_ESCAPE", f"{item}: {exc}")
                continue
            relative = f"{LOCALISATION_RELATIVE}/{relative_tail}"
            folded = relative.casefold()
            if folded in seen:
                self._record_fatal("LOCALISATION_DUPLICATE_FILE", f"duplicate localisation path: {relative}")
                continue
            seen.add(folded)
            files.append(item)
        if len(files) > self.max_files:
            self._record_fatal("LOCALISATION_FILE_LIMIT", f"layer has more than {self.max_files} localisation files: {directory}")
            files = files[:self.max_files]
        remaining = self.max_files - self._total_file_count
        if remaining < len(files):
            self._record_fatal(
                "LOCALISATION_FILE_LIMIT",
                f"localisation input has more than {self.max_files} files",
            )
            files = files[:max(remaining, 0)]
        for path in files:
            try:
                item = self._read_file(path, layer, relative=f"{LOCALISATION_RELATIVE}/{path.relative_to(directory).as_posix()}")
            except Exception as exc:
                self._record_fatal("LOCALISATION_FILE_INVALID", f"{path}: {exc}")
                continue
            layer.files.append(item)
            self._total_file_count += 1

    def _read_file(self, path: Path, layer: _Layer, *, relative: str) -> _LocalisationFile:
        digest = hashlib.sha256()
        total = 0
        entries: list[_LocalisationEntry] = []
        headers: list[dict[str, Any]] = []
        current_language: str | None = None
        current_header_line = 0
        with path.open("rb") as stream:
            line_number = 0
            while True:
                raw_line = stream.readline()
                if not raw_line:
                    break
                line_number += 1
                if len(raw_line) > MAX_LINE_BYTES:
                    raise ValueError(f"line {line_number} exceeds {MAX_LINE_BYTES} bytes")
                total += len(raw_line)
                if total > self.max_file_bytes:
                    raise ValueError(f"file exceeds {self.max_file_bytes} bytes")
                digest.update(raw_line)
                try:
                    line = raw_line.decode("utf-8-sig" if line_number == 1 else "utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError(f"invalid UTF-8 at line {line_number}") from exc
                line = line.rstrip("\r\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                header = _HEADER_RE.match(line)
                if header:
                    current_language = header.group("header")
                    current_header_line = line_number
                    headers.append({"language": current_language, "line": line_number})
                    continue
                prefix = _ENTRY_PREFIX_RE.match(line)
                if not prefix:
                    # Localisation files are a line-oriented key/value format;
                    # treating a non-comment non-header line as invalid avoids
                    # silently omitting a malformed override.
                    raise ValueError(f"unrecognised localisation line {line_number}")
                if current_language is None:
                    raise ValueError(f"entry before language header at line {line_number}")
                key = prefix.group("key")
                if len(key) > MAX_KEY_CHARS:
                    raise ValueError(f"key at line {line_number} exceeds {MAX_KEY_CHARS} characters")
                parsed = _parse_quoted_value(line, prefix.end())
                if parsed is None:
                    raise ValueError(f"unterminated quoted value at line {line_number}")
                raw_value, close = parsed
                trailing = line[close + 1:].strip()
                if trailing and not trailing.startswith("#"):
                    raise ValueError(f"unexpected text after quoted value at line {line_number}")
                if len(raw_value.encode("utf-8")) > MAX_VALUE_BYTES:
                    raise ValueError(f"value at line {line_number} exceeds {MAX_VALUE_BYTES} bytes")
                line_hash = hashlib.sha256(raw_line).hexdigest()
                dynamic_tokens, malformed_dynamic_markers = _scan_dynamic_tokens(raw_value)
                entries.append(_LocalisationEntry(
                    key=key, raw_value=raw_value, raw_line=line,
                    line=line_number, version=prefix.group("version"),
                    language=current_language, language_header_line=current_header_line,
                    line_sha256=line_hash, file_relative=relative, file_path=path,
                    file_sha256="", file_size=0, layer=layer.name,
                    layer_order=layer.order, source_kind=layer.source_kind,
                    source_label=layer.source_label,
                    dynamic_tokens=tuple(dynamic_tokens),
                    malformed_dynamic_markers=tuple(malformed_dynamic_markers),
                ))
        if total > self.max_file_bytes:
            raise ValueError(f"file exceeds {self.max_file_bytes} bytes")
        file_digest = digest.hexdigest()
        item = _LocalisationFile(
            relative=relative, path=path, layer=layer.name, layer_order=layer.order,
            source_kind=layer.source_kind, source_label=layer.source_label,
            sha256=file_digest, size=total, entries=entries,
            language_headers=headers,
        )
        for entry in entries:
            entry.file_sha256 = file_digest
            entry.file_size = total
        self._total_bytes += total
        if self._total_bytes > self.max_total_bytes:
            raise ValueError(f"localisation input exceeds {self.max_total_bytes} bytes")
        return item

    def _resolve_effective_files(self) -> None:
        resolved: dict[str, _LocalisationFile] = {}
        for layer in self._layers:
            replacements: list[str] = []
            for raw_path in layer.replace_paths:
                try:
                    prefix = _localisation_replace_prefix(raw_path)
                except Exception as exc:
                    self._record_fatal("LOCALISATION_PATH_ESCAPE", str(exc))
                    continue
                if prefix is not None:
                    replacements.append(prefix)
            for prefix in replacements:
                before = len(resolved)
                resolved = {
                    key: item for key, item in resolved.items()
                    if not _under(item.relative[len(LOCALISATION_RELATIVE) + 1:], prefix)
                }
                supplied = any(
                    _under(item.relative[len(LOCALISATION_RELATIVE) + 1:], prefix)
                    for item in layer.files
                )
                if not supplied:
                    self._record_fatal(
                        "LOCALISATION_REPLACE_PATH_EMPTY",
                        f"replace_path removed localisation files but supplied none: {raw_path}",
                    )
                elif before == len(resolved) and prefix:
                    self._warnings.append(_error(
                        "LOCALISATION_REPLACE_PATH_NO_PRIOR_FILE",
                        f"replace_path matched no earlier localisation file: {raw_path}",
                    ))
            for item in layer.files:
                resolved[item.relative.casefold()] = item
        self._effective_files = resolved
        for item in resolved.values():
            for entry in item.entries:
                self._entries.setdefault((entry.language, entry.key), []).append(entry)
        for key, entries in self._entries.items():
            by_layer: dict[str, list[_LocalisationEntry]] = {}
            for entry in entries:
                by_layer.setdefault(entry.layer, []).append(entry)
            for layer_name, candidates in by_layer.items():
                if len(candidates) > 1:
                    self._same_layer_duplicates[key] = candidates
                    self._warnings.append(_error(
                        "LOCALISATION_SAME_LAYER_DUPLICATE",
                        f"{key[0]}:{key[1]} has {len(candidates)} candidates in {layer_name}",
                    ))

    def _integrity_errors(self) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        for path, expected in self._tracked_config.items():
            if expected is None:
                if path.exists():
                    errors.append(_error("LOCALISATION_CONFIG_CHANGED", f"configuration appeared after construction: {path}"))
                continue
            try:
                actual, _size = _hash_file(path, self.max_file_bytes)
            except Exception as exc:
                errors.append(_error("LOCALISATION_CONFIG_UNAVAILABLE", f"{path}: {exc}"))
                continue
            if actual != expected:
                errors.append(_error("LOCALISATION_CONFIG_CHANGED", f"configuration changed: {path}"))
        for layer in self._layers:
            try:
                actual_members = _directory_members(layer.directory, layer.root, self.max_files)
            except Exception as exc:
                errors.append(_error("LOCALISATION_DIRECTORY_INVALID", f"{layer.directory}: {exc}"))
                continue
            if actual_members != layer.directory_members:
                errors.append(_error("LOCALISATION_DIRECTORY_CHANGED", f"directory membership changed: {layer.directory}"))
            for item in layer.files:
                try:
                    actual_hash, actual_size = _hash_file(item.path, self.max_file_bytes)
                except Exception as exc:
                    errors.append(_error("LOCALISATION_FILE_UNAVAILABLE", f"{item.path}: {exc}"))
                    continue
                if actual_hash != item.sha256 or actual_size != item.size:
                    errors.append(_error("LOCALISATION_FILE_CHANGED", f"file changed: {item.path}"))
        return errors

    def context(self) -> dict[str, Any]:
        integrity = self._integrity_errors()
        reasons = [*_copy(self._fatal_errors), *integrity]
        ready = not reasons
        return {
            "status": "ready" if ready else "unready",
            "complete": ready,
            "mode": "static",
            "context_scope": "static_localisation",
            "game_root": str(self.game_root) if self.game_root is not None else None,
            "user_data": str(self.user_data) if self.user_data is not None else None,
            "game_version": self._mission_context.get("game_version"),
            "game_version_raw": self._mission_context.get("game_version_raw"),
            "supported_versions": list(SUPPORTED_VERSIONS) if self._mission_context.get("game_version") in SUPPORTED_VERSIONS else [],
            "configuration_sha256": self._mission_context.get("configuration_sha256"),
            "config_sha256": self._mission_context.get("config_sha256"),
            "configuration_files": deepcopy(self._mission_context.get("configuration_files", [])),
            "enabled_mods": deepcopy(self._mission_context.get("enabled_mods", [])),
            "reasons": reasons,
            "warnings": deepcopy(self._warnings),
            "localisation_layers": [
                {
                    "layer": layer.name, "order": layer.order,
                    "root": str(layer.root), "directory": str(layer.directory),
                    "source_kind": layer.source_kind, "source": layer.source_label,
                    "replace_paths": list(layer.replace_paths),
                    "exists": layer.directory_members is not None,
                    "members": list(layer.directory_members or ()),
                    "files_scanned": len(layer.files),
                    "bytes_scanned": sum(item.size for item in layer.files),
                }
                for layer in self._layers
            ],
            "file_count": len(self._effective_files),
            "total_bytes": self._total_bytes,
            "limits": {
                "max_file_bytes": self.max_file_bytes,
                "max_total_bytes": self.max_total_bytes,
                "max_files": self.max_files,
                "max_line_bytes": MAX_LINE_BYTES,
                "max_key_chars": MAX_KEY_CHARS,
                "max_value_bytes": MAX_VALUE_BYTES,
            },
            "precedence": {
                "rule": "later enabled layer wins after localisation replace_path removal",
                "configuration_order_verified": ready,
                "engine_merge_semantics_verified": False,
            },
            "static_source": "LocalizationIndex",
        }

    @staticmethod
    def _validate_keys(keys: str | Sequence[str]) -> list[str]:
        if isinstance(keys, str):
            requested = [keys]
        elif isinstance(keys, Sequence) and not isinstance(keys, (bytes, bytearray)):
            requested = list(keys)
        else:
            raise InformationError("invalid_keys", "keys must be a string or a sequence of strings")
        if not requested or len(requested) > MAX_QUERY_KEYS:
            raise InformationError("invalid_keys", f"keys must contain 1..{MAX_QUERY_KEYS} values")
        if any(not isinstance(key, str) or not key or len(key) > MAX_KEY_CHARS for key in requested):
            raise InformationError("invalid_keys", "keys must be non-empty strings within the key limit")
        if len(set(requested)) != len(requested):
            raise InformationError("invalid_keys", "keys must not contain duplicates")
        return requested

    @staticmethod
    def _validate_language(language: str) -> str:
        if not isinstance(language, str) or not _LANGUAGE_RE.fullmatch(language):
            raise InformationError("invalid_language", "language must be an explicit l_* header")
        return language

    @staticmethod
    def _validate_encoding(encoding: str) -> str:
        if encoding not in SUPPORTED_ENCODINGS:
            raise InformationError("unknown_encoding", f"unsupported localisation encoding: {encoding!r}")
        return encoding

    @staticmethod
    def _source_record(entry: _LocalisationEntry) -> dict[str, Any]:
        return {
            "layer": entry.layer, "order": entry.layer_order,
            "source_kind": entry.source_kind, "source": entry.source_label,
            "relative_path": entry.file_relative, "path": str(entry.file_path),
            "sha256": entry.file_sha256, "size_bytes": entry.file_size,
        }

    @classmethod
    def _raw_record(cls, entry: _LocalisationEntry) -> dict[str, Any]:
        return {
            "status": "present", "key": entry.key, "text": entry.raw_value,
            "line_text": entry.raw_line, "version": entry.version,
            "line": entry.line, "line_sha256": entry.line_sha256,
        }

    @classmethod
    def _render_entry(cls, entry: _LocalisationEntry, encoding: str) -> dict[str, Any]:
        raw = cls._raw_record(entry)
        base = {
            "key": entry.key,
            "language": entry.language,
            "language_header": {"language": entry.language, "line": entry.language_header_line},
            "line": entry.line,
            "file_sha256": entry.file_sha256,
            "source": cls._source_record(entry),
            "raw": raw,
            "raw_text": entry.raw_value,
            "raw_status": "present",
            "dynamic_tokens": list(entry.dynamic_tokens),
            "malformed_dynamic_markers": list(entry.malformed_dynamic_markers),
            "encoding": encoding,
        }
        try:
            decoded = _decode_value(entry.raw_value, encoding)
        except Exception as exc:
            base.update({
                "status": "unknown", "reason": "LOCALISATION_VALUE_DECODE_FAILED",
                "decode_error": str(exc),
                "decoded_text": None,
                "decoded_status": "unknown",
                "value": {"status": "unknown", "reason": "LOCALISATION_VALUE_DECODE_FAILED"},
            })
            return base
        tokens, malformed = _scan_dynamic_tokens(decoded)
        for token in entry.dynamic_tokens:
            if token not in tokens:
                tokens.append(token)
        malformed_markers = list(entry.malformed_dynamic_markers)
        for marker in malformed:
            if marker not in malformed_markers:
                malformed_markers.append(marker)
        base["dynamic_tokens"] = tokens[:MAX_DYNAMIC_TOKENS]
        base["malformed_dynamic_markers"] = malformed_markers[:MAX_DYNAMIC_TOKENS]
        if malformed_markers:
            base.update({
                "status": "unknown",
                "reason": "LOCALISATION_UNRESOLVED_DYNAMIC_MARKER",
                "decoded_text": None,
                "decoded_status": "unknown",
                "value": {
                    "status": "unknown",
                    "reason": "LOCALISATION_UNRESOLVED_DYNAMIC_MARKER",
                },
            })
            return base
        # Keep the decoded template visible for audit, but do not claim a
        # final static display value while tokens need Root/actor evaluation.
        decoded_status = "template" if tokens else "decoded"
        entry_status = "template" if tokens else "known"
        base.update({
            "status": entry_status,
            "decoded_text": decoded,
            "decoded_status": decoded_status,
            "value": {
                "status": decoded_status,
                "text": decoded,
            },
            "dynamic_tokens": tokens,
        })
        return base

    def lookup(
        self,
        keys: str | Sequence[str],
        *,
        language: str,
        encoding: str,
    ) -> dict[str, Any]:
        """Look up explicitly requested keys in one explicit language/codec.

        Missing keys, same-layer duplicates, malformed values and changed
        inputs are represented as ``unknown``/``unavailable`` entries.  The
        previous parsed content is never returned after an integrity failure.
        """

        requested = self._validate_keys(keys)
        language = self._validate_language(language)
        encoding = self._validate_encoding(encoding)
        context = self.context()
        integrity_or_scope = context.get("reasons", [])
        if integrity_or_scope:
            entries = {
                key: {
                    "status": "unavailable",
                    "reason": "LOCALISATION_SOURCE_CHANGED" if any(
                        isinstance(reason, Mapping) and str(reason.get("code", "")).endswith("CHANGED")
                        for reason in integrity_or_scope
                    ) else "LOCALISATION_SOURCE_UNAVAILABLE",
                }
                for key in requested
            }
            return {
                "status": "unavailable", "complete": False,
                "language": language, "encoding": encoding,
                "keys": requested, "entries": entries,
                "context": context, "source": "LocalizationIndex",
            }

        result_entries: dict[str, dict[str, Any]] = {}
        for key in requested:
            candidates = self._entries.get((language, key), [])
            if not candidates:
                result_entries[key] = {
                    "status": "unknown", "reason": "LOCALISATION_KEY_MISSING",
                    "key": key, "language": language,
                }
                continue
            duplicate_key = (language, key)
            if duplicate_key in self._same_layer_duplicates:
                result_entries[key] = {
                    "status": "unknown",
                    "reason": "LOCALISATION_SAME_LAYER_DUPLICATE",
                    "key": key, "language": language,
                    "candidates": [self._source_record(item) for item in self._same_layer_duplicates[duplicate_key]],
                }
                continue
            selected = max(candidates, key=lambda item: item.layer_order)
            result_entries[key] = self._render_entry(selected, encoding)
            if len(candidates) > 1:
                result_entries[key]["overridden_sources"] = [
                    self._source_record(item) for item in sorted(candidates, key=lambda item: item.layer_order)
                    if item is not selected
                ]
                result_entries[key]["coverage_source"] = "static_enabled_stack_order"
            else:
                result_entries[key]["coverage_source"] = "static_layer"
        complete = all(
            item.get("status") == "known" and item.get("decoded_status") == "decoded"
            for item in result_entries.values()
        )
        status = "complete" if complete else "partial"
        return {
            "status": status, "complete": complete,
            "language": language, "encoding": encoding,
            "keys": requested, "entries": result_entries,
            "context": context, "source": "LocalizationIndex",
        }


def _copy(value: Any) -> Any:
    return deepcopy(value)


__all__ = [
    "DEFAULT_MAX_FILE_BYTES", "DEFAULT_MAX_TOTAL_BYTES", "DEFAULT_MAX_FILES",
    "ENCODING_EU4_ESCAPE_CP1252", "ENCODING_UTF8", "LocalizationIndex",
    "LOCALISATION_RELATIVE", "MAX_KEY_CHARS", "MAX_LINE_BYTES",
    "MAX_VALUE_BYTES", "SUPPORTED_ENCODINGS", "SUPPORTED_VERSIONS",
]
