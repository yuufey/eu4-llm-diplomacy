"""Read a bounded, pinned subset of the vendored CWTools EU4 CWT rules.

This adapter exposes declarative scope names, aliases, and direct inheritance
from one pinned ``scopes.cwt`` file. It does not load the .NET CWTools engine,
evaluate triggers/annotations, validate the whole EU4 configuration, or decide
runtime visibility.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .mission_definitions import _parse_mission_script


_DEFAULT_ROOT = Path(__file__).resolve().parents[2]
_VENDOR_RELATIVE = Path("third_party/cwtools-eu4-config")
_VENDOR_NAME = "VENDOR.json"
_SCOPES_NAME = "scopes.cwt"
_MAX_VENDOR_BYTES = 16 * 1024
_MAX_SCOPE_FILE_BYTES = 64 * 1024
_MAX_SCOPES = 256
_MAX_TOKENS = 1024
_MAX_NAME_LENGTH = 128
_ALIAS_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,95}\Z")

_REPOSITORY_URL = "https://github.com/cwtools/cwtools-eu4-config.git"
_COMMIT = "a85622d368bbb7afca938ed70fdd5eda44aec769"
_LICENSE = "MIT"
_SCOPES_BYTES = 876
_SCOPES_SHA256 = "be3bfe226fd202c0268f4aacdfbb10548de38e4632ea5f59e50a9bf231739f5d"
_SCOPES_LF_BYTES = 830
_SCOPES_LF_SHA256 = "d276ea723dd44108e5597188c2e6c5feff64dc01f6a9baaf6828ac82d774b8c8"
_EXPECTED_VENDOR = {
    "schema": "cwtools-eu4-config.vendored-scope-rules.v1",
    "repository_url": _REPOSITORY_URL,
    "commit": _COMMIT,
    "license": _LICENSE,
    "license_file": "LICENSE",
    "consumed_files": {
        "scopes.cwt": {"bytes": _SCOPES_BYTES, "sha256": _SCOPES_SHA256},
    },
}


def _strict_json(raw: bytes) -> Any:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Malformed CWTools vendor manifest") from exc


def _read_bounded(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"CWTools input exceeds byte limit ({size}>{limit})")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"CWTools input exceeds byte limit ({len(raw)}>{limit})")
    return raw


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _bare_list(block, field: str, *, required: bool) -> list[str]:
    _require(block.assignment == "=" and block.kind == "block" and block.value is None,
             f"Invalid {field} block")
    values: list[str] = []
    for item in block.children:
        _require(item.kind == "bare" and item.assignment is None and item.value is None
                 and not item.children and item.raw_key == item.key,
                 f"Unsupported nested or quoted token in {field}")
        token = item.key
        _require(type(token) is str and _ALIAS_RE.fullmatch(token) is not None,
                 f"Invalid token in {field}")
        values.append(token)
    _require(not required or bool(values), f"Empty {field} list")
    _require(len(values) <= _MAX_TOKENS, f"Too many {field} entries")
    _require(len({value.casefold() for value in values}) == len(values),
             f"Duplicate {field} entries")
    return values


def _parse_scope_rules(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8-sig")
        nodes = _parse_mission_script(text)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("Malformed scopes.cwt text") from exc

    _require(len(nodes) == 1, "Expected one scopes.cwt root assignment")
    root = nodes[0]
    _require(root.key == "scopes" and root.assignment == "=" and root.kind == "block"
             and root.value is None, "Unexpected scopes.cwt root")
    _require(0 < len(root.children) <= _MAX_SCOPES, "Scope count out of bounds")

    raw_scopes: dict[str, dict[str, list[str]]] = {}
    folded_names: set[str] = set()
    total_tokens = 0
    for node in root.children:
        _require(node.kind == "block" and node.assignment == "=" and node.value is None,
                 f"Invalid scope definition at line {node.line}")
        name = node.key
        _require(type(name) is str and 0 < len(name) <= _MAX_NAME_LENGTH
                 and not any(ord(char) < 0x20 for char in name), "Invalid scope name")
        folded_name = name.casefold()
        _require(folded_name not in folded_names, "Duplicate scope name")
        folded_names.add(folded_name)

        fields: dict[str, Any] = {}
        for field in node.children:
            _require(field.key in {"aliases", "is_subscope_of"},
                     f"Unsupported scopes.cwt field {field.key!r} at line {field.line}")
            _require(field.key not in fields, f"Duplicate {field.key} field for {name}")
            fields[field.key] = field
        _require("aliases" in fields, f"Scope {name!r} lacks aliases")
        aliases = _bare_list(fields["aliases"], "aliases", required=True)
        parents = (_bare_list(fields["is_subscope_of"], "is_subscope_of", required=False)
                   if "is_subscope_of" in fields else [])
        total_tokens += len(aliases) + len(parents)
        _require(total_tokens <= _MAX_TOKENS, "Total scope token budget exceeded")
        raw_scopes[name] = {"aliases": aliases, "declared_parents": parents}

    alias_to_scope: dict[str, str] = {}
    aliases_for_output: dict[str, str] = {}
    for name, row in raw_scopes.items():
        for alias in row["aliases"]:
            folded_alias = alias.casefold()
            _require(folded_alias not in alias_to_scope, f"Alias collision: {alias}")
            alias_to_scope[folded_alias] = name
            aliases_for_output[alias] = name

    scopes: dict[str, dict[str, list[str]]] = {}
    parents_by_scope: dict[str, list[str]] = {}
    for name, row in raw_scopes.items():
        canonical_parents: list[str] = []
        for declared in row["declared_parents"]:
            parent = alias_to_scope.get(declared.casefold())
            _require(parent is not None, f"Unknown parent scope alias {declared!r} for {name!r}")
            _require(parent not in canonical_parents, f"Duplicate parent scope for {name!r}")
            canonical_parents.append(parent)
        parents_by_scope[name] = canonical_parents
        scopes[name] = {"aliases": list(row["aliases"]), "parents": canonical_parents}

    return {
        "scopes": scopes,
        "aliases": aliases_for_output,
        "is_subscope_of": parents_by_scope,
    }


def load_scope_rules(root: str | Path | None = None) -> dict[str, Any]:
    """Load one exact, bounded CWTools ``scopes.cwt`` file.

    ``root`` is the workspace root containing ``third_party/cwtools-eu4-config``.
    It is not a game installation path. Only VENDOR.json and scopes.cwt are
    read; the configured commit and consumed-file hash are fixed in this
    adapter and checked on every call.
    """
    workspace = _DEFAULT_ROOT if root is None else Path(root).resolve()
    vendor_dir = workspace / _VENDOR_RELATIVE
    vendor_path = vendor_dir / _VENDOR_NAME
    if not vendor_path.exists():
        vendor_path = vendor_dir.with_name(vendor_dir.name + ".vendor.json")
    vendor_raw = _read_bounded(vendor_path, _MAX_VENDOR_BYTES)
    vendor = _strict_json(vendor_raw)
    _require(type(vendor) is dict and vendor == _EXPECTED_VENDOR,
             "CWTools VENDOR.json schema, commit, license, or consumed-file pin mismatch")
    consumed = vendor["consumed_files"]["scopes.cwt"]
    _require(type(consumed) is dict and type(consumed.get("bytes")) is int
             and type(consumed.get("sha256")) is str,
             "Malformed CWTools consumed-file pin")

    scopes_path = vendor_dir / _SCOPES_NAME
    raw = _read_bounded(scopes_path, _MAX_SCOPE_FILE_BYTES)
    actual_sha = hashlib.sha256(raw).hexdigest()
    canonical = raw.replace(b"\r\n", b"\n")
    _require(consumed["bytes"] == _SCOPES_BYTES
             and consumed["sha256"] == _SCOPES_SHA256
             and len(canonical) == _SCOPES_LF_BYTES
             and hashlib.sha256(canonical).hexdigest() == _SCOPES_LF_SHA256,
             "Vendored scopes.cwt bytes or SHA-256 mismatch")
    parsed = _parse_scope_rules(raw)
    source = {
        "repository_url": vendor["repository_url"],
        "commit": vendor["commit"],
        "license": vendor["license"],
        "file": _SCOPES_NAME,
        "file_bytes": len(raw),
        "file_sha256": actual_sha,
        "canonical_lf_sha256": _SCOPES_LF_SHA256,
        "coverage": "one pinned scope metadata file only; not whole EU4 1.37.4 configuration and not runtime visibility",
    }
    return {
        "schema": "eu4.cwtools.scope_rules.v1",
        "scopes": parsed["scopes"],
        "aliases": parsed["aliases"],
        "is_subscope_of": parsed["is_subscope_of"],
        "rule_source": source,
    }


def trade_node_scope_rule(root: str | Path | None = None) -> dict[str, Any]:
    """Return the vendored Trade Node aliases and canonical direct parents."""
    rules = load_scope_rules(root)
    name = "Trade Node"
    _require(name in rules["scopes"], "Pinned CWT source lacks Trade Node scope")
    scope = rules["scopes"][name]
    source = rules["rule_source"]
    return {
        "name": name,
        "aliases": list(scope["aliases"]),
        "parents": list(rules["is_subscope_of"][name]),
        "source": {
            "repository_url": source["repository_url"],
            "commit": source["commit"],
            "license": source["license"],
            "file": source["file"],
            "file_sha256": source["file_sha256"],
            "coverage": source["coverage"],
        },
    }
