"""Read and normalize literal native localization cache entries.

This reader owns only the bounded cache path.  Mission membership, branch
inputs, and custom Root-template resolution deliberately stay in their
respective readers so other information sources can share this literal
localization contract without importing mission behavior.
"""
from __future__ import annotations

import re

from bridge.native_text import validate_native_text_codec

from .model import InformationError


_KEY_PATTERN = re.compile(r"[!-~]{1,160}")
_LANGUAGE_PATTERN = re.compile(r"l_[A-Za-z0-9_]{1,63}")
_SUPPORTED_COUNTRIES = ("FRA",)
_MAX_KEYS = 8192
_BATCH_SIZE = 128


def _gap(reason: str, status: str = "unknown") -> dict[str, str]:
    return {"status": status, "reason": reason}


class NativeLocalizationReader:
    """Normalize version-bound, double-pass native literal cache captures."""

    supported_countries = _SUPPORTED_COUNTRIES

    def __init__(self, base_source, capture=None):
        self.base_source = base_source
        self.capture = capture

    def localized_text(self, country, context, keys):
        """Read literal cache keys in bounded batches.

        Each capture is independently identity/date guarded.  The batches are
        intentionally not an atomic game snapshot, and no mission-specific
        template resolver is called here.
        """
        return self._localized_text(country, context, keys, verify_context=True)

    def _localized_text(self, country, context, keys, *, verify_context):
        """Internal literal read with an optional caller-owned final check.

        ``NativeMissionReader`` uses the false setting so its historical
        ordering remains literal read, custom-template derivation, then one
        final base-context check.  Public neutral consumers always use the
        guarded default through :meth:`localized_text`.
        """
        if country not in self.supported_countries or context.get("observer") != country:
            raise InformationError(
                "observer_scope_mismatch",
                "Localization reader supports the bound FRA observer",
            )
        session = getattr(self.base_source, "session", None)
        if session is None or context.get("status") != "ready" or context.get("mode") != "live":
            raise InformationError("source_unavailable", "No ready native localization session")

        record = getattr(session, "record", {})
        try:
            codec = validate_native_text_codec(record.get("native_text_codec"))
        except ValueError as exc:
            raise InformationError(
                "localization_codec_unconfigured",
                "Native localization requires an explicit session codec",
            ) from exc

        self._validate_request_keys(keys, max_keys=_MAX_KEYS)
        capture = self.capture
        if capture is None:
            from .localization_memory import capture

        values, batches, language = {}, [], None
        for offset in range(0, len(keys), _BATCH_SIZE):
            requested = keys[offset:offset + _BATCH_SIZE]
            raw = capture(session.directory / "installation.json", country, requested)
            normalized = self.normalize_localization(raw, context, requested, codec)
            if language is not None and normalized["language"] != language:
                raise InformationError(
                    "localization_language_changed",
                    "Localization language changed across bounded batches",
                )
            language = normalized["language"]
            values.update(normalized["entries"])
            batches.append(normalized["provenance"])

        # Health may have changed after a cache batch; never attach old text
        # to a different date, process session, executable or observer.
        if verify_context:
            refreshed = self.base_source.context()
            if any(
                refreshed.get(key) != context.get(key)
                for key in ("status", "mode", "session_id", "game_sha256", "observer", "game_date")
            ):
                raise InformationError(
                    "localization_context_changed",
                    "Localization context changed during capture",
                )
        return {
            "status": "known",
            "entries": values,
            "language": language,
            "provenance": {
                "reader": "bounded_ReadProcessMemory",
                "codec": codec,
                "codec_source": "operator_session.native_text_codec",
                "codec_module_provenance_verified": False,
                "batches": batches,
                "atomic_with_task_slots": False,
                "atomic_across_batches": False,
                "world_generation_verified": False,
                "dynamic_substitution_evaluated": False,
            },
        }

    @staticmethod
    def _validate_request_keys(keys, *, max_keys):
        if (
            not isinstance(keys, list)
            or not 1 <= len(keys) <= max_keys
            or any(not isinstance(key, str) or _KEY_PATTERN.fullmatch(key) is None for key in keys)
            or len(set(keys)) != len(keys)
        ):
            raise InformationError("localization_keys_invalid", "Invalid localization key request")

    @staticmethod
    def normalize_localization(report, context, keys, codec):
        """Validate one bounded cache report and decode literal entries.

        The checks intentionally mirror the original mission reader's full
        identity, request, guard, codec, date, double-pass and cleanup
        contract.  The method is shared by the mission compatibility wrapper
        and neutral consumers to keep one normalizer authoritative.
        """
        validate_native_text_codec(codec)
        NativeLocalizationReader._validate_request_keys(keys, max_keys=_BATCH_SIZE)

        if (
            not isinstance(report, dict)
            or not isinstance(context, dict)
            or any(
                not isinstance(report.get(key), dict)
                for key in (
                    "identity",
                    "request",
                    "doublepass",
                    "static_contract_guard",
                    "file_code_guard",
                    "runtime_code_guard",
                    "cleanup",
                    "before",
                    "after",
                    "language",
                )
            )
            or not isinstance(report["cleanup"].get("handle_close"), dict)
            or any(
                not isinstance(report[name].get("game_date"), dict)
                for name in ("before", "after")
            )
        ):
            raise InformationError(
                "localization_snapshot_invalid",
                "Invalid cache capture structure",
            )

        identity = report.get("identity", {})
        if (
            report.get("status") != "observed"
            or report.get("read_only") is not True
            or identity.get("binding_verified") is not True
            or identity.get("installation_session_id") != context.get("session_id")
            or identity.get("process_path_sha256") != context.get("game_sha256")
            or report.get("request", {}).get("country") != context.get("observer")
            or report.get("request", {}).get("keys") != keys
            or report.get("doublepass", {}).get("performed") is not True
            or report.get("doublepass", {}).get("consistent") is not True
            or any(
                report.get(key, {}).get("status") != "observed"
                for key in ("static_contract_guard", "file_code_guard", "runtime_code_guard")
            )
            or report.get("cleanup", {}).get("handle_close", {}).get("closed") is not True
        ):
            raise InformationError(
                "localization_snapshot_incomplete",
                "Localization identity, guard or cleanup check failed",
            )

        for name in ("before", "after"):
            if (
                report.get(name, {}).get("status") != "observed"
                or report[name].get("game_date", {}).get("raw") != context.get("game_date")
            ):
                raise InformationError(
                    "localization_context_changed",
                    "Localization belongs to another game date",
                )

        language = report.get("language", {})
        if (
            language.get("status") != "observed"
            or not isinstance(language.get("text"), str)
            or _LANGUAGE_PATTERN.fullmatch(language["text"]) is None
        ):
            raise InformationError("localization_language_unknown", "Native lookup language is unknown")

        entries = report.get("entries")
        if not isinstance(entries, dict) or set(entries) != set(keys):
            raise InformationError(
                "localization_snapshot_incomplete",
                "Requested cache keys are missing",
            )

        # Decode only literal cache bytes.  ``mission_texts`` contains the
        # shared byte decoder, but no mission capture or custom resolver is
        # imported or invoked by this reader.
        from .mission_texts import decode_template

        values = {}
        for key in keys:
            entry = entries[key]
            if not isinstance(entry, dict) or entry.get("key") != key:
                raise InformationError(
                    "localization_snapshot_invalid",
                    "Invalid cache entry identity",
                )
            if entry.get("status") == "observed":
                encoded = entry.get("value_hex")
                decoded = decode_template(encoded, codec)
                if (
                    decoded.get("reason") != "LOCALIZATION_BYTES_INVALID"
                    and (
                        type(entry.get("byte_length")) is not int
                        or len(encoded) // 2 != entry["byte_length"]
                    )
                ):
                    raise InformationError(
                        "localization_snapshot_invalid",
                        "Cache byte length mismatch",
                    )
                values[key] = decoded
            elif entry.get("status") == "unknown":
                values[key] = _gap(entry.get("unknown_reason") or "LOCALIZATION_KEY_UNRESOLVED")
            else:
                raise InformationError(
                    "localization_snapshot_invalid",
                    "Invalid cache entry status",
                )

        return {
            "status": "known",
            "entries": values,
            "language": language["text"],
            "provenance": {
                "profile_sha256": report.get("profile", {}).get("sha256"),
                "probe_sha256": report.get("probe_script_sha256"),
                "session_id": context.get("session_id"),
                "game_date": context.get("game_date"),
                "doublepass_consistent": True,
                "handle_closed": True,
                "lookup_semantics": "native_FNV1_hash_only",
                "literal_key_collision_excluded": False,
            },
        }


__all__ = ["NativeLocalizationReader"]
