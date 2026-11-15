"""Shared capability gate for v65's inherited v64 observation ACKs."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def has_v65_country_control_capability(ack: Any) -> bool:
    """Require the complete native country-control identity on a v65 ACK."""

    return (
        isinstance(ack, Mapping)
        and type(ack.get("version")) is int
        and ack.get("version") == 65
        and ack.get("native_country_control_configuration") is True
        and ack.get("native_country_control_protocol") == "EU4CONTROL1"
        and ack.get("native_country_control_ack") == "native_controlled_countries_set"
        and ack.get("native_country_control_request") == "controlled-countries.req"
    )


def supports_observer_version(ack: Any, versions: Sequence[int]) -> bool:
    """Match an existing feature version or its fully identified v65 successor.

    Version 65 inherits v64 feature behavior. It is accepted by an existing
    v64-capable feature validator only when the startup ACK also proves the
    country-control protocol identity; older version rules remain unchanged.
    """

    if not isinstance(ack, Mapping):
        return False
    version = ack.get("version")
    if type(version) is not int:
        return False
    if version in versions:
        return True
    return version == 65 and 64 in versions and has_v65_country_control_capability(ack)


__all__ = ["has_v65_country_control_capability", "supports_observer_version"]
