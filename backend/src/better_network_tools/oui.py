"""Offline MAC address normalization and IEEE OUI vendor lookup."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict


_PLAIN_MAC = re.compile(r"^[0-9A-Fa-f]{12}$")
_COLON_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_HYPHEN_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$")
_CISCO_MAC = re.compile(r"^(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")
_PLAIN_OUI = re.compile(r"^[0-9A-Fa-f]{6}$")
_COLON_OUI = re.compile(r"^(?:[0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}$")
_HYPHEN_OUI = re.compile(r"^(?:[0-9A-Fa-f]{2}-){2}[0-9A-Fa-f]{2}$")
_CISCO_OUI = re.compile(r"^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{2}$")


class InvalidMacAddress(ValueError):
    """Raised when input is not a supported 48-bit MAC address or OUI."""


class VendorNotFoundError(LookupError):
    """Raised when the local registry has no vendor for an OUI."""

    def __init__(self, normalized: "NormalizedMac") -> None:
        self.normalized = normalized
        super().__init__(f"no vendor was found for OUI {normalized.matched_prefix}")


class OuiDatabaseUnavailableError(RuntimeError):
    """Raised when the bundled vendor database cannot be loaded."""


@dataclass(frozen=True, slots=True)
class NormalizedMac:
    original: str
    normalized: str
    matched_prefix: str
    input_type: Literal["mac", "oui"]
    locally_administered: bool
    multicast: bool


class OuiLookupResponse(BaseModel):
    """Successful local vendor lookup response."""

    model_config = ConfigDict(frozen=True)

    query: str
    normalized: str
    matched_prefix: str
    vendor: str
    found: Literal[True] = True
    input_type: Literal["mac", "oui"]
    locally_administered: bool
    multicast: bool
    source: Literal["bundled_ieee_registry"] = "bundled_ieee_registry"


class VendorDatabase(Protocol):
    def lookup(self, mac_address: str) -> str | None:
        """Return a vendor name from local data, or ``None`` when absent."""


class BundledOuiDatabase:
    """Adapter for mac-vendor-lookup's package-bundled IEEE prefix list.

    The package's lookup helper downloads if its data file is missing, so this
    adapter intentionally reads the installed file itself. A lookup therefore
    cannot fall through to a network update.
    """

    def __init__(self) -> None:
        self._vendors: dict[str, str] | None = None
        self._load_lock = threading.Lock()

    def lookup(self, mac_address: str) -> str | None:
        vendors = self._load_vendors()
        prefix = mac_address.replace(":", "").upper()[:6]
        return vendors.get(prefix)

    def _load_vendors(self) -> dict[str, str]:
        if self._vendors is not None:
            return self._vendors

        with self._load_lock:
            if self._vendors is not None:
                return self._vendors
            try:
                from mac_vendor_lookup import BaseMacLookup
            except ModuleNotFoundError as exc:  # pragma: no cover - packaging failure
                raise OuiDatabaseUnavailableError(
                    "the bundled OUI database is not installed"
                ) from exc

            location = BaseMacLookup().find_vendors_list()
            if not location:
                raise OuiDatabaseUnavailableError(
                    "the installed package does not contain an OUI data file"
                )

            vendors: dict[str, str] = {}
            try:
                lines = Path(location).read_bytes().splitlines()
            except OSError as exc:
                raise OuiDatabaseUnavailableError(
                    "the bundled OUI database could not be read"
                ) from exc

            for line in lines:
                try:
                    prefix, vendor = line.split(b":", 1)
                    cleaned_prefix = prefix.decode("ascii").strip().upper()
                    cleaned_vendor = vendor.decode("utf-8").strip()
                except (UnicodeDecodeError, ValueError):
                    continue
                if len(cleaned_prefix) == 6 and cleaned_vendor:
                    vendors[cleaned_prefix] = cleaned_vendor

            if not vendors:
                raise OuiDatabaseUnavailableError("the bundled OUI database is empty")
            self._vendors = vendors
            return vendors


def normalize_mac(value: str) -> NormalizedMac:
    """Normalize common MAC/OUI formats to uppercase colon-delimited form."""

    original = value
    candidate = value.strip()
    full_mac = any(
        pattern.fullmatch(candidate)
        for pattern in (_PLAIN_MAC, _COLON_MAC, _HYPHEN_MAC, _CISCO_MAC)
    )
    oui_only = any(
        pattern.fullmatch(candidate)
        for pattern in (_PLAIN_OUI, _COLON_OUI, _HYPHEN_OUI, _CISCO_OUI)
    )
    if not full_mac and not oui_only:
        raise InvalidMacAddress(
            "Enter a 48-bit MAC address or 24-bit OUI, for example "
            "00:50:56:C0:00:08 or 00:50:56."
        )

    hex_digits = re.sub(r"[:.\-]", "", candidate).upper()
    normalized = ":".join(
        hex_digits[index : index + 2] for index in range(0, len(hex_digits), 2)
    )
    matched_prefix = ":".join(
        hex_digits[index : index + 2] for index in range(0, 6, 2)
    )
    first_octet = int(hex_digits[:2], 16)
    return NormalizedMac(
        original=original,
        normalized=normalized,
        matched_prefix=matched_prefix,
        input_type="mac" if full_mac else "oui",
        locally_administered=bool(first_octet & 0b00000010),
        multicast=bool(first_octet & 0b00000001),
    )


class OuiLookupService:
    """Normalize addresses and query an injected, entirely local OUI database."""

    def __init__(self, database: VendorDatabase | None = None) -> None:
        self.database = database or BundledOuiDatabase()

    def lookup(self, value: str) -> OuiLookupResponse:
        normalized = normalize_mac(value)
        database_address = (
            normalized.normalized
            if normalized.input_type == "mac"
            else f"{normalized.normalized}:00:00:00"
        )
        vendor = self.database.lookup(database_address)
        if vendor is None:
            raise VendorNotFoundError(normalized)

        return OuiLookupResponse(
            query=value,
            normalized=normalized.normalized,
            matched_prefix=normalized.matched_prefix,
            vendor=vendor,
            input_type=normalized.input_type,
            locally_administered=normalized.locally_administered,
            multicast=normalized.multicast,
        )
