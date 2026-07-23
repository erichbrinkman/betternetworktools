from __future__ import annotations

import httpx
import pytest

from better_network_tools.config import Settings
from better_network_tools.main import create_app
from better_network_tools.oui import (
    BundledOuiDatabase,
    InvalidMacAddress,
    OuiLookupService,
    VendorNotFoundError,
    normalize_mac,
)


@pytest.mark.parametrize(
    ("value", "expected", "input_type"),
    [
        ("00:50:56:c0:00:08", "00:50:56:C0:00:08", "mac"),
        ("00-50-56-C0-00-08", "00:50:56:C0:00:08", "mac"),
        ("0050.56c0.0008", "00:50:56:C0:00:08", "mac"),
        ("005056c00008", "00:50:56:C0:00:08", "mac"),
        (" 00:50:56 ", "00:50:56", "oui"),
        ("0050.56", "00:50:56", "oui"),
    ],
)
def test_normalize_mac_common_formats(
    value: str, expected: str, input_type: str
) -> None:
    result = normalize_mac(value)
    assert result.normalized == expected
    assert result.matched_prefix == "00:50:56"
    assert result.input_type == input_type


@pytest.mark.parametrize(
    "value",
    [
        "",
        "00:50:56:C0:00",
        "00:50:56:C0:00:GG",
        "00-50:56-C0:00-08",
        "00::50::56::C0::00::08",
        "not-a-mac",
    ],
)
def test_normalize_mac_rejects_invalid_values(value: str) -> None:
    with pytest.raises(InvalidMacAddress):
        normalize_mac(value)


class FakeDatabase:
    def __init__(self, vendor: str | None) -> None:
        self.vendor = vendor
        self.lookups: list[str] = []

    def lookup(self, mac_address: str) -> str | None:
        self.lookups.append(mac_address)
        return self.vendor


def test_lookup_returns_vendor_and_exact_matched_prefix() -> None:
    database = FakeDatabase("VMware, Inc.")
    service = OuiLookupService(database)

    result = service.lookup("00-50-56-C0-00-08")

    assert database.lookups == ["00:50:56:C0:00:08"]
    assert result.model_dump() == {
        "query": "00-50-56-C0-00-08",
        "normalized": "00:50:56:C0:00:08",
        "matched_prefix": "00:50:56",
        "vendor": "VMware, Inc.",
        "found": True,
        "input_type": "mac",
        "locally_administered": False,
        "multicast": False,
        "source": "bundled_ieee_registry",
    }


def test_prefix_lookup_expands_to_a_full_address_for_database() -> None:
    database = FakeDatabase("VMware, Inc.")
    service = OuiLookupService(database)

    result = service.lookup("00:50:56")

    assert database.lookups == ["00:50:56:00:00:00"]
    assert result.input_type == "oui"


def test_lookup_has_explicit_not_found_state() -> None:
    with pytest.raises(VendorNotFoundError) as caught:
        OuiLookupService(FakeDatabase(None)).lookup("02:00:00:00:00:01")

    assert caught.value.normalized.matched_prefix == "02:00:00"
    assert caught.value.normalized.locally_administered is True


def test_installed_database_contains_known_ieee_prefix() -> None:
    """The wheel must carry usable data without a cache update or web request."""

    vendor = BundledOuiDatabase().lookup("00:50:56:00:00:00")

    assert vendor is not None
    assert "VMWARE" in vendor.upper()


@pytest.mark.asyncio
async def test_oui_api_success_invalid_and_not_found_contract() -> None:
    settings = Settings()
    service = OuiLookupService(FakeDatabase("VMware, Inc."))
    app = create_app(settings, oui_lookup_service=service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        found = await client.get("/api/oui", params={"mac": "0050.56c0.0008"})
        assert found.status_code == 200
        assert found.json()["vendor"] == "VMware, Inc."
        assert found.json()["matched_prefix"] == "00:50:56"

        invalid = await client.get("/api/oui", params={"mac": "not-a-mac"})
        assert invalid.status_code == 422
        assert invalid.json()["detail"]["code"] == "invalid_mac"

    not_found_app = create_app(
        settings, oui_lookup_service=OuiLookupService(FakeDatabase(None))
    )
    not_found_transport = httpx.ASGITransport(app=not_found_app)
    async with httpx.AsyncClient(
        transport=not_found_transport, base_url="http://test"
    ) as client:
        missing = await client.get("/api/oui", params={"mac": "02:00:00:00:00:01"})
        assert missing.status_code == 404
        assert missing.json()["detail"] == {
            "code": "vendor_not_found",
            "message": "No vendor was found for OUI 02:00:00.",
            "normalized": "02:00:00:00:00:01",
            "matched_prefix": "02:00:00",
        }
