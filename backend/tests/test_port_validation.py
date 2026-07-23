from __future__ import annotations

import pytest
from pydantic import ValidationError

from better_network_tools.models import PortJobRequest
from better_network_tools.port_validation import (
    PortValidationError,
    format_port_spec,
    parse_port_spec,
    validate_port_target,
    validate_scannable_address,
)


def test_port_target_canonicalizes_ip_literals_and_idna_hostnames() -> None:
    ipv4 = validate_port_target(" 192.0.2.19 ")
    assert ipv4.display == "192.0.2.19"
    assert ipv4.lookup == "192.0.2.19"
    assert ipv4.address == "192.0.2.19"

    ipv6 = validate_port_target("2001:0db8:0:0:0:0:0:0007")
    assert ipv6.display == "2001:0db8:0:0:0:0:0:0007"
    assert ipv6.lookup == "2001:db8::7"
    assert ipv6.address == "2001:db8::7"

    mapped = validate_port_target("::ffff:192.0.2.19")
    assert mapped.lookup == "192.0.2.19"
    assert mapped.address == "192.0.2.19"

    hostname = validate_port_target("BÜCHER.Example.")
    assert hostname.display == "BÜCHER.Example."
    assert hostname.lookup == "xn--bcher-kva.example"
    assert hostname.address is None


@pytest.mark.parametrize(
    "target",
    [
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "ff02::1",
        "fe80::1",
        "::ffff:0.0.0.0",
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
    ],
)
def test_port_target_rejects_unsafe_address_scopes(target: str) -> None:
    with pytest.raises(PortValidationError) as raised:
        validate_port_target(target)

    assert raised.value.code == "unsafe_port_target"
    assert raised.value.as_detail()["target"] == target


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "-router.example",
        "router example",
        "https://router.example",
        "router.example/path",
        "router.example\\share",
        "router.example?query",
        "router.example#fragment",
        "user@router.example",
        "fe80::1%en0",
        "999.1.1.1",
        "2001:db8::invalid",
        ".",
        "bad..example",
        "bad_label.example",
    ],
)
def test_port_target_rejects_malformed_or_ambiguous_input(target: str) -> None:
    with pytest.raises(PortValidationError) as raised:
        validate_port_target(target)

    assert raised.value.code == "invalid_port_target"
    assert raised.value.as_detail()["target"] in {target, target.strip()}


def test_resolved_address_is_revalidated_and_keeps_original_target_context() -> None:
    with pytest.raises(PortValidationError) as invalid:
        validate_scannable_address("not-an-address", target="router.example")
    assert invalid.value.as_detail() == {
        "code": "invalid_resolved_address",
        "message": "the target resolver returned an invalid IP address",
        "target": "router.example",
    }

    with pytest.raises(PortValidationError) as unsafe:
        validate_scannable_address("0.0.0.0", target="router.example")
    assert unsafe.value.code == "unsafe_port_target"
    assert unsafe.value.as_detail()["target"] == "router.example"


def test_port_spec_is_sorted_deduplicated_and_collapsed_canonically() -> None:
    parsed = parse_port_spec(
        "443, 80-82, 81, 22, 443, 100 - 102",
        port_limit=16,
    )

    assert parsed.ports == (22, 80, 81, 82, 100, 101, 102, 443)
    assert parsed.canonical == "22,80-82,100-102,443"

    duplicate_heavy = parse_port_spec("1-3,1,2,3", port_limit=3)
    assert duplicate_heavy.ports == (1, 2, 3)
    assert duplicate_heavy.canonical == "1-3"


def test_format_port_spec_handles_singletons_and_boundary_ranges() -> None:
    assert format_port_spec((1,)) == "1"
    assert format_port_spec((1, 2, 4, 6, 7, 8, 65535)) == "1-2,4,6-8,65535"


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "   ",
        ",",
        "80,",
        ",80",
        "http",
        "0",
        "65536",
        "90-80",
        "1-2-3",
        "1;2",
        "1 2",
    ],
)
def test_port_spec_rejects_empty_malformed_and_out_of_range_entries(spec: str) -> None:
    with pytest.raises(PortValidationError) as raised:
        parse_port_spec(spec, port_limit=32)

    assert raised.value.code == "invalid_port_spec"


def test_port_spec_enforces_the_unique_port_limit_during_range_expansion() -> None:
    with pytest.raises(PortValidationError) as raised:
        parse_port_spec("1-4", port_limit=3)

    assert raised.value.as_detail() == {
        "code": "port_limit_exceeded",
        "message": "NetPorts jobs may scan at most 3 unique TCP ports",
        "limit": 3,
        "actual": 4,
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"target": "router.example", "ports": [80]},
        {"target": "router.example", "timeout": True},
        {"target": "router.example", "timeout": "0.2"},
        {"target": "router.example", "concurrency": True},
        {"target": "router.example", "collect_banners": 1},
        {"target": "router.example", "unexpected": "value"},
    ],
)
def test_port_job_request_rejects_coercion_and_unknown_fields(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        PortJobRequest.model_validate(payload)
