from __future__ import annotations

import pytest
from pydantic import ValidationError

from better_network_tools.models import TraceJobRequest
from better_network_tools.trace_validation import (
    TraceValidationError,
    validate_trace_target,
    validate_traceable_address,
)


def test_trace_target_normalizes_literals_and_idna_hostnames() -> None:
    ipv6 = validate_trace_target("2001:0db8:0:0::1")
    hostname = validate_trace_target(" BÜCHER.Example. ")

    assert ipv6.address == "2001:db8::1"
    assert ipv6.lookup == "2001:db8::1"
    assert hostname.display == "BÜCHER.Example."
    assert hostname.lookup == "xn--bcher-kva.example"
    assert hostname.address is None


@pytest.mark.parametrize(
    "target",
    [
        "https://router.example",
        "router.example/path",
        r"router.example\path",
        "-n",
        "bad host",
        "192.0.2.999",
        "fe80::1%en0",
        "bad_name.example",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
        "fe80::1",
    ],
)
def test_trace_target_rejects_unsafe_or_argument_like_values(target: str) -> None:
    with pytest.raises(TraceValidationError):
        validate_trace_target(target)


def test_resolver_output_is_revalidated_as_a_numeric_safe_address() -> None:
    assert validate_traceable_address("192.0.2.1").compressed == "192.0.2.1"

    with pytest.raises(TraceValidationError) as invalid:
        validate_traceable_address("-m", target="router.example")
    assert invalid.value.code == "invalid_resolved_address"

    with pytest.raises(TraceValidationError) as unsafe:
        validate_traceable_address("239.1.2.3", target="router.example")
    assert unsafe.value.code == "unsafe_trace_target"


@pytest.mark.parametrize("value", [1, "yes"])
def test_asn_lookup_opt_in_requires_a_strict_json_boolean(value: object) -> None:
    with pytest.raises(ValidationError):
        TraceJobRequest(target="8.8.8.8", lookup_asn=value)  # type: ignore[arg-type]
