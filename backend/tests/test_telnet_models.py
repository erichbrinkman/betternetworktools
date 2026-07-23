from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from better_network_tools.telnet_models import (
    TELNET_INPUT_LIMIT_BYTES,
    TelnetConnectMessage,
    TelnetInputMessage,
    TelnetResizeMessage,
)


@pytest.mark.parametrize(
    "host",
    ["router.example", "192.0.2.1", "2001:db8::1", "fe80::1%en0"],
)
def test_telnet_connect_accepts_only_bounded_hosts(host: str) -> None:
    message = TelnetConnectMessage(
        type="connect", host=host, port=23, cols=80, rows=24
    )
    assert message.host == host


@pytest.mark.parametrize(
    "host",
    ["", "http://router", "router/path", "999.1.1.1", "-router.example"],
)
def test_telnet_connect_rejects_unsafe_hosts(host: str) -> None:
    with pytest.raises(ValidationError):
        TelnetConnectMessage(
            type="connect", host=host, port=23, cols=80, rows=24
        )


def test_telnet_models_are_strict_and_bound_terminal_messages() -> None:
    with pytest.raises(ValidationError):
        TelnetConnectMessage.model_validate(
            {
                "type": "connect",
                "host": "router.example",
                "port": "23",
                "cols": 80,
                "rows": 24,
            }
        )
    with pytest.raises(ValidationError):
        TelnetResizeMessage(type="resize", cols=1, rows=24)
    with pytest.raises(ValidationError):
        TelnetResizeMessage(type="resize", cols=80, rows=257)


def test_telnet_input_requires_bounded_canonical_base64() -> None:
    raw = b"login\r\n"
    message = TelnetInputMessage(
        type="input", data=base64.b64encode(raw).decode("ascii")
    )
    assert message.decode() == raw

    with pytest.raises(ValidationError):
        TelnetInputMessage(type="input", data="not base64")
    with pytest.raises(ValidationError):
        TelnetInputMessage(
            type="input",
            data=base64.b64encode(
                b"x" * (TELNET_INPUT_LIMIT_BYTES + 1)
            ).decode("ascii"),
        )
