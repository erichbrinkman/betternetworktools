from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from better_network_tools.ssh_models import (
    SSH_INPUT_LIMIT_BYTES,
    SshConnectMessage,
    SshInputMessage,
    SshPasswordAuth,
    SshResizeMessage,
)


def test_connect_message_is_strict_and_keeps_password_out_of_representations() -> None:
    message = SshConnectMessage.model_validate(
        {
            "type": "connect",
            "host": "router.example",
            "port": 2222,
            "username": "network-admin",
            "auth": {
                "type": "password",
                "password": "  correct horse battery  ",
            },
            "known_host_key": "ssh-ed25519 Y3VycmVudC1ob3N0LWtleQ==",
            "cols": 132,
            "rows": 40,
        }
    )

    assert message.host == "router.example"
    assert isinstance(message.auth, SshPasswordAuth)
    assert message.auth.password.get_secret_value() == "  correct horse battery  "
    assert "correct horse battery" not in repr(message)
    assert "correct horse battery" not in str(message)

    invalid_messages = [
        {"type": "connect", "host": "https://router", "username": "admin"},
        {"type": "connect", "host": "999.1.2.3", "username": "admin"},
        {"type": "connect", "host": "router", "username": "bad user"},
        {"type": "connect", "host": "router", "username": "admin", "port": True},
        {
            "type": "connect",
            "host": "router",
            "username": "admin",
            "unexpected": "rejected",
        },
        {
            "type": "connect",
            "host": "router",
            "username": "admin",
            "known_host_key": "not a public key",
        },
    ]
    for payload in invalid_messages:
        with pytest.raises(ValidationError):
            SshConnectMessage.model_validate(payload)


def test_terminal_input_is_base64_byte_safe_and_bounded() -> None:
    raw = b"\x00\xff\r\n"
    message = SshInputMessage(
        type="input", data=base64.b64encode(raw).decode("ascii")
    )
    assert message.decode() == raw

    with pytest.raises(ValidationError):
        SshInputMessage(type="input", data="not base64!!!")
    with pytest.raises(ValidationError):
        SshInputMessage(
            type="input",
            data=base64.b64encode(b"x" * (SSH_INPUT_LIMIT_BYTES + 1)).decode(
                "ascii"
            ),
        )


def test_terminal_resize_rejects_coercion_and_unreasonable_dimensions() -> None:
    assert SshResizeMessage(type="resize", cols=120, rows=36).pixel_width == 0

    with pytest.raises(ValidationError):
        SshResizeMessage(type="resize", cols=True, rows=24)
    with pytest.raises(ValidationError):
        SshResizeMessage(type="resize", cols=513, rows=24)
    with pytest.raises(ValidationError):
        SshResizeMessage(type="resize", cols=80, rows=0)
