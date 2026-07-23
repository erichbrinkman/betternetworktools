from __future__ import annotations

import httpx
import pytest
import uvicorn

from better_network_tools import main as main_module
from better_network_tools.config import Settings, load_settings, normalize_cors_origins
from better_network_tools.main import create_app


@pytest.mark.asyncio
async def test_cors_allows_only_normalized_configured_origins() -> None:
    app = create_app(
        Settings(
            cors_origins=(
                " HTTP://LOCALHOST:4173/ ",
                "http://localhost:4173",
            )
        )
    )
    assert app.state.settings.cors_origins == ("http://localhost:4173",)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        allowed = await client.options(
            "/api/scans",
            headers={
                "Origin": "http://localhost:4173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert allowed.status_code == 200
        assert (
            allowed.headers["access-control-allow-origin"]
            == "http://localhost:4173"
        )

        unconfigured = await client.options(
            "/api/scans",
            headers={
                "Origin": "http://localhost:9999",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert unconfigured.status_code == 400
        assert "access-control-allow-origin" not in unconfigured.headers


def test_environment_origins_are_canonicalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "BNT_CORS_ORIGINS",
        " HTTPS://LOCALHOST:443/, http://127.0.0.1:3000/ ",
    )

    assert load_settings().cors_origins == (
        "https://localhost",
        "http://127.0.0.1:3000",
    )


@pytest.mark.parametrize(
    "origin",
    (
        "https://example.com",
        "http://192.168.1.20:3000",
    ),
)
def test_cors_refuses_non_loopback_origins(origin: str) -> None:
    with pytest.raises(
        ValueError,
        match="BNT_CORS_ORIGINS entries must use localhost or a loopback IP",
    ):
        normalize_cors_origins((origin,))


@pytest.mark.asyncio
async def test_http_api_refuses_non_loopback_clients() -> None:
    app = create_app(Settings())
    transport = httpx.ASGITransport(
        app=app,
        client=("192.0.2.10", 54321),
    )

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://192.0.2.20",
    ) as client:
        response = await client.get("/api/health")

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "api_requires_loopback"


def test_console_startup_refuses_non_loopback_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BNT_HOST", "0.0.0.0")
    started = False

    def unexpected_start(*args: object, **kwargs: object) -> None:
        nonlocal started
        started = True

    monkeypatch.setattr(uvicorn, "run", unexpected_start)

    with pytest.raises(
        ValueError, match="BNT_HOST must be localhost or a loopback IP address"
    ):
        main_module.run()
    assert started is False
