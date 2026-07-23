"""FastAPI application for Better Network Tools."""

from __future__ import annotations

import platform
import sys
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .config import (
    Settings,
    load_settings,
    normalize_cors_origins,
    normalize_loopback_host,
)
from .models import (
    HealthResponse,
    PingJobRequest,
    PingJobResponse,
    PortJobRequest,
    PortJobResponse,
    ScanJobResponse,
    ScanRequest,
    ScanResultsResponse,
    ScanSummaryResponse,
    SpeedJobRequest,
    SpeedJobResponse,
    SpeedServerListResponse,
    SystemCapabilities,
    SystemLimits,
    SystemResponse,
    TraceJobRequest,
    TraceJobResponse,
)
from .ping_service import (
    PingJobCapacityError,
    PingJobNotFoundError,
    PingJobService,
)
from .ping_validation import PingValidationError
from .port_service import (
    PortJobCapacityError,
    PortJobNotFoundError,
    PortJobService,
)
from .port_validation import PortValidationError
from .oui import (
    InvalidMacAddress,
    OuiDatabaseUnavailableError,
    OuiLookupResponse,
    OuiLookupService,
    VendorNotFoundError,
)
from .service import (
    DEFAULT_SCAN_LIST_LIMIT,
    MAX_SCAN_LIST_LIMIT,
    ScanNotFoundError,
    ScanService,
)
from .speed_service import (
    SpeedJobCapacityError,
    SpeedJobNotFoundError,
    SpeedJobService,
    SpeedJobSizeError,
)
from .speedtest import SpeedServerNotFoundError
from .ssh_service import (
    SshSessionHandler,
    SshSessionService,
    quickssh_bind_is_loopback,
    quickssh_scope_is_loopback,
    websocket_origin_allowed,
)
from .telnet_service import (
    TelnetSessionHandler,
    TelnetSessionService,
    telnet_bind_is_loopback,
    telnet_origin_allowed,
    telnet_scope_is_loopback,
)
from .terminal_sessions import InteractiveSessionLimiter
from .trace_service import (
    TraceJobCapacityError,
    TraceJobNotFoundError,
    TraceJobService,
)
from .trace_validation import TraceValidationError
from .tftp_models import (
    TftpFileListResponse,
    TftpFileResponse,
    TftpServerStartRequest,
    TftpServerStatusResponse,
    TftpTransferResponse,
)
from .tftp_service import (
    TftpConfigurationError,
    TftpServerAlreadyRunningError,
    TftpServerBindError,
    TftpServerService,
)
from .transfer_models import (
    TransferFileListResponse,
    TransferServerStartRequest,
    TransferServerStatusResponse,
)
from .transfer_service import TransferServerService, TransferServiceError
from .update_models import (
    UpdateApplyRequest,
    UpdateApplyResponse,
    UpdateCheckResponse,
    UpdateOperationResponse,
)
from .update_service import (
    UpdateService,
    UpdateServiceError,
    authorize_update_request,
)
from .validation import ScanValidationError


def create_app(
    settings: Settings | None = None,
    *,
    scan_service: ScanService | None = None,
    oui_lookup_service: OuiLookupService | None = None,
    ping_job_service: PingJobService | None = None,
    port_job_service: PortJobService | None = None,
    ssh_session_service: SshSessionHandler | None = None,
    telnet_session_service: TelnetSessionHandler | None = None,
    speed_job_service: SpeedJobService | None = None,
    trace_job_service: TraceJobService | None = None,
    tftp_server_service: TftpServerService | None = None,
    transfer_server_service: TransferServerService | None = None,
    update_service: UpdateService | None = None,
) -> FastAPI:
    resolved_settings = settings or load_settings()
    resolved_settings = replace(
        resolved_settings,
        cors_origins=normalize_cors_origins(resolved_settings.cors_origins),
    )
    service = scan_service or ScanService(resolved_settings)
    oui_service = oui_lookup_service or OuiLookupService()
    ping_service = ping_job_service or PingJobService(resolved_settings)
    port_service = port_job_service or PortJobService(resolved_settings)
    terminal_session_limiter = InteractiveSessionLimiter(
        max(
            resolved_settings.ssh_active_session_limit,
            resolved_settings.telnet_active_session_limit,
        )
    )
    ssh_service = ssh_session_service or SshSessionService(
        resolved_settings, session_limiter=terminal_session_limiter
    )
    telnet_service = telnet_session_service or TelnetSessionService(
        resolved_settings, session_limiter=terminal_session_limiter
    )
    speed_service = speed_job_service or SpeedJobService(resolved_settings)
    trace_service = trace_job_service or TraceJobService(resolved_settings)
    legacy_tftp_service = tftp_server_service
    transfer_service = transfer_server_service or TransferServerService(
        resolved_settings
    )
    updater = update_service or UpdateService(
        current_version=__version__,
        repository=resolved_settings.update_repository,
        branch=resolved_settings.update_branch,
        check_timeout_seconds=resolved_settings.update_check_timeout_seconds,
        total_check_timeout_seconds=(
            resolved_settings.update_total_check_timeout_seconds
        ),
        git_timeout_seconds=resolved_settings.update_git_timeout_seconds,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await service.shutdown()
        await ping_service.shutdown()
        await port_service.shutdown()
        await ssh_service.shutdown()
        await telnet_service.shutdown()
        await speed_service.shutdown()
        await trace_service.shutdown()
        await transfer_service.shutdown()
        if legacy_tftp_service is not None:
            await legacy_tftp_service.shutdown()
        await updater.shutdown()

    application = FastAPI(
        title="Better Network Tools API",
        description="Local API for Better Network Tools applications.",
        version=__version__,
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.scan_service = service
    application.state.oui_lookup_service = oui_service
    application.state.ping_job_service = ping_service
    application.state.port_job_service = port_service
    application.state.ssh_session_service = ssh_service
    application.state.telnet_session_service = telnet_service
    application.state.terminal_session_limiter = terminal_session_limiter
    application.state.speed_job_service = speed_service
    application.state.trace_job_service = trace_service
    application.state.transfer_server_service = transfer_service
    application.state.tftp_server_service = legacy_tftp_service or transfer_service
    application.state.update_service = updater
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(resolved_settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Content-Type"],
    )

    @application.middleware("http")
    async def require_loopback_client(request: Request, call_next):
        client_host = request.client.host if request.client else ""
        try:
            normalize_loopback_host(client_host)
        except ValueError:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "detail": {
                        "code": "api_requires_loopback",
                        "message": "The Better Network Tools API accepts only local clients",
                    }
                },
            )
        return await call_next(request)

    def not_found(scan_id: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "scan_not_found", "message": f"scan {scan_id} was not found"},
        )

    def ping_job_not_found(job_id: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "ping_job_not_found",
                "message": f"ping job {job_id} was not found",
            },
        )

    def port_job_not_found(job_id: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "port_job_not_found",
                "message": f"NetPorts job {job_id} was not found",
            },
        )

    def trace_job_not_found(job_id: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "trace_job_not_found",
                "message": f"trace job {job_id} was not found",
            },
        )

    def speed_job_not_found(job_id: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "speed_job_not_found",
                "message": f"speed job {job_id} was not found",
            },
        )

    def require_update_request(request: Request, *, mutation: bool) -> None:
        try:
            authorize_update_request(
                api_host=resolved_settings.host,
                client_host=request.client.host if request.client else None,
                origin=request.headers.get("origin"),
                allowed_origins=resolved_settings.cors_origins,
                mutation=mutation,
            )
        except UpdateServiceError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail=exc.as_detail()
            ) from exc

    def update_http_error(exc: UpdateServiceError) -> HTTPException:
        return HTTPException(status_code=exc.status_code, detail=exc.as_detail())

    @application.get("/api/health", response_model=HealthResponse, tags=["system"])
    async def health() -> HealthResponse:
        return HealthResponse(
            service="better-network-tools-api", version=__version__
        )

    @application.post(
        "/api/updates/check",
        response_model=UpdateCheckResponse,
        tags=["system"],
        summary="Check the official GitHub release for a safe local update",
    )
    async def check_for_updates(request: Request) -> UpdateCheckResponse:
        require_update_request(request, mutation=True)
        try:
            return await updater.check()
        except UpdateServiceError as exc:
            raise update_http_error(exc) from exc

    @application.get(
        "/api/updates/status",
        response_model=UpdateOperationResponse,
        tags=["system"],
        summary="Recover the current local update operation status",
    )
    async def update_status(request: Request) -> UpdateOperationResponse:
        require_update_request(request, mutation=False)
        return updater.operation_status()

    @application.post(
        "/api/updates/apply",
        response_model=UpdateApplyResponse,
        tags=["system"],
        summary="Fast-forward a clean local checkout to the checked release",
    )
    async def apply_update(
        update_request: UpdateApplyRequest,
        request: Request,
    ) -> UpdateApplyResponse:
        require_update_request(request, mutation=True)
        try:
            return await updater.apply(update_request)
        except UpdateServiceError as exc:
            raise update_http_error(exc) from exc

    @application.get("/api/system", response_model=SystemResponse, tags=["system"])
    async def system_information() -> SystemResponse:
        return SystemResponse(
            name="Better Network Tools API",
            version=__version__,
            platform=platform.system(),
            platform_release=platform.release(),
            python_version=platform.python_version(),
            capabilities=SystemCapabilities(),
            limits=SystemLimits(
                max_hosts=resolved_settings.scan_host_limit,
                max_ports=resolved_settings.max_ports,
                max_concurrency=resolved_settings.scan_concurrency,
                max_ssh_sessions=resolved_settings.ssh_active_session_limit,
                max_telnet_sessions=resolved_settings.telnet_active_session_limit,
                max_trace_hops=resolved_settings.trace_hop_limit,
                max_trace_jobs=resolved_settings.trace_active_job_limit,
                max_speed_jobs=resolved_settings.speed_active_job_limit,
                max_speed_test_seconds=resolved_settings.speed_total_timeout_seconds,
                min_speed_download_bytes=(
                    resolved_settings.speed_download_byte_minimum
                ),
                default_speed_download_bytes=(
                    resolved_settings.speed_download_byte_default
                ),
                max_speed_download_bytes=resolved_settings.speed_download_byte_limit,
                min_speed_upload_bytes=resolved_settings.speed_upload_byte_minimum,
                default_speed_upload_bytes=resolved_settings.speed_upload_byte_default,
                max_speed_upload_bytes=resolved_settings.speed_upload_byte_limit,
                max_port_scan_ports=resolved_settings.port_scan_port_limit,
                max_port_scan_concurrency=resolved_settings.port_scan_concurrency,
                max_port_scan_jobs=resolved_settings.port_scan_active_job_limit,
                max_port_scan_connect_seconds=(
                    resolved_settings.port_scan_timeout_limit_seconds
                ),
                max_port_scan_seconds=(
                    resolved_settings.port_scan_total_timeout_seconds
                ),
                max_port_scan_results=resolved_settings.port_scan_result_limit,
                max_retained_port_scan_jobs=(
                    resolved_settings.port_scan_retained_job_limit
                ),
            ),
        )

    @application.websocket("/api/ssh")
    async def quickssh(websocket: WebSocket) -> None:
        if not quickssh_bind_is_loopback(
            resolved_settings.host
        ) or not quickssh_scope_is_loopback(websocket.scope):
            await websocket.close(
                code=1008, reason="QuickSSH requires a loopback-bound local service"
            )
            return
        if not websocket_origin_allowed(
            websocket.headers.get("origin"), resolved_settings.cors_origins
        ):
            await websocket.close(code=1008, reason="WebSocket origin is not allowed")
            return
        await websocket.accept()
        await ssh_service.handle(websocket)

    @application.websocket("/api/telnet")
    async def telnet(websocket: WebSocket) -> None:
        if not telnet_bind_is_loopback(
            resolved_settings.host
        ) or not telnet_scope_is_loopback(websocket.scope):
            await websocket.close(
                code=1008,
                reason="Telnet requires a loopback-bound local service",
            )
            return
        if not telnet_origin_allowed(
            websocket.headers.get("origin"), resolved_settings.cors_origins
        ):
            await websocket.close(code=1008, reason="WebSocket origin is not allowed")
            return
        await websocket.accept()
        await telnet_service.handle(websocket)

    @application.get(
        "/api/transfer-server",
        response_model=TransferServerStatusResponse,
        tags=["NetTransfer"],
        summary="Get the local file-transfer server configuration and activity",
    )
    async def get_transfer_server() -> TransferServerStatusResponse:
        return await transfer_service.status()

    @application.post(
        "/api/transfer-server",
        response_model=TransferServerStatusResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["NetTransfer"],
        summary="Start one local TFTP, SFTP, or FTP server",
    )
    async def start_transfer_server(
        request: TransferServerStartRequest,
    ) -> TransferServerStatusResponse:
        try:
            return await transfer_service.start(request)
        except TransferServiceError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail=exc.as_detail()
            ) from exc

    @application.delete(
        "/api/transfer-server",
        response_model=TransferServerStatusResponse,
        tags=["NetTransfer"],
        summary="Stop the active local file-transfer server",
    )
    async def stop_transfer_server() -> TransferServerStatusResponse:
        return await transfer_service.stop()

    @application.get(
        "/api/transfer-server/files",
        response_model=TransferFileListResponse,
        tags=["NetTransfer"],
        summary="List bounded files beneath the shared NetTransfer root",
    )
    async def list_transfer_files() -> TransferFileListResponse:
        return await transfer_service.list_files()

    async def legacy_tftp_status() -> TftpServerStatusResponse:
        if legacy_tftp_service is not None:
            return await legacy_tftp_service.status()
        current = await transfer_service.status()
        is_tftp = current.protocol == "tftp"
        transfers = [
            TftpTransferResponse(
                id=item.id,
                direction=item.direction,
                status=item.status,
                filename=item.filename,
                client=item.client,
                bytes_transferred=item.bytes_transferred,
                started_at=item.started_at,
                finished_at=item.finished_at,
                error=item.error,
            )
            for item in current.recent_transfers
            if item.protocol == "tftp"
        ]
        return TftpServerStatusResponse(
            state="running" if is_tftp and current.running else "stopped",
            running=is_tftp and current.running,
            bind_address=(
                current.bind_address
                if is_tftp
                else resolved_settings.transfer_default_bind_address
            ),
            port=(
                current.port
                if is_tftp and current.port is not None
                else resolved_settings.transfer_tftp_default_port
            ),
            root_directory=current.root_directory,
            allow_read=current.allow_read if is_tftp else True,
            allow_write=current.allow_write if is_tftp else False,
            allow_overwrite=current.allow_overwrite if is_tftp else False,
            allowed_client_cidrs=(
                current.allowed_client_cidrs if is_tftp else ["127.0.0.0/8"]
            ),
            started_at=current.started_at if is_tftp else None,
            active_transfer_count=current.active_transfer_count if is_tftp else 0,
            completed_transfer_count=(
                current.completed_transfer_count if is_tftp else 0
            ),
            failed_transfer_count=current.failed_transfer_count if is_tftp else 0,
            bytes_sent=current.bytes_sent if is_tftp else 0,
            bytes_received=current.bytes_received if is_tftp else 0,
            recent_transfers=transfers if is_tftp else [],
        )

    @application.get(
        "/api/tftp-server",
        response_model=TftpServerStatusResponse,
        deprecated=True,
        tags=["NetTransfer compatibility"],
        summary="Get the legacy TFTP-only status view",
    )
    async def get_tftp_server() -> TftpServerStatusResponse:
        return await legacy_tftp_status()

    @application.post(
        "/api/tftp-server",
        response_model=TftpServerStatusResponse,
        status_code=status.HTTP_201_CREATED,
        deprecated=True,
        tags=["NetTransfer compatibility"],
        summary="Start TFTP through the legacy endpoint",
    )
    async def start_tftp_server(
        request: TftpServerStartRequest,
    ) -> TftpServerStatusResponse:
        try:
            if legacy_tftp_service is not None:
                return await legacy_tftp_service.start(request)
            await transfer_service.start(
                TransferServerStartRequest(
                    protocol="tftp",
                    bind_address=request.bind_address,
                    port=request.port,
                    allow_read=request.allow_read,
                    allow_write=request.allow_write,
                    allow_overwrite=request.allow_overwrite,
                    allowed_client_cidrs=request.allowed_client_cidrs,
                )
            )
            return await legacy_tftp_status()
        except TftpConfigurationError as exc:
            raise HTTPException(status_code=422, detail=exc.as_detail()) from exc
        except (TftpServerAlreadyRunningError, TftpServerBindError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=exc.as_detail()
            ) from exc
        except TransferServiceError as exc:
            raise HTTPException(
                status_code=exc.status_code, detail=exc.as_detail()
            ) from exc

    @application.delete(
        "/api/tftp-server",
        response_model=TftpServerStatusResponse,
        deprecated=True,
        tags=["NetTransfer compatibility"],
        summary="Stop TFTP through the legacy endpoint",
    )
    async def stop_tftp_server() -> TftpServerStatusResponse:
        if legacy_tftp_service is not None:
            return await legacy_tftp_service.stop()
        current = await transfer_service.status()
        if current.protocol == "tftp":
            await transfer_service.stop()
        return await legacy_tftp_status()

    @application.get(
        "/api/tftp-server/files",
        response_model=TftpFileListResponse,
        deprecated=True,
        tags=["NetTransfer compatibility"],
        summary="List files through the legacy TFTP endpoint",
    )
    async def list_tftp_files() -> TftpFileListResponse:
        if legacy_tftp_service is not None:
            return await legacy_tftp_service.list_files()
        listing = await transfer_service.list_files()
        return TftpFileListResponse(
            root_directory=listing.root_directory,
            files=[
                TftpFileResponse(
                    filename=item.filename,
                    size=item.size,
                    modified_at=item.modified_at,
                )
                for item in listing.files
            ],
            truncated=listing.truncated,
        )

    @application.get(
        "/api/oui", response_model=OuiLookupResponse, tags=["MAC OUI Lookup"]
    )
    def lookup_oui(
        mac: Annotated[
            str,
            Query(
                min_length=1,
                max_length=64,
                description="A 48-bit MAC address or 24-bit OUI prefix",
                examples=["00:50:56:C0:00:08"],
            ),
        ],
    ) -> OuiLookupResponse:
        try:
            return oui_service.lookup(mac)
        except InvalidMacAddress as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_mac", "message": str(exc)},
            ) from exc
        except VendorNotFoundError as exc:
            normalized = exc.normalized
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "code": "vendor_not_found",
                    "message": (
                        f"No vendor was found for OUI {normalized.matched_prefix}."
                    ),
                    "normalized": normalized.normalized,
                    "matched_prefix": normalized.matched_prefix,
                },
            ) from exc
        except OuiDatabaseUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "code": "oui_database_unavailable",
                    "message": "The local OUI database is unavailable.",
                },
            ) from exc

    @application.post(
        "/api/scans",
        response_model=ScanJobResponse,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["NetScanner"],
    )
    async def create_scan(request: ScanRequest) -> ScanJobResponse:
        try:
            return await service.create_scan(request)
        except ScanValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail=exc.as_detail(),
            ) from exc

    @application.get(
        "/api/scans",
        response_model=list[ScanSummaryResponse],
        tags=["NetScanner"],
        summary="List recent NetScanner jobs without device results",
    )
    async def list_scans(
        limit: Annotated[
            int,
            Query(
                ge=1,
                le=MAX_SCAN_LIST_LIMIT,
                description="Maximum number of recent scans to return",
            ),
        ] = DEFAULT_SCAN_LIST_LIMIT,
    ) -> list[ScanSummaryResponse]:
        return await service.list_scans(limit=limit)

    @application.post(
        "/api/port-jobs",
        response_model=PortJobResponse,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["NetPorts"],
        summary="Start a bounded single-target TCP connect scan",
    )
    async def create_port_job(request: PortJobRequest) -> PortJobResponse:
        try:
            return await port_service.create_job(request)
        except PortValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.as_detail()) from exc
        except PortJobCapacityError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=exc.as_detail(),
            ) from exc

    @application.get(
        "/api/port-jobs/{job_id}",
        response_model=PortJobResponse,
        tags=["NetPorts"],
        summary="Get live NetPorts scan progress and open ports",
    )
    async def get_port_job(job_id: str) -> PortJobResponse:
        try:
            return await port_service.get_job(job_id)
        except PortJobNotFoundError as exc:
            raise port_job_not_found(job_id) from exc

    @application.delete(
        "/api/port-jobs/{job_id}",
        response_model=PortJobResponse,
        tags=["NetPorts"],
        summary="Cancel a running NetPorts scan",
    )
    async def cancel_port_job(job_id: str) -> PortJobResponse:
        try:
            return await port_service.cancel_job(job_id)
        except PortJobNotFoundError as exc:
            raise port_job_not_found(job_id) from exc

    @application.post(
        "/api/ping-jobs",
        response_model=PingJobResponse,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["NetPinger"],
        summary="Start a multi-target ping job",
    )
    async def create_ping_job(request: PingJobRequest) -> PingJobResponse:
        try:
            return await ping_service.create_job(request)
        except PingValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.as_detail()) from exc
        except PingJobCapacityError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=exc.as_detail(),
            ) from exc

    @application.get(
        "/api/ping-jobs/{job_id}",
        response_model=PingJobResponse,
        tags=["NetPinger"],
        summary="Get live ping job status and statistics",
    )
    async def get_ping_job(job_id: str) -> PingJobResponse:
        try:
            return await ping_service.get_job(job_id)
        except PingJobNotFoundError as exc:
            raise ping_job_not_found(job_id) from exc

    @application.delete(
        "/api/ping-jobs/{job_id}",
        response_model=PingJobResponse,
        tags=["NetPinger"],
        summary="Cancel a running ping job",
    )
    async def cancel_ping_job(job_id: str) -> PingJobResponse:
        try:
            return await ping_service.cancel_job(job_id)
        except PingJobNotFoundError as exc:
            raise ping_job_not_found(job_id) from exc

    @application.get(
        "/api/speed-servers",
        response_model=SpeedServerListResponse,
        tags=["NetSpeed"],
        summary="List allowlisted public speed-test servers",
    )
    async def list_speed_servers() -> SpeedServerListResponse:
        return await speed_service.list_servers()

    @application.post(
        "/api/speed-jobs",
        response_model=SpeedJobResponse,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["NetSpeed"],
        summary="Start a bounded internet speed test",
    )
    async def create_speed_job(request: SpeedJobRequest) -> SpeedJobResponse:
        try:
            return await speed_service.create_job(request)
        except SpeedServerNotFoundError as exc:
            raise HTTPException(status_code=422, detail=exc.as_detail()) from exc
        except SpeedJobSizeError as exc:
            raise HTTPException(status_code=422, detail=exc.as_detail()) from exc
        except SpeedJobCapacityError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=exc.as_detail(),
            ) from exc

    @application.get(
        "/api/speed-jobs/{job_id}",
        response_model=SpeedJobResponse,
        tags=["NetSpeed"],
        summary="Get a speed-test job",
    )
    async def get_speed_job(job_id: str) -> SpeedJobResponse:
        try:
            return await speed_service.get_job(job_id)
        except SpeedJobNotFoundError as exc:
            raise speed_job_not_found(job_id) from exc

    @application.delete(
        "/api/speed-jobs/{job_id}",
        response_model=SpeedJobResponse,
        tags=["NetSpeed"],
        summary="Cancel a running speed test",
    )
    async def cancel_speed_job(job_id: str) -> SpeedJobResponse:
        try:
            return await speed_service.cancel_job(job_id)
        except SpeedJobNotFoundError as exc:
            raise speed_job_not_found(job_id) from exc

    @application.post(
        "/api/trace-jobs",
        response_model=TraceJobResponse,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["NetTrace"],
        summary="Start a traceroute job",
    )
    async def create_trace_job(request: TraceJobRequest) -> TraceJobResponse:
        try:
            return await trace_service.create_job(request)
        except TraceValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.as_detail()) from exc
        except TraceJobCapacityError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=exc.as_detail(),
            ) from exc

    @application.get(
        "/api/trace-jobs/{job_id}",
        response_model=TraceJobResponse,
        tags=["NetTrace"],
        summary="Get traceroute status, hops, and ASN path",
    )
    async def get_trace_job(job_id: str) -> TraceJobResponse:
        try:
            return await trace_service.get_job(job_id)
        except TraceJobNotFoundError as exc:
            raise trace_job_not_found(job_id) from exc

    @application.delete(
        "/api/trace-jobs/{job_id}",
        response_model=TraceJobResponse,
        tags=["NetTrace"],
        summary="Cancel a running traceroute job",
    )
    async def cancel_trace_job(job_id: str) -> TraceJobResponse:
        try:
            return await trace_service.cancel_job(job_id)
        except TraceJobNotFoundError as exc:
            raise trace_job_not_found(job_id) from exc

    @application.get(
        "/api/scans/{scan_id}", response_model=ScanJobResponse, tags=["NetScanner"]
    )
    async def get_scan(scan_id: str) -> ScanJobResponse:
        try:
            return await service.get_scan(scan_id)
        except ScanNotFoundError as exc:
            raise not_found(scan_id) from exc

    @application.get(
        "/api/scans/{scan_id}/results",
        response_model=ScanResultsResponse,
        tags=["NetScanner"],
    )
    async def get_scan_results(scan_id: str) -> ScanResultsResponse:
        try:
            return await service.get_results(scan_id)
        except ScanNotFoundError as exc:
            raise not_found(scan_id) from exc

    @application.delete(
        "/api/scans/{scan_id}", response_model=ScanJobResponse, tags=["NetScanner"]
    )
    async def cancel_scan(scan_id: str) -> ScanJobResponse:
        try:
            return await service.cancel_scan(scan_id)
        except ScanNotFoundError as exc:
            raise not_found(scan_id) from exc

    return application


app = create_app()


def run() -> None:
    import uvicorn

    settings = load_settings()
    host = normalize_loopback_host(settings.host)
    uvicorn.run(
        "better_network_tools.main:app",
        host=host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":  # pragma: no cover - exercised by the console script
    sys.exit(run())
