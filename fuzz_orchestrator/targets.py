"""Target adapters for local binaries and simple network protocols."""

from __future__ import annotations

import base64
import hashlib
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

try:  # resource.prlimit is available on Linux and some other POSIX systems.
    import resource
except ImportError:  # pragma: no cover - exercised on Windows only
    resource = None  # type: ignore[assignment]
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote_from_bytes, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .config import host_is_allowed
from .models import (
    BinaryTargetConfig,
    DifferentialTargetConfig,
    ExecutionResult,
    HttpTargetConfig,
    SafetyConfig,
    TargetConfig,
    TcpTargetConfig,
    UdpTargetConfig,
)


class Target(Protocol):
    def execute(self, payload: bytes, case_id: str) -> ExecutionResult:
        """Execute one test case and return a bounded result."""


def _now() -> float:
    return time.perf_counter()


def _duration(start: float) -> float:
    return round((_now() - start) * 1000.0, 3)


_MAX_RENDERED_FRAME_BYTES = 32 * 1024 * 1024


def _render_frames(frames: tuple[str, ...], payload: bytes) -> tuple[bytes, ...]:
    if not frames:
        return (payload,)
    rendered: list[bytes] = []
    for template in frames:
        pieces = template.split("{input}")
        value = bytearray()
        for index, piece in enumerate(pieces):
            value.extend(piece.encode("utf-8"))
            if index < len(pieces) - 1:
                value.extend(payload)
        if len(value) > _MAX_RENDERED_FRAME_BYTES:
            raise ValueError("rendered network frame exceeds 32 MiB")
        rendered.append(bytes(value))
    return tuple(rendered)


def _bounded_reader(stream: Any, limit: int, output: bytearray, flags: dict[str, bool]) -> None:
    total = 0
    try:
        while True:
            chunk = stream.read(65_536)
            if not chunk:
                return
            total += len(chunk)
            if len(output) < limit:
                output.extend(chunk[: limit - len(output)])
            if total > limit:
                flags["truncated"] = True
    except (OSError, ValueError):
        # The process may be terminated while a reader is blocked.  The
        # execution status remains useful even if the final bytes are absent.
        return


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    """Terminate a process and, on POSIX, its whole process group."""

    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=0.25)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass


def _apply_memory_limit(
    process: subprocess.Popen[bytes], max_memory_mb: int | None
) -> tuple[bool | None, str | None]:
    if max_memory_mb is None:
        return None, None
    if resource is None or not hasattr(resource, "prlimit"):
        return False, "memory limits require a POSIX platform with resource.prlimit"
    try:
        limit = max_memory_mb * 1024 * 1024
        resource.prlimit(process.pid, resource.RLIMIT_AS, (limit, limit))
    except (AttributeError, OSError, PermissionError, ValueError) as exc:
        return False, str(exc)
    return True, None


class BinaryTarget:
    def __init__(self, config: BinaryTargetConfig, timeout_seconds: float):
        self.config = config
        self.timeout_seconds = timeout_seconds

    def execute(self, payload: bytes, case_id: str) -> ExecutionResult:
        start = _now()
        try:
            if self.config.input_mode == "file":
                with tempfile.TemporaryDirectory(prefix=f"fuzz-{case_id}-") as directory:
                    input_path = Path(directory) / "input.bin"
                    input_path.write_bytes(payload)
                    command = self._render_command(str(input_path))
                    return self._run(command, None, len(payload), case_id, start)
            if self.config.input_mode == "argv":
                argument = payload.decode("utf-8", errors="replace").replace("\x00", "")
                command = self._render_command(argument)
                return self._run(command, None, len(payload), case_id, start)
            return self._run(self.config.command, payload, len(payload), case_id, start)
        except (OSError, ValueError) as exc:
            return ExecutionResult(
                case_id=case_id,
                status="error",
                duration_ms=_duration(start),
                input_size=len(payload),
                stderr=str(exc).encode("utf-8", errors="replace"),
                metadata={"exception": type(exc).__name__},
            )

    def _render_command(self, value: str) -> tuple[str, ...]:
        return tuple(item.replace("{input}", value) for item in self.config.command)

    def _run(
        self,
        command: tuple[str, ...],
        payload: bytes | None,
        input_size: int,
        case_id: str,
        start: float,
    ) -> ExecutionResult:
        stdout = bytearray()
        stderr = bytearray()
        stdout_flags: dict[str, bool] = {"truncated": False}
        stderr_flags: dict[str, bool] = {"truncated": False}
        input_pipe = subprocess.PIPE if payload is not None else subprocess.DEVNULL
        try:
            process = subprocess.Popen(
                list(command),
                cwd=str(self.config.cwd) if self.config.cwd else None,
                env={**os.environ, **dict(self.config.env)},
                stdin=input_pipe,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
            )
        except (OSError, ValueError) as exc:
            return ExecutionResult(
                case_id=case_id,
                status="error",
                duration_ms=_duration(start),
                input_size=input_size,
                stderr=str(exc).encode("utf-8", errors="replace"),
                metadata={"exception": type(exc).__name__, "command": list(command)},
            )

        memory_limit_applied, memory_limit_error = _apply_memory_limit(
            process, self.config.max_memory_mb
        )
        if memory_limit_error is not None:
            _terminate_process(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
            return ExecutionResult(
                case_id=case_id,
                status="error",
                duration_ms=_duration(start),
                input_size=input_size,
                stderr=memory_limit_error.encode("utf-8", errors="replace"),
                metadata={
                    "command": list(command),
                    "memory_limit_mb": self.config.max_memory_mb,
                    "memory_limit_applied": memory_limit_applied,
                },
            )

        assert process.stdout is not None
        assert process.stderr is not None
        stdout_thread = threading.Thread(
            target=_bounded_reader,
            args=(process.stdout, self.config.max_output_bytes, stdout, stdout_flags),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_bounded_reader,
            args=(process.stderr, self.config.max_output_bytes, stderr, stderr_flags),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()

        writer_thread: threading.Thread | None = None
        if payload is not None and process.stdin is not None:
            def write_input() -> None:
                try:
                    process.stdin.write(payload)
                    process.stdin.close()
                except (BrokenPipeError, OSError, ValueError):
                    try:
                        process.stdin.close()
                    except (OSError, ValueError):
                        pass

            writer_thread = threading.Thread(target=write_input, daemon=True)
            writer_thread.start()
        elif process.stdin is not None:
            process.stdin.close()

        timed_out = False
        try:
            process.wait(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process(process)

        if writer_thread is not None:
            writer_thread.join(timeout=0.5)
        stdout_thread.join(timeout=1.0)
        stderr_thread.join(timeout=1.0)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        returncode = process.poll()

        metadata = {
            "command": list(command),
            "input_mode": self.config.input_mode,
            "stdout_truncated": stdout_flags["truncated"],
            "stderr_truncated": stderr_flags["truncated"],
            "memory_limit_mb": self.config.max_memory_mb,
            "memory_limit_applied": memory_limit_applied,
        }
        if timed_out:
            status = "timeout"
        elif returncode in self.config.expected_exit_codes:
            status = "ok"
        elif returncode is not None and returncode < 0:
            status = "crash"
        else:
            status = "nonzero_exit"
        return ExecutionResult(
            case_id=case_id,
            status=status,
            duration_ms=_duration(start),
            input_size=input_size,
            returncode=returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            metadata=metadata,
        )


def _network_error_status(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, URLError) and isinstance(exc.reason, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, (ConnectionError, OSError, URLError)):
        return "connection_error"
    return "error"


def _network_error(
    case_id: str,
    payload: bytes,
    start: float,
    exc: BaseException,
) -> ExecutionResult:
    return ExecutionResult(
        case_id=case_id,
        status=_network_error_status(exc),
        duration_ms=_duration(start),
        input_size=len(payload),
        stderr=str(exc).encode("utf-8", errors="replace"),
        metadata={"exception": type(exc).__name__},
    )


def _read_socket_response(sock: socket.socket, limit: int) -> tuple[bytes, bool]:
    response = bytearray()
    truncated = False
    while len(response) < limit:
        chunk = sock.recv(min(65_536, limit - len(response) + 1))
        if not chunk:
            break
        response.extend(chunk)
        if len(response) > limit:
            response = response[:limit]
            truncated = True
            break
    return bytes(response), truncated


class TcpTarget:
    def __init__(
        self,
        config: TcpTargetConfig,
        timeout_seconds: float,
        max_response_bytes: int,
        request_wait: Callable[[], float] | None = None,
    ):
        self.config = config
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.request_wait = request_wait

    def execute(self, payload: bytes, case_id: str) -> ExecutionResult:
        start = _now()
        try:
            if self.request_wait is not None:
                self.request_wait()
            frames = _render_frames(self.config.frames, payload)
            with socket.create_connection(
                (self.config.host, self.config.port), timeout=self.timeout_seconds
            ) as sock:
                sock.settimeout(self.timeout_seconds)
                for frame in frames:
                    sock.sendall(frame)
                response = b""
                truncated = False
                response_timeout = False
                if self.config.expect_response:
                    try:
                        response, truncated = _read_socket_response(sock, self.max_response_bytes)
                    except socket.timeout:
                        response_timeout = True
                status = "timeout" if response_timeout and self.config.response_timeout_is_failure else "ok"
                return ExecutionResult(
                    case_id=case_id,
                    status=status,
                    duration_ms=_duration(start),
                    input_size=len(payload),
                    stdout=response,
                    metadata={
                        "protocol": "tcp",
                        "host": self.config.host,
                        "port": self.config.port,
                        "frame_count": len(frames),
                        "response_truncated": truncated,
                        "response_timeout": response_timeout,
                    },
                )
        except BaseException as exc:
            if isinstance(exc, KeyboardInterrupt):
                raise
            return _network_error(case_id, payload, start, exc)


class UdpTarget:
    def __init__(
        self,
        config: UdpTargetConfig,
        timeout_seconds: float,
        max_response_bytes: int,
        request_wait: Callable[[], float] | None = None,
    ):
        self.config = config
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.request_wait = request_wait

    def execute(self, payload: bytes, case_id: str) -> ExecutionResult:
        start = _now()
        family = socket.AF_INET6 if ":" in self.config.host else socket.AF_INET
        try:
            if self.request_wait is not None:
                self.request_wait()
            frames = _render_frames(self.config.frames, payload)
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout_seconds)
                sock.connect((self.config.host, self.config.port))
                for frame in frames:
                    sock.send(frame)
                response = b""
                response_timeout = False
                if self.config.expect_response:
                    try:
                        response = sock.recv(self.max_response_bytes + 1)
                    except socket.timeout:
                        response_timeout = True
                status = "timeout" if response_timeout and self.config.response_timeout_is_failure else "ok"
                return ExecutionResult(
                    case_id=case_id,
                    status=status,
                    duration_ms=_duration(start),
                    input_size=len(payload),
                    stdout=response[: self.max_response_bytes],
                    metadata={
                        "protocol": "udp",
                        "host": self.config.host,
                        "port": self.config.port,
                        "frame_count": len(frames),
                        "response_truncated": len(response) > self.max_response_bytes,
                        "response_timeout": response_timeout,
                    },
                )
        except BaseException as exc:
            if isinstance(exc, KeyboardInterrupt):
                raise
            return _network_error(case_id, payload, start, exc)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, new: str) -> None:
        return None


class HttpTarget:
    def __init__(
        self,
        config: HttpTargetConfig,
        timeout_seconds: float,
        max_response_bytes: int,
        request_wait: Callable[[], float] | None = None,
    ):
        self.config = config
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.request_wait = request_wait
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def execute(self, payload: bytes, case_id: str) -> ExecutionResult:
        start = _now()
        if self.request_wait is not None:
            self.request_wait()
        url = self._input_url(payload)
        body: bytes | None = payload if self.config.input_location == "body" else None
        headers = dict(self.config.headers)
        if self.config.input_location == "header":
            headers[self.config.input_header] = base64.b64encode(payload).decode("ascii")
        request = Request(url, data=body, headers=headers, method=self.config.method)
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                response_body = response.read(self.max_response_bytes + 1)
                status_code = getattr(response, "status", None)
                status = "server_error" if status_code is not None and status_code >= 500 else "ok"
                return ExecutionResult(
                    case_id=case_id,
                    status=status,
                    duration_ms=_duration(start),
                    input_size=len(payload),
                    response_status=status_code,
                    stdout=response_body[: self.max_response_bytes],
                    metadata={
                        "protocol": "http",
                        "url": url,
                        "method": self.config.method,
                        "response_truncated": len(response_body) > self.max_response_bytes,
                    },
                )
        except HTTPError as exc:
            # A 4xx response means the server handled the malformed input.  A
            # 5xx is kept as a finding because it often indicates a crash or
            # unhandled parser path.
            try:
                response_body = exc.read(self.max_response_bytes + 1)
            except OSError:
                response_body = b""
            status = "server_error" if exc.code >= 500 else "ok"
            return ExecutionResult(
                case_id=case_id,
                status=status,
                duration_ms=_duration(start),
                input_size=len(payload),
                response_status=exc.code,
                stdout=response_body[: self.max_response_bytes],
                stderr=str(exc).encode("utf-8", errors="replace"),
                metadata={"protocol": "http", "url": url, "http_error": True},
            )
        except BaseException as exc:
            if isinstance(exc, KeyboardInterrupt):
                raise
            return _network_error(case_id, payload, start, exc)

    def _input_url(self, payload: bytes) -> str:
        if self.config.input_location != "query":
            return self.config.url
        parts = urlsplit(self.config.url)
        token = "fuzz=" + quote_from_bytes(payload, safe="")
        query = f"{parts.query}&{token}" if parts.query else token
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _differential_fingerprint(result: ExecutionResult) -> str:
    digest = hashlib.sha256()
    digest.update(result.status.encode("utf-8"))
    digest.update(str(result.returncode).encode("ascii"))
    digest.update(str(result.response_status).encode("ascii"))
    digest.update(result.stdout)
    digest.update(result.stderr)
    return digest.hexdigest()


def _differential_summary(result: ExecutionResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "returncode": result.returncode,
        "response_status": result.response_status,
        "duration_ms": result.duration_ms,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
    }


def _combine_differential_output(left: bytes, right: bytes, label: bytes) -> bytes:
    limit = 262_144
    available = max(0, (limit - len(label) - 2) // 2)
    return label + left[:available] + b"\n---RIGHT---\n" + right[:available]


class DifferentialTarget:
    """Compare two targets with the same generated input."""

    def __init__(self, left: Target, right: Target):
        self.left = left
        self.right = right

    def execute(self, payload: bytes, case_id: str) -> ExecutionResult:
        start = _now()
        left_result = self.left.execute(payload, f"{case_id}-left")
        right_result = self.right.execute(payload, f"{case_id}-right")
        divergent = _differential_fingerprint(left_result) != _differential_fingerprint(right_result)
        if divergent:
            status = "divergence"
        elif left_result.is_finding or right_result.is_finding:
            status = "shared_finding"
        else:
            status = "ok"
        return ExecutionResult(
            case_id=case_id,
            status=status,
            duration_ms=_duration(start),
            input_size=len(payload),
            returncode=left_result.returncode if left_result.returncode == right_result.returncode else None,
            response_status=(
                left_result.response_status
                if left_result.response_status == right_result.response_status
                else None
            ),
            stdout=_combine_differential_output(
                left_result.stdout,
                right_result.stdout,
                b"---LEFT---\n",
            ),
            stderr=_combine_differential_output(
                left_result.stderr,
                right_result.stderr,
                b"---LEFT-ERR---\n",
            ),
            metadata={
                "differential": True,
                "divergent": divergent,
                "left": _differential_summary(left_result),
                "right": _differential_summary(right_result),
            },
        )


def build_target(
    config: TargetConfig,
    timeout_seconds: float,
    safety: SafetyConfig,
    request_wait: Callable[[], float] | None = None,
) -> Target:
    """Construct a target adapter after re-checking network guardrails."""

    if isinstance(config, BinaryTargetConfig):
        return BinaryTarget(config, timeout_seconds)
    if isinstance(config, TcpTargetConfig):
        if not safety.allow_network or not host_is_allowed(config.host, safety.allowed_hosts):
            raise ValueError("TCP target is not allowed by the network safety policy")
        return TcpTarget(
            config,
            timeout_seconds,
            safety.max_response_bytes,
            request_wait,
        )
    if isinstance(config, UdpTargetConfig):
        if not safety.allow_network or not host_is_allowed(config.host, safety.allowed_hosts):
            raise ValueError("UDP target is not allowed by the network safety policy")
        return UdpTarget(
            config,
            timeout_seconds,
            safety.max_response_bytes,
            request_wait,
        )
    if isinstance(config, HttpTargetConfig):
        host = urlsplit(config.url).hostname
        if not host or not safety.allow_network or not host_is_allowed(host, safety.allowed_hosts):
            raise ValueError("HTTP target is not allowed by the network safety policy")
        return HttpTarget(
            config,
            timeout_seconds,
            safety.max_response_bytes,
            request_wait,
        )
    if isinstance(config, DifferentialTargetConfig):
        return DifferentialTarget(
            build_target(config.left, timeout_seconds, safety, request_wait),
            build_target(config.right, timeout_seconds, safety, request_wait),
        )
    raise TypeError(f"unsupported target configuration: {type(config).__name__}")
