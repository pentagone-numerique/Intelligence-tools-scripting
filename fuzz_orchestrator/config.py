"""Configuration loading and validation.

The project intentionally uses TOML/JSON from the standard library instead of
requiring a large dependency stack.  TOML is the recommended format.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import tomllib
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .models import (
    BinaryTargetConfig,
    DifferentialTargetConfig,
    EngineConfig,
    HttpTargetConfig,
    MutationConfig,
    RunConfig,
    SafetyConfig,
    TargetConfig,
    TcpTargetConfig,
    UdpTargetConfig,
)


class ConfigError(ValueError):
    """Raised when a configuration is missing or unsafe/invalid."""


_ALLOWED_OPERATIONS = {
    "bitflip",
    "byteflip",
    "arith8",
    "insert",
    "delete",
    "duplicate",
    "dictionary",
    "overwrite",
    "splice",
}
_ALLOWED_INPUT_MODES = {"stdin", "file", "argv"}
_ALLOWED_HTTP_LOCATIONS = {"body", "query", "header"}
_ALLOWED_ENGINES = {"builtin", "aflpp", "libfuzzer", "command"}
_MAX_ITERATIONS = 1_000_000
_MAX_WORKERS = 64
_MAX_INPUT_SIZE = 16 * 1024 * 1024
_MAX_OUTPUT_SIZE = 16 * 1024 * 1024
_MAX_CORPUS_FILES = 10_000
_MAX_CORPUS_BYTES = 64 * 1024 * 1024
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _section(raw: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = raw.get(name, {})
    if not isinstance(value, Mapping):
        raise ConfigError(f"[{name}] must be a table/object")
    return value


def _string(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ConfigError(f"{field} must be a non-empty string")
    return value


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{field} must be an array of strings")
    return value


def _int(value: Any, field: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    # bool is an int subclass, but accepting it here makes typos surprisingly
    # easy (for example iterations = true).
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{field} must be an integer")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{field} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{field} must be <= {maximum}")
    return value


def _float(value: Any, field: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{field} must be a number")
    result = float(value)
    if result < minimum or result > maximum:
        raise ConfigError(f"{field} must be between {minimum} and {maximum}")
    return result


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{field} must be a boolean")
    return value


def _resolve_path(base_dir: Path, value: Any, field: str) -> Path:
    text = _string(value, field)
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _load_document(path: Path) -> Mapping[str, Any]:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read configuration {path}: {exc}") from exc

    try:
        if path.suffix.lower() == ".json":
            value = json.loads(raw_bytes.decode("utf-8"))
        else:
            value = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"invalid {path.suffix or 'TOML'} configuration: {exc}") from exc

    if not isinstance(value, Mapping):
        raise ConfigError("the configuration root must be a table/object")
    return value


def _host_matches(host: str, allowed: str) -> bool:
    """Match an exact host or an explicitly listed CIDR, never a wildcard."""

    host_normalized = host.strip().rstrip(".").lower()
    allowed_normalized = allowed.strip().rstrip(".").lower()
    if not host_normalized or not allowed_normalized:
        return False
    if host_normalized == allowed_normalized:
        return True

    try:
        host_ip = ipaddress.ip_address(host_normalized)
    except ValueError:
        return False
    try:
        network = ipaddress.ip_network(allowed_normalized, strict=False)
    except ValueError:
        return False
    return host_ip in network


def host_is_allowed(host: str, allowed_hosts: tuple[str, ...]) -> bool:
    return any(_host_matches(host, allowed) for allowed in allowed_hosts)


def _validate_network_target(host: str, safety: SafetyConfig) -> None:
    if not safety.allow_network:
        raise ConfigError(
            "network targets are disabled by default; set safety.allow_network = true "
            "only for a system you are authorised to test"
        )
    if not safety.allowed_hosts:
        raise ConfigError(
            "network targets require safety.allowed_hosts with an exact host or CIDR"
        )
    if not host_is_allowed(host, safety.allowed_hosts):
        raise ConfigError(
            f"target host {host!r} is not in safety.allowed_hosts; "
            "wildcards are intentionally not supported"
        )


def _parse_safety(raw: Mapping[str, Any]) -> SafetyConfig:
    allow_network = _bool(raw.get("allow_network", False), "safety.allow_network")
    allowed_hosts = tuple(_string_list(raw.get("allowed_hosts", []), "safety.allowed_hosts"))
    for host in allowed_hosts:
        if any(char in host for char in "\r\n\t"):
            raise ConfigError("safety.allowed_hosts cannot contain control characters")
    max_response_bytes = _int(
        raw.get("max_response_bytes", 65_536),
        "safety.max_response_bytes",
        minimum=1,
        maximum=_MAX_OUTPUT_SIZE,
    )
    return SafetyConfig(
        allow_network=allow_network,
        allowed_hosts=allowed_hosts,
        max_response_bytes=max_response_bytes,
    )


def _read_dictionary_file(path: Path) -> list[bytes]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read mutations.dictionary_file {path}: {exc}") from exc
    if len(data) > _MAX_CORPUS_BYTES:
        raise ConfigError("mutations.dictionary_file is too large")
    # A line-oriented dictionary is easy to inspect and works for both text
    # tokens and escaped/binary-ish tokens without adding a parser dependency.
    return [line for line in data.splitlines() if line]


def _parse_mutations(raw: Mapping[str, Any], base_dir: Path) -> MutationConfig:
    operations = tuple(
        _string_list(
            raw.get(
                "operations",
                [
                    "bitflip",
                    "byteflip",
                    "arith8",
                    "insert",
                    "delete",
                    "duplicate",
                    "dictionary",
                ],
            ),
            "mutations.operations",
        )
    )
    if not operations:
        raise ConfigError("mutations.operations cannot be empty")
    unknown = sorted(set(operations) - _ALLOWED_OPERATIONS)
    if unknown:
        raise ConfigError(
            f"unknown mutation operation(s): {', '.join(unknown)}; "
            f"choose from {', '.join(sorted(_ALLOWED_OPERATIONS))}"
        )
    max_operations = _int(
        raw.get("max_operations", 8),
        "mutations.max_operations",
        minimum=1,
        maximum=32,
    )

    dictionary_values = raw.get("dictionary", [])
    dictionary_strings = _string_list(dictionary_values, "mutations.dictionary")
    dictionary = [value.encode("utf-8") for value in dictionary_strings]
    dictionary_file = raw.get("dictionary_file")
    if dictionary_file is not None:
        dictionary.extend(_read_dictionary_file(_resolve_path(base_dir, dictionary_file, "mutations.dictionary_file")))
    if any(len(item) > 1_048_576 for item in dictionary):
        raise ConfigError("dictionary entries must be <= 1 MiB")

    return MutationConfig(
        operations=operations,
        max_operations=max_operations,
        dictionary=tuple(dictionary),
    )


def _parse_binary_target(raw: Mapping[str, Any], base_dir: Path) -> BinaryTargetConfig:
    command_value = raw.get("command")
    if not isinstance(command_value, list) or not command_value or not all(
        isinstance(item, str) and item for item in command_value
    ):
        raise ConfigError(
            "target.command must be a non-empty array of strings; shell strings are not supported"
        )
    command = tuple(command_value)
    input_mode = _string(raw.get("input_mode", "stdin"), "target.input_mode").lower()
    if input_mode not in _ALLOWED_INPUT_MODES:
        raise ConfigError(
            f"target.input_mode must be one of {', '.join(sorted(_ALLOWED_INPUT_MODES))}"
        )
    has_placeholder = any("{input}" in item for item in command)
    if input_mode in {"file", "argv"} and not has_placeholder:
        raise ConfigError(
            "target.command must contain the {input} placeholder when input_mode is file or argv"
        )
    if input_mode == "stdin" and has_placeholder:
        raise ConfigError(
            "target.command must not contain {input} when input_mode is stdin"
        )

    cwd_value = raw.get("cwd")
    cwd = _resolve_path(base_dir, cwd_value, "target.cwd") if cwd_value is not None else None
    if cwd is not None and not cwd.is_dir():
        raise ConfigError(f"target.cwd is not a directory: {cwd}")

    env_value = raw.get("env", {})
    if not isinstance(env_value, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in env_value.items()
    ):
        raise ConfigError("target.env must be a table/object of string values")
    if any("\x00" in key or "\x00" in value for key, value in env_value.items()):
        raise ConfigError("target.env cannot contain NUL characters")

    expected_value = raw.get("expected_exit_codes", [0])
    expected = tuple(
        _int(code, "target.expected_exit_codes[]", minimum=-255, maximum=255)
        for code in expected_value
    ) if isinstance(expected_value, list) else None
    if expected is None or not expected:
        raise ConfigError("target.expected_exit_codes must be a non-empty array of integers")
    max_output_bytes = _int(
        raw.get("max_output_bytes", 65_536),
        "target.max_output_bytes",
        minimum=1,
        maximum=_MAX_OUTPUT_SIZE,
    )
    max_memory_value = raw.get("max_memory_mb")
    max_memory_mb = (
        _int(max_memory_value, "target.max_memory_mb", minimum=16, maximum=65_536)
        if max_memory_value is not None
        else None
    )
    return BinaryTargetConfig(
        type="binary",
        command=command,
        input_mode=input_mode,
        cwd=cwd,
        env=dict(env_value),
        expected_exit_codes=expected,
        max_output_bytes=max_output_bytes,
        max_memory_mb=max_memory_mb,
    )


def _parse_frames(raw: Mapping[str, Any]) -> tuple[str, ...]:
    values = tuple(_string_list(raw.get("frames", []), "target.frames"))
    if len(values) > 64:
        raise ConfigError("target.frames cannot contain more than 64 frames")
    if any(len(value.encode("utf-8")) > 1_048_576 for value in values):
        raise ConfigError("each target frame must be <= 1 MiB")
    if values and not any("{input}" in value for value in values):
        raise ConfigError("target.frames must contain the {input} placeholder")
    return values


def _network_port(raw: Mapping[str, Any]) -> int:
    return _int(raw.get("port"), "target.port", minimum=1, maximum=65_535)


def _parse_tcp_target(raw: Mapping[str, Any], safety: SafetyConfig) -> TcpTargetConfig:
    host = _string(raw.get("host"), "target.host")
    if not _HOSTNAME_RE.match(host):
        raise ConfigError("target.host contains unsupported characters")
    _validate_network_target(host, safety)
    return TcpTargetConfig(
        type="tcp",
        host=host,
        port=_network_port(raw),
        expect_response=_bool(raw.get("expect_response", False), "target.expect_response"),
        response_timeout_is_failure=_bool(
            raw.get("response_timeout_is_failure", False),
            "target.response_timeout_is_failure",
        ),
        frames=_parse_frames(raw),
    )


def _parse_udp_target(raw: Mapping[str, Any], safety: SafetyConfig) -> UdpTargetConfig:
    host = _string(raw.get("host"), "target.host")
    if not _HOSTNAME_RE.match(host):
        raise ConfigError("target.host contains unsupported characters")
    _validate_network_target(host, safety)
    return UdpTargetConfig(
        type="udp",
        host=host,
        port=_network_port(raw),
        expect_response=_bool(raw.get("expect_response", False), "target.expect_response"),
        response_timeout_is_failure=_bool(
            raw.get("response_timeout_is_failure", False),
            "target.response_timeout_is_failure",
        ),
        frames=_parse_frames(raw),
    )


def _parse_http_target(raw: Mapping[str, Any], safety: SafetyConfig) -> HttpTargetConfig:
    url = _string(raw.get("url"), "target.url")
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"invalid target.url: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ConfigError("target.url must be an http:// or https:// URL with a hostname")
    if port is not None and not 1 <= port <= 65_535:
        raise ConfigError("target.url port must be between 1 and 65535")
    if parsed.username or parsed.password or parsed.fragment:
        raise ConfigError("target.url cannot contain credentials or a fragment")
    if any(char in url for char in "\r\n\t"):
        raise ConfigError("target.url cannot contain control characters")
    _validate_network_target(hostname, safety)

    method = _string(raw.get("method", "POST"), "target.method").upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
        raise ConfigError("target.method is not supported")
    headers_value = raw.get("headers", {})
    if not isinstance(headers_value, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in headers_value.items()
    ):
        raise ConfigError("target.headers must be a table/object of string values")
    for key, value in headers_value.items():
        if not key or any(char in key + value for char in "\r\n"):
            raise ConfigError("target.headers cannot contain empty names or CR/LF characters")
    input_location = _string(raw.get("input_location", "body"), "target.input_location").lower()
    if input_location not in _ALLOWED_HTTP_LOCATIONS:
        raise ConfigError(
            f"target.input_location must be one of {', '.join(sorted(_ALLOWED_HTTP_LOCATIONS))}"
        )
    input_header = _string(raw.get("input_header", "X-Fuzz-Input"), "target.input_header")
    if any(char in input_header for char in "\r\n"):
        raise ConfigError("target.input_header cannot contain CR/LF characters")
    return HttpTargetConfig(
        type="http",
        url=url,
        method=method,
        headers=dict(headers_value),
        input_location=input_location,
        input_header=input_header,
    )


def _parse_target(
    raw: Mapping[str, Any],
    base_dir: Path,
    safety: SafetyConfig,
) -> TargetConfig:
    target_type = _string(raw.get("type"), "target.type").lower()
    if target_type == "binary":
        return _parse_binary_target(raw, base_dir)
    if target_type == "tcp":
        return _parse_tcp_target(raw, safety)
    if target_type == "udp":
        return _parse_udp_target(raw, safety)
    if target_type == "http":
        return _parse_http_target(raw, safety)
    if target_type == "differential":
        left = raw.get("left")
        right = raw.get("right")
        if not isinstance(left, Mapping) or not isinstance(right, Mapping):
            raise ConfigError(
                "differential targets require [target.left] and [target.right] tables"
            )
        return DifferentialTargetConfig(
            type="differential",
            left=_parse_target(left, base_dir, safety),
            right=_parse_target(right, base_dir, safety),
        )
    raise ConfigError("target.type must be one of: binary, tcp, udp, http, differential")


def _parse_engine(raw: Mapping[str, Any]) -> EngineConfig:
    engine_type = _string(raw.get("type", "builtin"), "engine.type").lower()
    if engine_type not in _ALLOWED_ENGINES:
        raise ConfigError(
            "engine.type must be one of: builtin, aflpp, libfuzzer, command"
        )
    executable_value = raw.get("executable", "")
    if not isinstance(executable_value, str):
        raise ConfigError("engine.executable must be a string")
    extra_args = tuple(_string_list(raw.get("extra_args", []), "engine.extra_args"))
    command_value = raw.get("command", [])
    command = tuple(_string_list(command_value, "engine.command"))
    if any("\x00" in value for value in (*extra_args, *command, executable_value)):
        raise ConfigError("engine arguments cannot contain NUL characters")
    duration_seconds = _float(
        raw.get("duration_seconds", 3_600.0),
        "engine.duration_seconds",
        minimum=1.0,
        maximum=86_400.0,
    )
    if engine_type == "command":
        if not command:
            raise ConfigError("engine.command is required when engine.type = command")
        if not any("{corpus}" in item for item in command):
            raise ConfigError("engine.command must contain the {corpus} placeholder")
        if not any("{output}" in item for item in command):
            raise ConfigError("engine.command must contain the {output} placeholder")
    return EngineConfig(
        type=engine_type,
        executable=executable_value,
        command=command,
        extra_args=extra_args,
        duration_seconds=duration_seconds,
    )


def load_config(path: str | Path) -> RunConfig:
    """Load and validate a TOML or JSON run configuration."""

    config_path = Path(path).expanduser().resolve()
    raw = _load_document(config_path)
    base_dir = config_path.parent

    run = _section(raw, "run")
    corpus = _section(raw, "corpus")
    mutations_raw = _section(raw, "mutations")
    safety_raw = _section(raw, "safety")
    target_raw = _section(raw, "target")
    engine_raw = _section(raw, "engine")

    name = _string(run.get("name", config_path.stem), "run.name")
    iterations = _int(run.get("iterations", 100), "run.iterations", minimum=1, maximum=_MAX_ITERATIONS)
    workers = _int(run.get("workers", 1), "run.workers", minimum=1, maximum=_MAX_WORKERS)
    seed = _int(run.get("seed", 1337), "run.seed", minimum=-(2**63), maximum=2**63 - 1)
    timeout_seconds = _float(
        run.get("timeout_seconds", 2.0),
        "run.timeout_seconds",
        minimum=0.01,
        maximum=300.0,
    )
    max_input_size = _int(
        run.get("max_input_size", 1_048_576),
        "run.max_input_size",
        minimum=1,
        maximum=_MAX_INPUT_SIZE,
    )
    save_all_inputs = _bool(run.get("save_all_inputs", False), "run.save_all_inputs")
    stop_on_finding = _bool(run.get("stop_on_finding", False), "run.stop_on_finding")
    scheduler = _string(run.get("scheduler", "random"), "run.scheduler").lower()
    if scheduler not in {"random", "feedback"}:
        raise ConfigError("run.scheduler must be either random or feedback")
    rate_value = run.get("max_requests_per_second")
    max_requests_per_second = (
        _float(
            rate_value,
            "run.max_requests_per_second",
            minimum=0.1,
            maximum=1_000.0,
        )
        if rate_value is not None
        else None
    )
    output_dir = _resolve_path(base_dir, run.get("output_dir", "artifacts"), "run.output_dir")

    corpus_paths = tuple(
        _resolve_path(base_dir, item, "corpus.paths[]")
        for item in _string_list(corpus.get("paths", []), "corpus.paths")
    )
    inline_seeds = tuple(
        item.encode("utf-8")
        for item in _string_list(corpus.get("inline", []), "corpus.inline")
    )
    if not corpus_paths and not inline_seeds:
        raise ConfigError("provide at least one seed in corpus.paths or corpus.inline")

    safety = _parse_safety(safety_raw)
    mutations = _parse_mutations(mutations_raw, base_dir)
    engine = _parse_engine(engine_raw)
    target = _parse_target(target_raw, base_dir, safety)
    if engine.type != "builtin" and not isinstance(target, BinaryTargetConfig):
        raise ConfigError("external engines currently require target.type = binary")

    return RunConfig(
        name=name,
        iterations=iterations,
        workers=workers,
        seed=seed,
        output_dir=output_dir,
        corpus_paths=corpus_paths,
        inline_seeds=inline_seeds,
        timeout_seconds=timeout_seconds,
        max_input_size=max_input_size,
        save_all_inputs=save_all_inputs,
        stop_on_finding=stop_on_finding,
        target=target,
        mutations=mutations,
        safety=safety,
        scheduler=scheduler,
        engine=engine,
        max_requests_per_second=max_requests_per_second,
    )


def _manifest_value(value: Any, *, key: str = "") -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        sensitive_headers = {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "api-key",
        }
        if key == "env":
            return {str(name): "<redacted>" for name in value}
        if key == "headers":
            return {
                str(name): (
                    "<redacted>"
                    if str(name).lower() in sensitive_headers
                    else _manifest_value(item, key=str(name))
                )
                for name, item in value.items()
            }
        return {
            str(name): _manifest_value(item, key=str(name))
            for name, item in value.items()
            if item is not None
        }
    if isinstance(value, (tuple, list)):
        return [_manifest_value(item, key=key) for item in value]
    return value


def config_to_dict(config: RunConfig) -> dict[str, Any]:
    """Return a JSON-safe, redacted representation for manifests and CLI output."""

    target = _manifest_value(asdict(config.target))
    mutation = asdict(config.mutations)
    mutation["dictionary"] = [base64.b64encode(item).decode("ascii") for item in config.mutations.dictionary]
    engine = asdict(config.engine)
    return {
        "name": config.name,
        "iterations": config.iterations,
        "workers": config.workers,
        "seed": config.seed,
        "output_dir": str(config.output_dir),
        "corpus_paths": [str(item) for item in config.corpus_paths],
        "inline_seed_count": len(config.inline_seeds),
        "timeout_seconds": config.timeout_seconds,
        "max_input_size": config.max_input_size,
        "save_all_inputs": config.save_all_inputs,
        "stop_on_finding": config.stop_on_finding,
        "scheduler": config.scheduler,
        "max_requests_per_second": config.max_requests_per_second,
        "target": target,
        "mutations": mutation,
        "safety": asdict(config.safety),
        "engine": engine,
    }
