"""Data models shared by configuration, targets and the execution engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Union


@dataclass(frozen=True)
class SafetyConfig:
    """Network guardrails.

    Network targets are deliberately opt-in and must also match an explicit
    host allow-list.  The defaults therefore keep a run local-only.
    """

    allow_network: bool = False
    allowed_hosts: tuple[str, ...] = ()
    max_response_bytes: int = 65_536


@dataclass(frozen=True)
class MutationConfig:
    operations: tuple[str, ...] = (
        "bitflip",
        "byteflip",
        "arith8",
        "insert",
        "delete",
        "duplicate",
        "dictionary",
    )
    max_operations: int = 8
    dictionary: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class EngineConfig:
    """Campaign engine selection.

    ``builtin`` uses the Python mutation engine.  ``aflpp``, ``libfuzzer`` and
    ``command`` delegate generation to an installed external engine while the
    orchestrator still prepares the corpus, bounds the process and collects
    artifacts.
    """

    type: str = "builtin"
    executable: str = ""
    command: tuple[str, ...] = ()
    extra_args: tuple[str, ...] = ()
    duration_seconds: float = 3_600.0


@dataclass(frozen=True)
class BinaryTargetConfig:
    type: str
    command: tuple[str, ...]
    input_mode: str = "stdin"
    cwd: Optional[Path] = None
    env: Mapping[str, str] = field(default_factory=dict)
    expected_exit_codes: tuple[int, ...] = (0,)
    max_output_bytes: int = 65_536
    max_memory_mb: Optional[int] = None


@dataclass(frozen=True)
class TcpTargetConfig:
    type: str
    host: str
    port: int
    expect_response: bool = False
    response_timeout_is_failure: bool = False
    frames: tuple[str, ...] = ()


@dataclass(frozen=True)
class UdpTargetConfig:
    type: str
    host: str
    port: int
    expect_response: bool = False
    response_timeout_is_failure: bool = False
    frames: tuple[str, ...] = ()


@dataclass(frozen=True)
class HttpTargetConfig:
    type: str
    url: str
    method: str = "POST"
    headers: Mapping[str, str] = field(default_factory=dict)
    input_location: str = "body"
    input_header: str = "X-Fuzz-Input"


TargetConfig = Union[
    BinaryTargetConfig,
    TcpTargetConfig,
    UdpTargetConfig,
    HttpTargetConfig,
]


@dataclass(frozen=True)
class RunConfig:
    name: str
    iterations: int
    workers: int
    seed: int
    output_dir: Path
    corpus_paths: tuple[Path, ...]
    inline_seeds: tuple[bytes, ...]
    timeout_seconds: float
    max_input_size: int
    save_all_inputs: bool
    stop_on_finding: bool
    target: TargetConfig
    mutations: MutationConfig = field(default_factory=MutationConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    scheduler: str = "random"
    engine: EngineConfig = field(default_factory=EngineConfig)
    max_requests_per_second: Optional[float] = None


@dataclass
class ExecutionResult:
    """Outcome of a single target execution.

    ``status == "ok"`` is the only status considered non-finding by the
    engine.  Target implementations may add diagnostic fields to metadata,
    but should keep it JSON serialisable.
    """

    case_id: str
    status: str
    duration_ms: float
    input_size: int
    returncode: Optional[int] = None
    response_status: Optional[int] = None
    stdout: bytes = b""
    stderr: bytes = b""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_finding(self) -> bool:
        return self.status != "ok"
