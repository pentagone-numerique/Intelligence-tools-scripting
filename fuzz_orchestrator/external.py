"""Adapters for running installed coverage-guided fuzzing engines.

The built-in engine remains the default.  This module deliberately delegates
mutation and instrumentation to tools the operator has installed, while still
preparing a bounded corpus, avoiding a shell, enforcing a wall-clock limit and
collecting the output directory in one run bundle.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .config import config_to_dict
from .engine import _new_run_dir, load_corpus
from .models import BinaryTargetConfig, ExecutionResult, RunConfig
from .targets import _terminate_process


@dataclass
class ExternalSummary:
    engine_type: str
    requested: int
    executed: int
    findings: int
    statuses: dict[str, int]
    run_dir: Path
    returncode: int | None
    timed_out: bool
    artifacts: tuple[str, ...]
    command: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine_type": self.engine_type,
            "requested": self.requested,
            "executed": self.executed,
            "findings": self.findings,
            "statuses": self.statuses,
            "run_dir": str(self.run_dir),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "artifacts": list(self.artifacts),
            "command": list(self.command),
        }


class ExternalFuzzEngine:
    """Run AFL++, libFuzzer or an explicitly configured fuzzer command."""

    def __init__(self, config: RunConfig):
        if not isinstance(config.target, BinaryTargetConfig):
            raise ValueError("external engines currently require a binary target")
        self.config = config
        self.target = config.target
        self.corpus = load_corpus(config)

    def plan(self) -> dict[str, Any]:
        command = self._build_command(
            corpus_dir=Path("<corpus>"),
            output_dir=Path("<output>"),
            check_executable=False,
        )
        return {
            "name": self.config.name,
            "engine_type": self.config.engine.type,
            "duration_seconds": self.config.engine.duration_seconds,
            "corpus_count": len(self.corpus),
            "corpus_bytes": sum(len(seed) for seed in self.corpus),
            "target_command": list(self.target.command),
            "engine_command": list(command),
            "instrumentation_note": self._instrumentation_note(),
        }

    def run(
        self,
        *,
        limit: int | None = None,
        on_finding: Callable[[ExecutionResult], None] | None = None,
    ) -> ExternalSummary:
        if limit is not None:
            raise ValueError("--limit n'est pas disponible avec un moteur externe; utilisez engine.duration_seconds")

        run_dir = _new_run_dir(self.config)
        corpus_dir = run_dir / "corpus"
        output_dir = run_dir / "engine-output"
        corpus_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        for index, seed in enumerate(self.corpus, start=1):
            (corpus_dir / f"seed-{index:08d}.bin").write_bytes(seed)

        command = self._build_command(corpus_dir=corpus_dir, output_dir=output_dir)
        _write_json(
            run_dir / "manifest.json",
            {
                "config": config_to_dict(self.config),
                "engine_command": list(command),
                "corpus_count": len(self.corpus),
                "instrumentation_note": self._instrumentation_note(),
            },
        )
        returncode, timed_out = self._run_process(command, run_dir)
        artifacts = tuple(str(path.relative_to(run_dir)) for path in self._find_artifacts(output_dir))
        if timed_out:
            status = "timeout"
        elif returncode == 0:
            status = "ok"
        else:
            status = "engine_error"
        findings = len(artifacts)
        if on_finding is not None:
            for index, artifact in enumerate(artifacts, start=1):
                on_finding(
                    ExecutionResult(
                        case_id=f"external-{index:08d}",
                        status="finding",
                        duration_ms=0.0,
                        input_size=0,
                        metadata={"artifact": artifact, "engine": self.config.engine.type},
                    )
                )
        summary = ExternalSummary(
            engine_type=self.config.engine.type,
            requested=0,
            executed=0,
            findings=findings,
            statuses={status: 1},
            run_dir=run_dir,
            returncode=returncode,
            timed_out=timed_out,
            artifacts=artifacts,
            command=command,
        )
        _write_json(run_dir / "summary.json", summary.as_dict())
        return summary

    def _build_command(
        self,
        *,
        corpus_dir: Path,
        output_dir: Path,
        check_executable: bool = True,
    ) -> tuple[str, ...]:
        engine = self.config.engine
        if engine.type == "aflpp":
            executable = engine.executable or "afl-fuzz"
            if check_executable:
                executable = _find_executable(executable)
            command = [executable, "-i", str(corpus_dir), "-o", str(output_dir)]
            if not _has_flag(engine.extra_args, "-V"):
                command.extend(("-V", str(math.ceil(engine.duration_seconds))))
            if not _has_flag(engine.extra_args, "-t"):
                command.extend(("-t", str(max(1, round(self.config.timeout_seconds * 1000)))))
            command.extend(engine.extra_args)
            command.append("--")
            command.extend(
                _render_tokens(
                    self.target.command,
                    corpus_dir=corpus_dir,
                    output_dir=output_dir,
                    duration=engine.duration_seconds,
                    afl_input=True,
                )
            )
            return tuple(command)

        if engine.type == "libfuzzer":
            command = list(
                _render_tokens(
                    self.target.command,
                    corpus_dir=corpus_dir,
                    output_dir=output_dir,
                    duration=engine.duration_seconds,
                    afl_input=False,
                )
            )
            command.extend(engine.extra_args)
            if not _has_prefix(engine.extra_args, "-max_total_time="):
                command.append(f"-max_total_time={math.ceil(engine.duration_seconds)}")
            if not _has_prefix(engine.extra_args, "-artifact_prefix="):
                prefix = str(output_dir) + os.sep
                command.append(f"-artifact_prefix={prefix}")
            command.append(str(corpus_dir))
            return tuple(command)

        if engine.type == "command":
            return tuple(
                _render_tokens(
                    engine.command,
                    corpus_dir=corpus_dir,
                    output_dir=output_dir,
                    duration=engine.duration_seconds,
                    afl_input=False,
                )
            )
        raise ValueError(f"unsupported external engine: {engine.type}")

    def _run_process(self, command: tuple[str, ...], run_dir: Path) -> tuple[int | None, bool]:
        stdout_path = run_dir / "engine.stdout"
        stderr_path = run_dir / "engine.stderr"
        stdout_file = stdout_path.open("wb")
        stderr_file = stderr_path.open("wb")
        try:
            process = subprocess.Popen(
                list(command),
                cwd=str(self.target.cwd) if self.target.cwd else None,
                env={**os.environ, **dict(self.target.env)},
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=(os.name == "posix"),
            )
            timed_out = False
            try:
                process.wait(timeout=self.config.engine.duration_seconds + 30.0)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process(process)
            return process.poll(), timed_out
        finally:
            stdout_file.close()
            stderr_file.close()

    def _find_artifacts(self, output_dir: Path) -> list[Path]:
        directories = ("crashes", "hangs", "findings")
        found: set[Path] = set()
        for directory in directories:
            root = output_dir / directory
            if root.exists():
                found.update(
                    path for path in root.rglob("*") if path.is_file() and path.name.lower() != "readme.txt"
                )
        if self.config.engine.type == "libfuzzer":
            found.update(
                path
                for path in output_dir.rglob("*")
                if path.is_file() and path.name.lower() not in {"readme.txt", "engine.stdout", "engine.stderr"}
            )
        return sorted(found)

    def _instrumentation_note(self) -> str:
        if self.config.engine.type == "aflpp":
            return "target should be compiled with AFL++ instrumentation or a compatible mode"
        if self.config.engine.type == "libfuzzer":
            return "target must be a libFuzzer-compatible instrumented harness"
        return "external command owns instrumentation and coverage collection"


def _find_executable(value: str) -> str:
    resolved = shutil.which(value)
    if resolved is None:
        raise FileNotFoundError(
            f"external fuzzer executable not found: {value}; install it or set engine.executable"
        )
    return resolved


def _render_tokens(
    tokens: tuple[str, ...],
    *,
    corpus_dir: Path,
    output_dir: Path,
    duration: float,
    afl_input: bool,
) -> tuple[str, ...]:
    values = {
        "{corpus}": str(corpus_dir),
        "{output}": str(output_dir),
        "{duration}": str(math.ceil(duration)),
    }
    rendered: list[str] = []
    for token in tokens:
        value = token
        for placeholder, replacement in values.items():
            value = value.replace(placeholder, replacement)
        if "{input}" in value:
            if not afl_input:
                raise ValueError("{input} is only supported by the AFL++ adapter")
            value = value.replace("{input}", "@@")
        rendered.append(value)
    return tuple(rendered)


def _has_flag(args: tuple[str, ...], flag: str) -> bool:
    return any(arg == flag or arg.startswith(flag + "=") for arg in args)


def _has_prefix(args: tuple[str, ...], prefix: str) -> bool:
    return any(arg.startswith(prefix) for arg in args)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
