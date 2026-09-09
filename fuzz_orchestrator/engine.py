"""Corpus loading, case scheduling and result/artifact persistence."""

from __future__ import annotations

import hashlib
import json
import random
import re
import threading
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .config import config_to_dict
from .models import ExecutionResult, RunConfig
from .mutations import Mutator
from .targets import Target, build_target

_MAX_CORPUS_FILES = 10_000
_MAX_CORPUS_BYTES = 64 * 1024 * 1024
_MAX_ADAPTIVE_SEEDS = 10_000
_RUN_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class CorpusError(ValueError):
    """Raised when a configured corpus cannot be loaded safely."""


def _corpus_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if not path.exists():
            raise CorpusError(f"corpus path does not exist: {path}")
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(item for item in sorted(path.rglob("*")) if item.is_file())
        else:
            raise CorpusError(f"corpus path is neither a file nor a directory: {path}")
        if len(files) > _MAX_CORPUS_FILES:
            raise CorpusError(f"corpus contains more than {_MAX_CORPUS_FILES} files")
    return files


def load_corpus(config: RunConfig) -> list[bytes]:
    """Load inline and file seeds, truncating each seed to the configured cap."""

    corpus = [seed[: config.max_input_size] for seed in config.inline_seeds]
    total_bytes = sum(len(seed) for seed in corpus)
    if total_bytes > _MAX_CORPUS_BYTES:
        raise CorpusError(f"corpus exceeds {_MAX_CORPUS_BYTES} bytes")
    for path in _corpus_files(config.corpus_paths):
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise CorpusError(f"cannot read corpus seed {path}: {exc}") from exc
        data = data[: config.max_input_size]
        total_bytes += len(data)
        if total_bytes > _MAX_CORPUS_BYTES:
            raise CorpusError(f"corpus exceeds {_MAX_CORPUS_BYTES} bytes")
        corpus.append(data)
    if not corpus:
        raise CorpusError("the corpus is empty")
    return corpus


def _feedback_signature(result: ExecutionResult) -> str:
    """Hash observable target behavior, not the generated input.

    This is deliberately called *observable feedback*, not code coverage: it
    works for network targets and uninstrumented binaries.  It is useful for
    spotting new status/response/output classes while remaining honest about
    what the orchestrator can measure.
    """

    digest = hashlib.sha256()
    digest.update(result.status.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(result.returncode).encode("ascii"))
    digest.update(b"\0")
    digest.update(str(result.response_status).encode("ascii"))
    digest.update(b"\0")
    digest.update(result.stdout)
    digest.update(b"\0")
    digest.update(result.stderr)
    return digest.hexdigest()


@dataclass
class RunSummary:
    requested: int
    executed: int
    findings: int
    statuses: dict[str, int]
    run_dir: Path
    stopped_early: bool = False
    novel_behaviors: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "executed": self.executed,
            "findings": self.findings,
            "statuses": self.statuses,
            "run_dir": str(self.run_dir),
            "novel_behaviors": self.novel_behaviors,
            "stopped_early": self.stopped_early,
        }


class ArtifactStore:
    """Persist bounded logs and reproducible inputs for a run."""

    def __init__(self, run_dir: Path, config: RunConfig):
        self.run_dir = run_dir
        self.config = config
        self.findings_dir = run_dir / "findings"
        self.cases_dir = run_dir / "cases"
        self.results_file = run_dir / "results.jsonl"
        self._lock = threading.Lock()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.findings_dir.mkdir(exist_ok=True)
        if config.save_all_inputs:
            self.cases_dir.mkdir(exist_ok=True)
        self._results_handle = self.results_file.open("w", encoding="utf-8")

    def write_manifest(self, corpus_count: int) -> None:
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "corpus_count": corpus_count,
            "config": config_to_dict(self.config),
        }
        _write_json(self.run_dir / "manifest.json", manifest)

    def record(self, result: ExecutionResult, payload: bytes) -> None:
        digest = hashlib.sha256(payload).hexdigest()
        record = {
            "case_id": result.case_id,
            "status": result.status,
            "duration_ms": result.duration_ms,
            "input_size": result.input_size,
            "input_sha256": digest,
            "returncode": result.returncode,
            "response_status": result.response_status,
            "metadata": result.metadata,
        }
        with self._lock:
            self._results_handle.write(json.dumps(record, sort_keys=True) + "\n")
            self._results_handle.flush()
            if self.config.save_all_inputs or result.is_finding:
                directory = self.findings_dir if result.is_finding else self.cases_dir
                self._write_case(directory, result, payload, digest)

    def close(self) -> None:
        with self._lock:
            self._results_handle.close()

    def _write_case(
        self,
        directory: Path,
        result: ExecutionResult,
        payload: bytes,
        digest: str,
    ) -> None:
        stem = f"case-{result.case_id}"
        (directory / f"{stem}.bin").write_bytes(payload)
        metadata = {
            "case_id": result.case_id,
            "status": result.status,
            "duration_ms": result.duration_ms,
            "input_size": result.input_size,
            "input_sha256": digest,
            "returncode": result.returncode,
            "response_status": result.response_status,
            "metadata": result.metadata,
        }
        _write_json(directory / f"{stem}.json", metadata)
        if result.stdout:
            (directory / f"{stem}.stdout").write_bytes(result.stdout)
        if result.stderr:
            (directory / f"{stem}.stderr").write_bytes(result.stderr)


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _new_run_dir(config: RunConfig) -> Path:
    slug = _RUN_NAME_RE.sub("-", config.name).strip("-._") or "fuzz-run"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = config.output_dir
    root.mkdir(parents=True, exist_ok=True)
    candidate = root / f"{slug}-{timestamp}"
    suffix = 1
    while candidate.exists():
        candidate = root / f"{slug}-{timestamp}-{suffix}"
        suffix += 1
    return candidate


class FuzzEngine:
    """Run a deterministic campaign against one configured target."""

    def __init__(self, config: RunConfig):
        self.config = config
        self.corpus = load_corpus(config)
        self.mutator = Mutator(config.mutations, config.max_input_size)
        self.target: Target = build_target(config.target, config.timeout_seconds, config.safety)
        self._adaptive_corpus = list(self.corpus)
        self._adaptive_hashes = {hashlib.sha256(seed).digest() for seed in self.corpus}
        self._adaptive_bytes = sum(len(seed) for seed in self.corpus)
        self._adaptive_lock = threading.Lock()

    def plan(self) -> dict[str, Any]:
        return {
            "name": self.config.name,
            "iterations": self.config.iterations,
            "workers": self.config.workers,
            "corpus_count": len(self.corpus),
            "corpus_bytes": sum(len(seed) for seed in self.corpus),
            "target_type": self.config.target.type,
            "timeout_seconds": self.config.timeout_seconds,
            "max_input_size": self.config.max_input_size,
            "network_enabled": self.config.safety.allow_network,
            "scheduler": self.config.scheduler,
            "operations": list(self.config.mutations.operations),
        }

    def run(
        self,
        *,
        limit: int | None = None,
        on_finding: Callable[[ExecutionResult], None] | None = None,
    ) -> RunSummary:
        requested = self.config.iterations if limit is None else min(limit, self.config.iterations)
        if requested < 1:
            raise ValueError("run limit must be >= 1")
        run_dir = _new_run_dir(self.config)
        store = ArtifactStore(run_dir, self.config)
        store.write_manifest(len(self.corpus))
        statuses: Counter[str] = Counter()
        feedback_seen: set[str] = set()
        findings = 0
        executed = 0
        novel_behaviors = 0
        stopped_early = False

        pending: dict[Future[tuple[ExecutionResult, bytes]], int] = {}
        next_index = 1
        stop_requested = False

        def submit(executor: ThreadPoolExecutor, index: int) -> None:
            pending[executor.submit(self._execute_case, index)] = index

        try:
            with ThreadPoolExecutor(max_workers=self.config.workers, thread_name_prefix="fuzz") as executor:
                while next_index <= requested and len(pending) < self.config.workers:
                    submit(executor, next_index)
                    next_index += 1

                while pending:
                    done, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
                    for future in sorted(done, key=lambda item: pending[item]):
                        pending.pop(future, None)
                        result, payload = future.result()
                        signature = _feedback_signature(result)
                        is_novel = signature not in feedback_seen
                        feedback_seen.add(signature)
                        result.metadata = {
                            **result.metadata,
                            "feedback_signature": signature,
                            "novel_behavior": is_novel,
                        }
                        adaptive_seed_added = False
                        if is_novel:
                            novel_behaviors += 1
                            if self.config.scheduler == "feedback":
                                payload_hash = hashlib.sha256(payload).digest()
                                with self._adaptive_lock:
                                    if (
                                        payload_hash not in self._adaptive_hashes
                                        and len(self._adaptive_corpus) < _MAX_ADAPTIVE_SEEDS
                                        and self._adaptive_bytes + len(payload) <= _MAX_CORPUS_BYTES
                                    ):
                                        self._adaptive_corpus.append(payload)
                                        self._adaptive_hashes.add(payload_hash)
                                        self._adaptive_bytes += len(payload)
                                        adaptive_seed_added = True
                        result.metadata["adaptive_seed_added"] = adaptive_seed_added
                        store.record(result, payload)
                        statuses[result.status] += 1
                        executed += 1
                        if result.is_finding:
                            findings += 1
                            if on_finding is not None:
                                on_finding(result)
                            if self.config.stop_on_finding:
                                stop_requested = True
                        if not stop_requested and next_index <= requested:
                            submit(executor, next_index)
                            next_index += 1
                    if stop_requested:
                        stopped_early = True
                        for future in pending:
                            future.cancel()
                        # Running tasks cannot be cancelled safely; let the
                        # executor context wait for their bounded completion.
                        break
        finally:
            store.close()

        summary = RunSummary(
            requested=requested,
            executed=executed,
            findings=findings,
            statuses=dict(sorted(statuses.items())),
            run_dir=run_dir,
            novel_behaviors=novel_behaviors,
            stopped_early=stopped_early,
        )
        _write_json(run_dir / "summary.json", summary.as_dict())
        return summary

    def _execute_case(self, index: int) -> tuple[ExecutionResult, bytes]:
        case_id = f"{index:08d}"
        case_seed = self.config.seed + index
        rng = random.Random(case_seed)
        if self.config.scheduler == "feedback":
            with self._adaptive_lock:
                corpus = tuple(self._adaptive_corpus)
        else:
            corpus = self.corpus
        corpus_index = rng.randrange(len(corpus))
        payload = self.mutator.mutate(corpus[corpus_index], rng, corpus)
        try:
            result = self.target.execute(payload, case_id)
        except Exception as exc:  # target plug-ins should not abort the campaign
            result = ExecutionResult(
                case_id=case_id,
                status="error",
                duration_ms=0.0,
                input_size=len(payload),
                stderr=str(exc).encode("utf-8", errors="replace"),
                metadata={"exception": type(exc).__name__},
            )
        result.metadata = {
            **result.metadata,
            "case_seed": case_seed,
            "corpus_index": corpus_index,
            "scheduler_corpus_size": len(corpus),
        }
        return result, payload
