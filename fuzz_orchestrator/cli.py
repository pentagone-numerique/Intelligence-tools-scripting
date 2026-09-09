"""Command line interface for the fuzzing orchestrator."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import ConfigError, config_to_dict, load_config
from .dashboard import serve as serve_dashboard
from .engine import CorpusError, FuzzEngine
from .external import ExternalFuzzEngine
from .minimize import minimize_payload, replay_payload
from .models import (
    BinaryTargetConfig,
    EngineConfig,
    ExecutionResult,
    MutationConfig,
    RunConfig,
    SafetyConfig,
)


def _salomon_template(kind: str) -> str:
    target_block = {
        "binary": '''[target]
kind = "binary"
command = ["./path/to/your-target"]
input = "stdin"
''',
        "tcp": '''[target]
kind = "tcp"
host = "127.0.0.1"
port = 9001
expect_response = false
''',
        "udp": '''[target]
kind = "udp"
host = "127.0.0.1"
port = 9001
expect_response = false
''',
        "http": '''[target]
kind = "http"
url = "http://127.0.0.1:8080/parse"
method = "POST"
input_location = "body"
headers = { Content-Type = "application/octet-stream" }
''',
        "differential": '''[target]
kind = "differential"

[target.left]
kind = "binary"
command = ["./stable-target"]
input = "stdin"

[target.right]
kind = "binary"
command = ["./candidate-target"]
input = "stdin"
''',
    }[kind]
    return f'''# SALOMON configuration schema v1.
# Compatible with: salomon validate Salomon.toml
schema_version = 1

[project]
name = "salomon-campaign"

[run]
iterations = 100
workers = 1
seed = 1337

[engine]
backend = "builtin" # builtin, aflpp, libfuzzer, command
scheduler = "feedback" # random or feedback
corpus_backend = "python" # python or rust (optional local IPC)
# corpus_command = ["salomon-corpusd"]
corpus_batch_size = 32

[corpus]
directory = "seeds"
inline = ["hello"]

[limits]
timeout_ms = 2000
max_input_bytes = 1048576
# Network targets only:
# max_requests_per_second = 10

[reporting]
output_directory = "artifacts"

[safety]
allow_network = false
allowed_hosts = ["127.0.0.1", "localhost", "::1"]
max_response_bytes = 65536

{target_block}'''


def _template(kind: str) -> str:
    common = '''# Fuzzing orchestrator configuration. TOML is resolved relative to this file.
# Start with: python -m fuzz_orchestrator validate fuzz.toml

[run]
name = "fuzz-campaign"
iterations = 100
workers = 1
seed = 1337
timeout_seconds = 2.0
max_input_size = 1048576
output_dir = "artifacts"
save_all_inputs = false
stop_on_finding = false
scheduler = "random" # or "feedback" to retain novel observable behaviors
# Network targets only: global request pacing across workers.
# max_requests_per_second = 10

[corpus]
paths = ["seeds"]
inline = ["hello"]

[mutations]
operations = ["bitflip", "byteflip", "arith8", "insert", "delete", "duplicate", "dictionary"]
max_operations = 8
dictionary = ["\\r\\n", "{}", "null"]

[engine]
type = "builtin" # builtin, aflpp, libfuzzer or command
# Optional local Rust corpus backend; Python remains the default.
# corpus_backend = "rust"
# corpus_command = ["salomon-corpusd"]
# corpus_batch_size = 32

# Network access is disabled by default. Keep it disabled for binary targets.
[safety]
allow_network = false
allowed_hosts = ["127.0.0.1", "localhost", "::1"]
max_response_bytes = 65536

'''
    if kind == "differential":
        return common + '''[target]
type = "differential"

[target.left]
type = "binary"
command = ["./stable-target"]
input_mode = "stdin"

[target.right]
type = "binary"
command = ["./candidate-target"]
input_mode = "stdin"
'''
    if kind == "binary":
        return common + '''[target]
type = "binary"
# Use an argument array, never a shell string. The default sends bytes on stdin.
command = ["./path/to/your-target"]
input_mode = "stdin"
expected_exit_codes = [0]
max_output_bytes = 65536
# Optional Linux/resource.prlimit address-space cap (MiB); omit it to disable.
# max_memory_mb = 512
# For a file-based target instead:
# input_mode = "file"
# command = ["./path/to/your-target", "{input}"]
'''
    if kind == "tcp":
        return common + '''[target]
type = "tcp"
host = "127.0.0.1"
port = 9001
expect_response = false
response_timeout_is_failure = false
# Optional stateful exchange; {input} is replaced by the fuzzed payload.
# frames = ["HELLO", "{input}", "QUIT"]

# Before running, explicitly opt in for this host:
# [safety]
# allow_network = true
# allowed_hosts = ["127.0.0.1"]
'''
    if kind == "udp":
        return common + '''[target]
type = "udp"
host = "127.0.0.1"
port = 9001
expect_response = false
response_timeout_is_failure = false
# Optional stateful exchange; {input} is replaced by the fuzzed payload.
# frames = ["HELLO", "{input}", "QUIT"]

# Before running, explicitly opt in for this host:
# [safety]
# allow_network = true
# allowed_hosts = ["127.0.0.1"]
'''
    return common + '''[target]
type = "http"
url = "http://127.0.0.1:8080/parse"
method = "POST"
input_location = "body"
headers = { Content-Type = "application/octet-stream" }

# Before running, explicitly opt in for this host:
# [safety]
# allow_network = true
# allowed_hosts = ["127.0.0.1"]
'''


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="salomon" if Path(sys.argv[0]).name == "salomon" else "fuzz-orchestrator",
        description="Orchestrateur de fuzzing local et réseau, à garde-fous explicites.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="créer une configuration et un corpus minimal")
    init.add_argument("path", nargs="?", default="fuzz.toml", help="fichier TOML à créer")
    init.add_argument(
        "--kind",
        choices=("binary", "tcp", "udp", "http", "differential"),
        default="binary",
        help="type de cible à préconfigurer",
    )
    init.add_argument("--force", action="store_true", help="remplacer les fichiers existants")
    init.add_argument(
        "--format",
        choices=("legacy", "salomon"),
        default="legacy",
        help="format à générer (legacy pour fuzz.toml, salomon pour Salomon.toml)",
    )

    validate = subparsers.add_parser("validate", help="valider une configuration et son corpus")
    validate.add_argument("config", help="fichier TOML ou JSON")

    run = subparsers.add_parser("run", help="lancer une campagne")
    run.add_argument("config", help="fichier TOML ou JSON")
    run.add_argument("--dry-run", action="store_true", help="prévisualiser sans exécuter la cible")
    run.add_argument("--limit", type=int, help="limiter le nombre de cas pour cette exécution")
    run.add_argument("--workers", type=int, help="surcharger temporairement run.workers")
    run.add_argument("--seed", type=int, help="surcharger temporairement run.seed")
    run.add_argument("--output-dir", help="surcharger temporairement run.output_dir")
    run.add_argument("--verbose", action="store_true", help="afficher chaque finding")

    fuzz = subparsers.add_parser("fuzz", help="lancer SALOMON avec un fichier ou une cible rapide")
    fuzz.add_argument("--config", help="Salomon.toml ou fuzz.toml existant")
    fuzz.add_argument("--target", help="chemin d'un binaire à fuzz, si --config est absent")
    fuzz.add_argument("--input", help="fichier ou dossier de corpus, si --config est absent")
    fuzz.add_argument("--iterations", type=int, default=100, help="nombre de cas en mode rapide")
    fuzz.add_argument("--timeout-ms", type=float, default=2000.0, help="timeout par cas en mode rapide")
    fuzz.add_argument("--max-input-bytes", type=int, default=1_048_576, help="taille maximale d'entrée")
    fuzz.add_argument("--workers", type=int, default=1, help="nombre de workers")
    fuzz.add_argument("--seed", type=int, default=1337, help="seed de reproductibilité")
    fuzz.add_argument("--output-dir", default="artifacts", help="dossier de sortie")
    fuzz.add_argument("--dry-run", action="store_true", help="prévisualiser sans exécuter")
    fuzz.add_argument("--verbose", action="store_true", help="afficher chaque finding")

    replay = subparsers.add_parser("replay", help="rejouer une entrée sauvegardée")
    replay.add_argument("config", help="fichier TOML ou JSON")
    replay.add_argument("input", help="fichier .bin à rejouer")
    replay.add_argument("--case-id", default="replay", help="identifiant affiché dans le résultat")

    minimize = subparsers.add_parser("minimize", help="réduire un finding en conservant son statut")
    minimize.add_argument("config", help="fichier TOML ou JSON")
    minimize.add_argument("input", help="fichier .bin à réduire")
    minimize.add_argument("--output", help="fichier de sortie (par défaut: <input>.min.bin)")
    minimize.add_argument("--max-attempts", type=int, default=500, help="nombre maximal de tentatives")

    dashboard = subparsers.add_parser("dashboard", help="servir le tableau de bord d'un run")
    dashboard.add_argument("run_dir", help="dossier de run contenant summary.json/manifest.json")
    dashboard.add_argument("--host", default="127.0.0.1", help="adresse d'écoute (localhost par défaut)")
    dashboard.add_argument("--port", type=int, default=8765, help="port HTTP (8765 par défaut, 0 = automatique)")
    return parser


def _init(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser().resolve()
    seed_dir = path.parent / "seeds"
    if path.exists() and not args.force:
        print(f"fichier déjà présent: {path} (utilisez --force pour remplacer)", file=sys.stderr)
        return 2
    if seed_dir.exists() and not args.force and any(seed_dir.iterdir()):
        print(f"corpus déjà présent: {seed_dir} (utilisez --force pour compléter)", file=sys.stderr)
        return 2
    path.parent.mkdir(parents=True, exist_ok=True)
    template = _salomon_template(args.kind) if args.format == "salomon" else _template(args.kind)
    path.write_text(template, encoding="utf-8")
    seed_dir.mkdir(parents=True, exist_ok=True)
    sample = seed_dir / "hello.txt"
    if args.force or not sample.exists():
        sample.write_bytes(b"hello\n")
    print(f"Configuration créée: {path}")
    print(f"Corpus de départ: {sample}")
    return 0


def _quick_config(args: argparse.Namespace) -> RunConfig:
    if not args.target or not args.input:
        raise ConfigError("mode rapide: --target et --input sont obligatoires")
    if args.iterations < 1:
        raise ConfigError("--iterations doit être >= 1")
    if args.workers < 1 or args.workers > 64:
        raise ConfigError("--workers doit être compris entre 1 et 64")
    if args.timeout_ms <= 0:
        raise ConfigError("--timeout-ms doit être > 0")
    if args.max_input_bytes < 1:
        raise ConfigError("--max-input-bytes doit être >= 1")
    target_path = Path(args.target).expanduser().resolve()
    input_path = Path(args.input).expanduser().resolve()
    return RunConfig(
        name=target_path.stem or "salomon-quick",
        iterations=args.iterations,
        workers=args.workers,
        seed=args.seed,
        output_dir=Path(args.output_dir).expanduser().resolve(),
        corpus_paths=(input_path,),
        inline_seeds=(),
        timeout_seconds=args.timeout_ms / 1000.0,
        max_input_size=args.max_input_bytes,
        save_all_inputs=False,
        stop_on_finding=False,
        target=BinaryTargetConfig(
            type="binary",
            command=(str(target_path),),
            input_mode="stdin",
        ),
        mutations=MutationConfig(),
        safety=SafetyConfig(),
        scheduler="feedback",
        engine=EngineConfig(),
    )


def _fuzz(args: argparse.Namespace) -> int:
    if args.config:
        proxy = argparse.Namespace(
            config=args.config,
            dry_run=args.dry_run,
            limit=None,
            workers=None,
            seed=None,
            output_dir=None,
            verbose=args.verbose,
        )
        return _run(proxy)
    config = _quick_config(args)
    engine = FuzzEngine(config)
    if args.dry_run:
        try:
            print(json.dumps({"dry_run": True, "plan": engine.plan()}, indent=2, ensure_ascii=False))
        finally:
            engine.close()
        return 0
    on_finding = None
    if args.verbose:
        def print_finding(result: ExecutionResult) -> None:
            print(f"[finding] case={result.case_id} status={result.status}")

        on_finding = print_finding
    try:
        summary = engine.run(on_finding=on_finding)
    finally:
        close = getattr(engine, "close", None)
        if close is not None:
            close()
    print(json.dumps(summary.as_dict(), indent=2, ensure_ascii=False))
    return 0 if summary.findings == 0 else 1


def _load_engine(
    config_path: str, args: argparse.Namespace
) -> FuzzEngine | ExternalFuzzEngine:
    config = load_config(config_path)
    if getattr(args, "workers", None) is not None:
        if args.workers < 1 or args.workers > 64:
            raise ConfigError("--workers doit être compris entre 1 et 64")
        config = replace(config, workers=args.workers)
    if getattr(args, "seed", None) is not None:
        config = replace(config, seed=args.seed)
    if getattr(args, "output_dir", None) is not None:
        config = replace(config, output_dir=Path(args.output_dir).expanduser().resolve())
    if config.engine.type == "builtin":
        return FuzzEngine(config)
    return ExternalFuzzEngine(config)


def _validate(args: argparse.Namespace) -> int:
    engine = _load_engine(args.config, args)
    try:
        print(json.dumps({"valid": True, "plan": engine.plan()}, indent=2, ensure_ascii=False))
    finally:
        close = getattr(engine, "close", None)
        if close is not None:
            close()
    return 0


def _run(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit < 1:
        raise ConfigError("--limit doit être >= 1")
    engine = _load_engine(args.config, args)
    if args.dry_run:
        try:
            print(json.dumps({"dry_run": True, "plan": engine.plan()}, indent=2, ensure_ascii=False))
        finally:
            close = getattr(engine, "close", None)
            if close is not None:
                close()
        return 0
    on_finding = None
    if args.verbose:
        def print_finding(result: ExecutionResult) -> None:
            print(f"[finding] case={result.case_id} status={result.status}")

        on_finding = print_finding
    try:
        summary = engine.run(limit=args.limit, on_finding=on_finding)
    finally:
        close = getattr(engine, "close", None)
        if close is not None:
            close()
    print(json.dumps(summary.as_dict(), indent=2, ensure_ascii=False))
    if args.verbose and summary.findings:
        if getattr(summary, "engine_type", "builtin") == "builtin":
            findings_path = summary.run_dir / "findings"
        else:
            findings_path = summary.run_dir / "engine-output"
        print(f"Findings enregistrés dans: {findings_path}")
    return 0 if summary.findings == 0 else 1


def _result_to_dict(result: ExecutionResult) -> dict[str, object]:
    return {
        "case_id": result.case_id,
        "status": result.status,
        "duration_ms": result.duration_ms,
        "input_size": result.input_size,
        "returncode": result.returncode,
        "response_status": result.response_status,
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "metadata": result.metadata,
    }


def _replay(args: argparse.Namespace) -> int:
    input_path = Path(args.input).expanduser().resolve()
    payload = input_path.read_bytes()
    engine = _load_engine(args.config, args)
    if not isinstance(engine, FuzzEngine):
        raise ConfigError("replay nécessite engine.type = builtin")
    result = replay_payload(engine, payload, args.case_id)
    print(json.dumps(_result_to_dict(result), indent=2, ensure_ascii=False))
    return 1 if result.is_finding else 0


def _minimize(args: argparse.Namespace) -> int:
    if args.max_attempts < 1 or args.max_attempts > 10_000:
        raise ConfigError("--max-attempts doit être compris entre 1 et 10000")
    input_path = Path(args.input).expanduser().resolve()
    payload = input_path.read_bytes()
    engine = _load_engine(args.config, args)
    if not isinstance(engine, FuzzEngine):
        raise ConfigError("minimize nécessite engine.type = builtin")
    result = minimize_payload(engine, payload, max_attempts=args.max_attempts)
    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else input_path.with_name(input_path.stem + ".min" + input_path.suffix)
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(result.payload)
    report = {
        "input": str(input_path),
        "output": str(output_path),
        "attempts": result.attempts,
        "original": _result_to_dict(result.original),
        "minimized": _result_to_dict(result.minimized),
        "original_size": len(payload),
        "minimized_size": len(result.payload),
    }
    report_path = output_path.with_suffix(output_path.suffix + ".json")
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if result.minimized.is_finding else 0


def _dashboard(args: argparse.Namespace) -> int:
    if args.port < 0 or args.port > 65_535:
        raise ConfigError("--port doit être compris entre 0 et 65535")
    serve_dashboard(args.run_dir, host=args.host, port=args.port)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            return _init(args)
        if args.command == "validate":
            return _validate(args)
        if args.command == "run":
            return _run(args)
        if args.command == "fuzz":
            return _fuzz(args)
        if args.command == "replay":
            return _replay(args)
        if args.command == "minimize":
            return _minimize(args)
        if args.command == "dashboard":
            return _dashboard(args)
        parser.error("commande inconnue")
    except (ConfigError, CorpusError, OSError, ValueError) as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCampagne interrompue.", file=sys.stderr)
        return 130
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
