"""Command line interface for the fuzzing orchestrator."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from . import __version__
from .config import ConfigError, config_to_dict, load_config
from .engine import CorpusError, FuzzEngine
from .models import ExecutionResult


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

[corpus]
paths = ["seeds"]
inline = ["hello"]

[mutations]
operations = ["bitflip", "byteflip", "arith8", "insert", "delete", "duplicate", "dictionary"]
max_operations = 8
dictionary = ["\\r\\n", "{}", "null"]

# Network access is disabled by default. Keep it disabled for binary targets.
[safety]
allow_network = false
allowed_hosts = ["127.0.0.1", "localhost", "::1"]
max_response_bytes = 65536

'''
    if kind == "binary":
        return common + '''[target]
type = "binary"
# Use an argument array, never a shell string. The default sends bytes on stdin.
command = ["./path/to/your-target"]
input_mode = "stdin"
expected_exit_codes = [0]
max_output_bytes = 65536
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
        prog="fuzz-orchestrator",
        description="Orchestrateur de fuzzing local et réseau, à garde-fous explicites.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="créer une configuration et un corpus minimal")
    init.add_argument("path", nargs="?", default="fuzz.toml", help="fichier TOML à créer")
    init.add_argument(
        "--kind",
        choices=("binary", "tcp", "udp", "http"),
        default="binary",
        help="type de cible à préconfigurer",
    )
    init.add_argument("--force", action="store_true", help="remplacer les fichiers existants")

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
    path.write_text(_template(args.kind), encoding="utf-8")
    seed_dir.mkdir(parents=True, exist_ok=True)
    sample = seed_dir / "hello.txt"
    if args.force or not sample.exists():
        sample.write_bytes(b"hello\n")
    print(f"Configuration créée: {path}")
    print(f"Corpus de départ: {sample}")
    return 0


def _load_engine(config_path: str, args: argparse.Namespace) -> FuzzEngine:
    config = load_config(config_path)
    if getattr(args, "workers", None) is not None:
        if args.workers < 1 or args.workers > 64:
            raise ConfigError("--workers doit être compris entre 1 et 64")
        config = replace(config, workers=args.workers)
    if getattr(args, "seed", None) is not None:
        config = replace(config, seed=args.seed)
    if getattr(args, "output_dir", None) is not None:
        config = replace(config, output_dir=Path(args.output_dir).expanduser().resolve())
    return FuzzEngine(config)


def _validate(args: argparse.Namespace) -> int:
    engine = _load_engine(args.config, args)
    print(json.dumps({"valid": True, "plan": engine.plan()}, indent=2, ensure_ascii=False))
    return 0


def _run(args: argparse.Namespace) -> int:
    if args.limit is not None and args.limit < 1:
        raise ConfigError("--limit doit être >= 1")
    engine = _load_engine(args.config, args)
    if args.dry_run:
        print(json.dumps({"dry_run": True, "plan": engine.plan()}, indent=2, ensure_ascii=False))
        return 0
    on_finding = None
    if args.verbose:
        def print_finding(result: ExecutionResult) -> None:
            print(f"[finding] case={result.case_id} status={result.status}")

        on_finding = print_finding
    summary = engine.run(limit=args.limit, on_finding=on_finding)
    print(json.dumps(summary.as_dict(), indent=2, ensure_ascii=False))
    if args.verbose and summary.findings:
        print(f"Findings enregistrés dans: {summary.run_dir / 'findings'}")
    return 0 if summary.findings == 0 else 1


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
