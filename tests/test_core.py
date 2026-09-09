from __future__ import annotations

import json
import random
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from fuzz_orchestrator.config import ConfigError, load_config
from fuzz_orchestrator.engine import FuzzEngine
from fuzz_orchestrator.minimize import minimize_payload
from fuzz_orchestrator.models import BinaryTargetConfig, MutationConfig
from fuzz_orchestrator.mutations import Mutator
from fuzz_orchestrator.targets import BinaryTarget


class MutationTests(unittest.TestCase):
    def test_mutations_are_deterministic_and_bounded(self) -> None:
        config = MutationConfig(
            operations=(
                "bitflip",
                "byteflip",
                "arith8",
                "insert",
                "delete",
                "duplicate",
                "dictionary",
                "overwrite",
                "splice",
            ),
            max_operations=12,
            dictionary=(b"TOKEN", b"{}"),
        )
        mutator = Mutator(config, max_input_size=32)
        corpus = [b"hello", b"world" * 20]
        first = mutator.mutate(corpus[0], random.Random(42), corpus)
        second = mutator.mutate(corpus[0], random.Random(42), corpus)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 32)


class ConfigTests(unittest.TestCase):
    def _write(self, directory: Path, contents: str) -> Path:
        path = directory / "fuzz.toml"
        path.write_text(textwrap.dedent(contents), encoding="utf-8")
        return path

    def test_network_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = self._write(
                directory,
                """
                [corpus]
                inline = ["seed"]
                [target]
                type = "tcp"
                host = "127.0.0.1"
                port = 9001
                """,
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_network_allow_list_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = self._write(
                directory,
                """
                [corpus]
                inline = ["seed"]
                [safety]
                allow_network = true
                allowed_hosts = ["127.0.0.1"]
                [target]
                type = "tcp"
                host = "127.0.0.2"
                port = 9001
                """,
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_stateful_frames_require_the_input_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = self._write(
                directory,
                """
                [corpus]
                inline = ["seed"]
                [safety]
                allow_network = true
                allowed_hosts = ["127.0.0.1"]
                [target]
                type = "tcp"
                host = "127.0.0.1"
                port = 9001
                frames = ["HELLO\\n", "{input}", "QUIT\\n"]
                """,
            )
            config = load_config(path)
            self.assertEqual(config.target.frames, ("HELLO\n", "{input}", "QUIT\n"))


class TargetTests(unittest.TestCase):
    def test_binary_nonzero_exit_is_reported(self) -> None:
        code = "import sys; sys.stdin.buffer.read(); sys.exit(3)"
        target = BinaryTarget(
            BinaryTargetConfig(
                type="binary",
                command=(sys.executable, "-c", code),
            ),
            timeout_seconds=1.0,
        )
        result = target.execute(b"input", "00000001")
        self.assertEqual(result.status, "nonzero_exit")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.input_size, 5)

    def test_binary_timeout_is_reported(self) -> None:
        code = "import time; time.sleep(2)"
        target = BinaryTarget(
            BinaryTargetConfig(
                type="binary",
                command=(sys.executable, "-c", code),
            ),
            timeout_seconds=0.05,
        )
        result = target.execute(b"input", "00000001")
        self.assertEqual(result.status, "timeout")


class EngineTests(unittest.TestCase):
    def test_engine_persists_findings_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            script = directory / "target.py"
            script.write_text(
                "import sys\nsys.stdin.buffer.read()\nsys.exit(3)\n",
                encoding="utf-8",
            )
            config_path = directory / "campaign.toml"
            command = json.dumps([sys.executable, str(script)])
            output = json.dumps(str(directory / "artifacts"))
            config_path.write_text(
                "\n".join(
                    [
                        "[run]",
                        "name = 'test'",
                        "iterations = 3",
                        "workers = 2",
                        "scheduler = 'feedback'",
                        "output_dir = " + output,
                        "[corpus]",
                        "inline = ['seed']",
                        "[mutations]",
                        "operations = ['bitflip']",
                        "max_operations = 1",
                        "[target]",
                        "type = 'binary'",
                        f"command = {command}",
                        "input_mode = 'stdin'",
                        "expected_exit_codes = [0]",
                    ]
                ),
                encoding="utf-8",
            )
            summary = FuzzEngine(load_config(config_path)).run()
            self.assertEqual(summary.executed, 3)
            self.assertEqual(summary.findings, 3)
            self.assertEqual(summary.statuses, {"nonzero_exit": 3})
            self.assertEqual(summary.novel_behaviors, 1)
            self.assertTrue((summary.run_dir / "summary.json").exists())
            self.assertEqual(len(list((summary.run_dir / "findings").glob("*.bin"))), 3)

    def test_minimizer_preserves_finding_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            config_path = directory / "campaign.toml"
            command = json.dumps(
                [sys.executable, "-c", "import sys; sys.stdin.buffer.read(); sys.exit(3)"]
            )
            config_path.write_text(
                "\n".join(
                    [
                        "[corpus]",
                        "inline = ['seed']",
                        "[target]",
                        "type = 'binary'",
                        f"command = {command}",
                    ]
                ),
                encoding="utf-8",
            )
            result = minimize_payload(
                FuzzEngine(load_config(config_path)),
                b"abcdefghijklmnop",
                max_attempts=50,
            )
            self.assertEqual(result.original.status, "nonzero_exit")
            self.assertEqual(result.minimized.status, "nonzero_exit")
            self.assertLess(len(result.payload), 16)


if __name__ == "__main__":
    unittest.main()
