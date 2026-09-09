from __future__ import annotations

import json
import random
import sqlite3
import sys
import tempfile
import textwrap
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from fuzz_orchestrator.config import ConfigError, load_config
from fuzz_orchestrator.dashboard import create_server
from fuzz_orchestrator.engine import FuzzEngine
from fuzz_orchestrator.external import ExternalFuzzEngine
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

    def test_salomon_schema_translates_without_legacy_sections(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            (directory / "seeds").mkdir()
            (directory / "seeds" / "seed.bin").write_bytes(b"seed")
            path = self._write(
                directory,
                """
                schema_version = 1
                [project]
                name = "schema-demo"
                [run]
                iterations = 2
                [engine]
                backend = "builtin"
                scheduler = "feedback"
                [corpus]
                directory = "seeds"
                [limits]
                timeout_ms = 250
                max_input_bytes = 64
                [reporting]
                output_directory = "artifacts"
                [target]
                kind = "binary"
                command = ["/bin/cat"]
                input = "stdin"
                """,
            )
            config = load_config(path)
            self.assertEqual(config.name, "schema-demo")
            self.assertEqual(config.timeout_seconds, 0.25)
            self.assertEqual(config.scheduler, "feedback")
            self.assertEqual(config.max_input_size, 64)
            self.assertEqual(config.corpus_paths[0], (directory / "seeds").resolve())

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

    def test_aflpp_engine_builds_the_at_at_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = self._write(
                directory,
                """
                [corpus]
                inline = ["seed"]
                [engine]
                type = "aflpp"
                executable = "afl-fuzz"
                duration_seconds = 10
                [target]
                type = "binary"
                command = ["./target", "{input}"]
                input_mode = "file"
                """,
            )
            engine = ExternalFuzzEngine(load_config(path))
            plan = engine.plan()
            self.assertEqual(plan["engine_type"], "aflpp")
            self.assertIn("@@", plan["engine_command"])


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
            self.assertEqual(summary.unique_findings, 1)
            self.assertTrue((summary.run_dir / "summary.json").exists())
            self.assertTrue((summary.run_dir / "results.sqlite3").exists())
            self.assertEqual(len(list((summary.run_dir / "findings").glob("*.bin"))), 3)

    def test_differential_target_finds_output_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            config_path = directory / "differential.toml"
            left = json.dumps(
                [sys.executable, "-c", "import sys; sys.stdin.buffer.read(); print('left')"]
            )
            right = json.dumps(
                [sys.executable, "-c", "import sys; sys.stdin.buffer.read(); print('right')"]
            )
            config_path.write_text(
                "\n".join(
                    [
                        "[run]",
                        "name = 'differential'",
                        "iterations = 1",
                        "output_dir = " + json.dumps(str(directory / "artifacts")),
                        "[corpus]",
                        "inline = ['seed']",
                        "[target]",
                        "type = 'differential'",
                        "[target.left]",
                        f"type = 'binary'\ncommand = {left}",
                        "[target.right]",
                        f"type = 'binary'\ncommand = {right}",
                    ]
                ),
                encoding="utf-8",
            )
            summary = FuzzEngine(load_config(config_path)).run()
            self.assertEqual(summary.findings, 1)
            self.assertEqual(summary.statuses, {"divergence": 1})

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


class DashboardTests(unittest.TestCase):
    def test_dashboard_serves_summary_results_and_blocks_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            run_dir = Path(directory_name)
            findings = run_dir / "findings"
            findings.mkdir()
            (run_dir / "manifest.json").write_text(
                json.dumps({"config": {"name": "dashboard-test", "engine": {"type": "builtin"}}}),
                encoding="utf-8",
            )
            (run_dir / "summary.json").write_text(
                json.dumps({"executed": 1, "findings": 1, "statuses": {"crash": 1}}),
                encoding="utf-8",
            )
            (run_dir / "results.jsonl").write_text(
                json.dumps({"case_id": "00000001", "status": "crash", "input_size": 3, "metadata": {}}) + "\n",
                encoding="utf-8",
            )
            database = sqlite3.connect(run_dir / "results.sqlite3")
            database.execute(
                "CREATE TABLE results (sequence INTEGER PRIMARY KEY, case_id TEXT, status TEXT, duration_ms REAL, input_size INTEGER, input_sha256 TEXT, returncode INTEGER, response_status INTEGER, metadata TEXT)"
            )
            database.execute(
                "INSERT INTO results VALUES (1, '00000001', 'crash', 1.2, 3, 'abc', 3, NULL, '{}')"
            )
            database.commit()
            database.close()
            (findings / "case-00000001.bin").write_bytes(b"abc")
            server = create_server(run_dir, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urllib.request.urlopen(base + "/api/summary") as response:
                    summary = json.loads(response.read())
                self.assertEqual(summary["summary"]["findings"], 1)
                with urllib.request.urlopen(base + "/api/results") as response:
                    results = json.loads(response.read())
                self.assertTrue(results["results"][0]["artifact_urls"])
                with urllib.request.urlopen(base + "/artifact/findings/case-00000001.bin") as response:
                    self.assertEqual(response.read(), b"abc")
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(base + "/artifact/../summary.json")
                self.assertEqual(error.exception.code, 404)
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
