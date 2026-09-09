"""Optional local IPC client for the native SALOMON corpus scheduler.

The Python engine does not start this helper by default.  A campaign can opt
into it when the Rust ``salomon-corpusd`` binary is available.  Communication
uses a versioned line protocol over pipes, never a shell or a network socket.
The protocol is intentionally small so a future FFI implementation can keep
these data types as its compatibility reference.
"""

from __future__ import annotations

import base64
import binascii
import subprocess
import threading
from dataclasses import dataclass
from typing import Sequence

_PROTOCOL_VERSION = "1"


class NativeCorpusError(RuntimeError):
    """Raised when the native corpus helper cannot serve a request."""


@dataclass(frozen=True)
class NativeCorpusEntry:
    input_id: int
    data: bytes
    parent_id: int | None
    energy: int
    favored: bool
    new_edges: int = 0
    interesting: bool = False
    bitmap_hash: bytes | None = None


@dataclass(frozen=True)
class NativeCorpusStats:
    entries: int
    bytes: int
    max_entries: int
    max_bytes: int


class NativeCorpusClient:
    """Drive ``salomon-corpusd`` through a local, non-shell subprocess.

    This client is deliberately explicit and opt-in.  The current Python
    engine remains independent from it; callers can use it for corpus/control
    batches without putting a network RPC in the mutation/execution loop.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        strategy: str = "feedback",
        seed: int = 1337,
        max_entries: int = 10_000,
        max_bytes: int = 64 * 1024 * 1024,
        max_input_bytes: int = 1024 * 1024,
    ) -> None:
        if isinstance(command, (str, bytes)) or not command:
            raise NativeCorpusError("native corpus command must be a non-empty argument array")
        if strategy not in {"random", "feedback"}:
            raise NativeCorpusError("native corpus strategy must be random or feedback")
        for name, value in (
            ("max_entries", max_entries),
            ("max_bytes", max_bytes),
            ("max_input_bytes", max_input_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise NativeCorpusError(f"{name} must be a positive integer")

        argv = [str(item) for item in command]
        argv.extend(
            [
                "--strategy",
                strategy,
                "--seed",
                str(seed),
                "--max-entries",
                str(max_entries),
                "--max-bytes",
                str(max_bytes),
                "--max-input-bytes",
                str(max_input_bytes),
            ]
        )
        try:
            self._process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                text=True,
                encoding="ascii",
                errors="strict",
                bufsize=1,
            )
        except OSError as exc:
            raise NativeCorpusError(f"cannot start native corpus helper: {exc}") from exc
        self._lock = threading.Lock()
        self._closed = False
        try:
            response = self._request(f"HELLO {_PROTOCOL_VERSION}")
            if response[:2] != ["HELLO", _PROTOCOL_VERSION]:
                raise NativeCorpusError("native corpus helper returned an invalid HELLO response")
        except Exception:
            self.close()
            raise

    def ping(self) -> None:
        response = self._request("PING")
        if response != ["PONG"]:
            raise NativeCorpusError("native corpus helper returned an invalid PONG response")

    def add(self, data: bytes, parent_id: int | None = None) -> NativeCorpusEntry:
        if not isinstance(data, bytes):
            raise NativeCorpusError("native corpus input must be bytes")
        parent = "-" if parent_id is None else str(_non_negative_int(parent_id, "parent_id"))
        response = self._request(f"ADD {parent} {_encode(data)}")
        return _parse_entry(response)

    def next(self) -> NativeCorpusEntry | None:
        response = self._request("NEXT")
        if response == ["NONE"]:
            return None
        return _parse_entry(response)

    def feedback(
        self,
        input_id: int,
        *,
        energy: int = 1,
        favored: bool = False,
        new_edges: int = 0,
        interesting: bool = False,
        bitmap_hash: bytes | None = None,
    ) -> None:
        input_id = _non_negative_int(input_id, "input_id")
        energy = _non_negative_int(energy, "energy")
        new_edges = _non_negative_int(new_edges, "new_edges")
        if bitmap_hash is not None and len(bitmap_hash) != 32:
            raise NativeCorpusError("bitmap_hash must contain exactly 32 bytes")
        hash_value = "-" if bitmap_hash is None else _encode(bitmap_hash)
        response = self._request(
            "FEEDBACK "
            f"{input_id} {energy} {1 if favored else 0} {new_edges} "
            f"{1 if interesting else 0} {hash_value}"
        )
        if response != ["OK", "FEEDBACK"]:
            raise NativeCorpusError("native corpus helper rejected feedback")

    def stats(self) -> NativeCorpusStats:
        response = self._request("STATS")
        if len(response) != 5 or response[0] != "STATS":
            raise NativeCorpusError("native corpus helper returned invalid statistics")
        try:
            values = tuple(int(item) for item in response[1:])
        except ValueError as exc:
            raise NativeCorpusError("native corpus helper returned non-numeric statistics") from exc
        if any(value < 0 for value in values):
            raise NativeCorpusError("native corpus helper returned negative statistics")
        return NativeCorpusStats(*values)

    def close(self) -> None:
        with getattr(self, "_lock", threading.Lock()):
            if getattr(self, "_closed", True):
                return
            self._closed = True
            process = self._process
            try:
                if process.poll() is None and process.stdin is not None:
                    process.stdin.write("QUIT\n")
                    process.stdin.flush()
                    if process.stdout is not None:
                        process.stdout.readline()
            except (BrokenPipeError, OSError, UnicodeError):
                pass
            finally:
                if process.stdin is not None:
                    process.stdin.close()
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    def __enter__(self) -> "NativeCorpusClient":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def _request(self, line: str) -> list[str]:
        with self._lock:
            if self._closed:
                raise NativeCorpusError("native corpus helper is closed")
            process = self._process
            if process.poll() is not None:
                raise self._process_error("native corpus helper exited before the request")
            if process.stdin is None or process.stdout is None:
                raise NativeCorpusError("native corpus helper pipes are unavailable")
            try:
                process.stdin.write(line + "\n")
                process.stdin.flush()
                raw_response = process.stdout.readline()
            except (BrokenPipeError, OSError, UnicodeError) as exc:
                raise self._process_error("native corpus helper I/O failed") from exc
            if not raw_response:
                raise self._process_error("native corpus helper closed its output")
            response = raw_response.rstrip("\r\n").split(" ")
            if response and response[0] == "ERR":
                detail = "native corpus helper returned an error"
                if len(response) >= 3:
                    try:
                        detail = base64.b64decode(response[2], validate=True).decode("utf-8", "replace")
                    except (binascii.Error, UnicodeError):
                        pass
                raise NativeCorpusError(detail)
            return response

    def _process_error(self, message: str) -> NativeCorpusError:
        process = self._process
        detail = ""
        if process.poll() is not None and process.stderr is not None:
            try:
                detail = process.stderr.read().strip()
            except (OSError, UnicodeError):
                pass
        if detail:
            message = f"{message}: {detail}"
        return NativeCorpusError(message)


def _non_negative_int(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NativeCorpusError(f"{field} must be a non-negative integer")
    return value


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise NativeCorpusError(f"invalid base64 in native corpus {field}") from exc


def _parse_entry(response: list[str]) -> NativeCorpusEntry:
    if len(response) != 9 or response[0] != "ENTRY":
        raise NativeCorpusError("native corpus helper returned an invalid corpus entry")
    try:
        input_id = int(response[1])
        parent_id = None if response[2] == "-" else int(response[2])
        energy = int(response[3])
        favored = response[4] == "1"
        if response[4] not in {"0", "1"}:
            raise ValueError("favored")
        new_edges = int(response[6])
        interesting = response[7] == "1"
        if response[7] not in {"0", "1"}:
            raise ValueError("interesting")
    except ValueError as exc:
        raise NativeCorpusError("native corpus helper returned invalid entry metadata") from exc
    if input_id < 0 or (parent_id is not None and parent_id < 0) or energy < 0 or new_edges < 0:
        raise NativeCorpusError("native corpus helper returned negative entry metadata")
    data = _decode(response[5], "entry")
    bitmap_hash = None if response[8] == "-" else _decode(response[8], "coverage")
    if bitmap_hash is not None and len(bitmap_hash) != 32:
        raise NativeCorpusError("native corpus helper returned an invalid bitmap hash")
    return NativeCorpusEntry(
        input_id=input_id,
        data=data,
        parent_id=parent_id,
        energy=energy,
        favored=favored,
        new_edges=new_edges,
        interesting=interesting,
        bitmap_hash=bitmap_hash,
    )
