"""Optional local IPC client for the native SALOMON corpus scheduler.

The Python engine does not start this helper by default. A campaign can opt
into it when the Rust ``salomon-corpusd`` binary is available. Communication
uses a versioned line protocol over pipes, never a shell or a network socket.
Batch operations keep the control boundary out of the per-input hot path.
"""

from __future__ import annotations

import base64
import binascii
import subprocess
import threading
from dataclasses import dataclass
from typing import Sequence

_PROTOCOL_VERSION = "1"
_MAX_BATCH_SIZE = 1_024
_MAX_BATCH_FRAME_BYTES = 8 * 1024 * 1024


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

    This client is deliberately explicit and opt-in. The current Python
    engine remains independent from it; callers can use batch operations for
    corpus/control synchronization without putting a network RPC in the
    mutation/execution loop.
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

        self._max_input_bytes = max_input_bytes
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
        self._validate_data(data)
        parent = _parent_token(parent_id)
        response = self._request(f"ADD {parent} {_encode(data)}")
        return _parse_entry(response)

    def add_many(
        self,
        items: Sequence[tuple[bytes, int | None]],
    ) -> list[NativeCorpusEntry]:
        """Add entries in bounded frames and read framed multi-line responses."""

        if not items:
            return []
        if len(items) > _MAX_BATCH_SIZE:
            raise NativeCorpusError(f"native corpus batch exceeds {_MAX_BATCH_SIZE} entries")
        encoded: list[tuple[str, str]] = []
        for data, parent_id in items:
            self._validate_data(data)
            encoded.append((_parent_token(parent_id), _encode(data)))

        entries: list[NativeCorpusEntry] = []
        fields = ["ADD_BATCH", "0"]
        count = 0
        frame_size = len(fields[0]) + 1

        def flush() -> None:
            nonlocal fields, count, frame_size
            if count == 0:
                return
            fields[1] = str(count)
            responses = self._request_batch(" ".join(fields), expected=count)
            entries.extend(_parse_entry(response) for response in responses)
            fields = ["ADD_BATCH", "0"]
            count = 0
            frame_size = len(fields[0]) + 1

        for parent, payload in encoded:
            item_size = len(parent) + len(payload) + 2
            if count and frame_size + item_size > _MAX_BATCH_FRAME_BYTES:
                flush()
            if frame_size + item_size > _MAX_BATCH_FRAME_BYTES:
                raise NativeCorpusError("a single native corpus seed exceeds the IPC frame limit")
            fields.extend((parent, payload))
            count += 1
            frame_size += item_size
        flush()
        return entries

    def next(self) -> NativeCorpusEntry | None:
        response = self._request("NEXT")
        if response == ["NONE"]:
            return None
        return _parse_entry(response)

    def next_batch(self, count: int) -> list[NativeCorpusEntry]:
        count = _batch_count(count)
        responses = self._request_batch(f"NEXT_BATCH {count}", expected=count, allow_short=True)
        return [_parse_entry(response) for response in responses]

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

    def feedback_many(
        self,
        items: Sequence[tuple[int, int, bool, int, bool, bytes | None]],
    ) -> None:
        """Apply feedback for several selected entries in one IPC request."""

        if not items:
            return
        if len(items) > _MAX_BATCH_SIZE:
            raise NativeCorpusError(f"native corpus batch exceeds {_MAX_BATCH_SIZE} entries")
        fields = ["FEEDBACK_BATCH", str(len(items))]
        for input_id, energy, favored, new_edges, interesting, bitmap_hash in items:
            input_id = _non_negative_int(input_id, "input_id")
            energy = _non_negative_int(energy, "energy")
            new_edges = _non_negative_int(new_edges, "new_edges")
            if bitmap_hash is not None and len(bitmap_hash) != 32:
                raise NativeCorpusError("bitmap_hash must contain exactly 32 bytes")
            fields.extend(
                (
                    str(input_id),
                    str(energy),
                    "1" if favored else "0",
                    str(new_edges),
                    "1" if interesting else "0",
                    "-" if bitmap_hash is None else _encode(bitmap_hash),
                )
            )
        response = self._request(" ".join(fields))
        if response != ["OK", "FEEDBACK_BATCH"]:
            raise NativeCorpusError("native corpus helper rejected feedback batch")

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

    def _validate_data(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise NativeCorpusError("native corpus input must be bytes")
        if len(data) > self._max_input_bytes:
            raise NativeCorpusError(
                f"native corpus input exceeds configured limit of {self._max_input_bytes} bytes"
            )

    def _request(self, line: str) -> list[str]:
        with self._lock:
            self._write_locked(line)
            return self._read_locked()

    def _request_batch(
        self,
        line: str,
        *,
        expected: int,
        allow_short: bool = False,
    ) -> list[list[str]]:
        with self._lock:
            self._write_locked(line)
            header = self._read_locked()
            if len(header) != 2 or header[0] != "BATCH":
                raise NativeCorpusError("native corpus helper returned an invalid batch header")
            try:
                count = int(header[1])
            except ValueError as exc:
                raise NativeCorpusError("native corpus helper returned an invalid batch count") from exc
            if count < 0 or count > expected or (not allow_short and count != expected):
                raise NativeCorpusError("native corpus helper returned an unexpected batch size")
            responses = [self._read_locked() for _ in range(count)]
            trailer = self._read_locked()
            if trailer != ["END", "BATCH"]:
                raise NativeCorpusError("native corpus helper returned an invalid batch trailer")
            return responses

    def _write_locked(self, line: str) -> None:
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
        except (BrokenPipeError, OSError, UnicodeError) as exc:
            raise self._process_error("native corpus helper I/O failed") from exc

    def _read_locked(self) -> list[str]:
        process = self._process
        if process.stdout is None:
            raise NativeCorpusError("native corpus helper output pipe is unavailable")
        try:
            raw_response = process.stdout.readline()
        except (OSError, UnicodeError) as exc:
            raise self._process_error("native corpus helper output failed") from exc
        if not raw_response:
            raise self._process_error("native corpus helper closed its output")
        response = raw_response.rstrip("\r\n").split()
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


def _batch_count(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_BATCH_SIZE:
        raise NativeCorpusError(f"native corpus batch size must be between 1 and {_MAX_BATCH_SIZE}")
    return value


def _parent_token(parent_id: int | None) -> str:
    return "-" if parent_id is None else str(_non_negative_int(parent_id, "parent_id"))


def _non_negative_int(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NativeCorpusError(f"{field} must be a non-negative integer")
    return value


def _encode(value: bytes) -> str:
    # A line protocol cannot carry an empty whitespace-delimited field.
    return "~" if not value else base64.b64encode(value).decode("ascii")


def _decode(value: str, field: str) -> bytes:
    if value == "~":
        return b""
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
