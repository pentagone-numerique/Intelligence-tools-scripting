"""Deterministic, bounded input mutation primitives."""

from __future__ import annotations

import random
from typing import Sequence

from .models import MutationConfig


class Mutator:
    """Apply a reproducible sequence of small mutations to a corpus seed.

    A per-case ``random.Random`` instance is supplied by the engine.  No global
    random state is touched, so a case can be reproduced from its case seed.
    Every operation is bounded by ``max_input_size``.
    """

    def __init__(self, config: MutationConfig, max_input_size: int):
        self.config = config
        self.max_input_size = max_input_size

    def mutate(
        self,
        seed: bytes,
        rng: random.Random,
        corpus: Sequence[bytes] = (),
    ) -> bytes:
        data = bytearray(seed[: self.max_input_size])
        operation_count = rng.randint(1, self.config.max_operations)
        for _ in range(operation_count):
            operation = rng.choice(self.config.operations)
            if operation == "bitflip":
                self._bitflip(data, rng)
            elif operation == "byteflip":
                self._byteflip(data, rng)
            elif operation == "arith8":
                self._arith8(data, rng)
            elif operation == "insert":
                self._insert(data, rng)
            elif operation == "delete":
                self._delete(data, rng)
            elif operation == "duplicate":
                self._duplicate(data, rng)
            elif operation == "dictionary":
                self._dictionary(data, rng)
            elif operation == "overwrite":
                self._overwrite(data, rng)
            elif operation == "splice":
                self._splice(data, rng, corpus)
        return bytes(data[: self.max_input_size])

    @staticmethod
    def _bitflip(data: bytearray, rng: random.Random) -> None:
        if not data:
            return
        index = rng.randrange(len(data))
        data[index] ^= 1 << rng.randrange(8)

    @staticmethod
    def _byteflip(data: bytearray, rng: random.Random) -> None:
        if not data:
            return
        index = rng.randrange(len(data))
        value = rng.randrange(1, 256)
        data[index] ^= value

    @staticmethod
    def _arith8(data: bytearray, rng: random.Random) -> None:
        if not data:
            return
        index = rng.randrange(len(data))
        delta = rng.randint(1, 35)
        if rng.choice((True, False)):
            delta = -delta
        data[index] = (data[index] + delta) % 256

    def _insert(self, data: bytearray, rng: random.Random) -> None:
        if len(data) >= self.max_input_size:
            return
        count = rng.randint(1, min(16, self.max_input_size - len(data)))
        token = self._random_token(count, rng)
        index = rng.randrange(len(data) + 1)
        data[index:index] = token

    def _delete(self, data: bytearray, rng: random.Random) -> None:
        if not data:
            return
        count = rng.randint(1, min(16, len(data)))
        index = rng.randrange(len(data) - count + 1)
        del data[index : index + count]

    def _duplicate(self, data: bytearray, rng: random.Random) -> None:
        if not data or len(data) >= self.max_input_size:
            return
        count = rng.randint(1, min(16, len(data), self.max_input_size - len(data)))
        source = rng.randrange(len(data) - count + 1)
        destination = rng.randrange(len(data) + 1)
        chunk = data[source : source + count]
        data[destination:destination] = chunk

    def _dictionary(self, data: bytearray, rng: random.Random) -> None:
        if not self.config.dictionary:
            self._insert(data, rng)
            return
        token = rng.choice(self.config.dictionary)
        if not token:
            return
        room = self.max_input_size - len(data)
        if room <= 0:
            return
        token = token[:room]
        if not token:
            return
        if data and rng.choice((True, False)):
            index = rng.randrange(len(data))
            end = min(len(data), index + len(token))
            data[index:end] = token[: end - index]
        else:
            index = rng.randrange(len(data) + 1)
            data[index:index] = token

    def _overwrite(self, data: bytearray, rng: random.Random) -> None:
        if not data:
            self._insert(data, rng)
            return
        count = rng.randint(1, min(16, len(data)))
        index = rng.randrange(len(data) - count + 1)
        data[index : index + count] = self._random_token(count, rng)

    def _splice(self, data: bytearray, rng: random.Random, corpus: Sequence[bytes]) -> None:
        if not corpus:
            self._insert(data, rng)
            return
        other = corpus[rng.randrange(len(corpus))]
        if not other:
            return
        left = rng.randrange(len(data) + 1) if data else 0
        right = rng.randrange(len(other) + 1)
        chunk = other[right : right + min(32, len(other) - right)]
        room = self.max_input_size - left
        if room <= 0:
            return
        data[left:] = data[left : left + room - min(len(chunk), room)] + chunk[:room]

    @staticmethod
    def _random_token(count: int, rng: random.Random) -> bytes:
        return bytes(rng.randrange(256) for _ in range(count))
