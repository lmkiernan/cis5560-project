"""
models.py - Core blockchain data model classes.

These classes make transaction, block, and blockchain structure explicit for
students while remaining compatible with existing dict/list-based utilities.

Key design notes
----------------
- `Block.transaction` stores the full Transaction object (including any
  authentication material set by the student's implementation).
- The student-facing `Transaction` class (with authorization methods) lives in
  transaction.py. `Block.from_dict` imports it lazily to avoid a circular import.
- Coin recipients are stored as plain `str` values.  The student's concrete
  `address` type (defined in address.py) is a str subclass, so equality
  comparisons work across both.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Domain type wrappers
#
# Each type is a thin subclass of its underlying primitive (str or int), so
# it can be used anywhere the primitive is expected with no conversion needed.
# ---------------------------------------------------------------------------


class TxID(str):
    """A SHA-256 transaction ID, hex-encoded (64 characters / 32 bytes)."""

    def __new__(cls, value: str) -> "TxID":
        if len(value) != 64:
            raise ValueError(
                f"TxID must be 64 hex characters (32 bytes); got {len(value)}"
            )
        return super().__new__(cls, value)


class BlockHash(str):
    """A SHA-256 block hash, hex-encoded (64 characters / 32 bytes)."""

    def __new__(cls, value: str) -> "BlockHash":
        if len(value) != 64:
            raise ValueError(
                f"BlockHash must be 64 hex characters (32 bytes); got {len(value)}"
            )
        return super().__new__(cls, value)


class Value(int):
    """A coin amount (non-negative integer)."""

    def __new__(cls, value: int) -> "Value":
        if value < 0:
            raise ValueError(f"Value must be non-negative; got {value}")
        return super().__new__(cls, value)


class OutIndex(int):
    """An output index within a transaction (non-negative integer)."""

    def __new__(cls, value: int) -> "OutIndex":
        if value < 0:
            raise ValueError(f"OutIndex must be non-negative; got {value}")
        return super().__new__(cls, value)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TxInput:
    """A reference to a previously created transaction output."""

    prev_txid: TxID
    prev_out_idx: OutIndex

    def to_dict(self) -> dict:
        return {
            "prev_txid": self.prev_txid,
            "prev_out_idx": self.prev_out_idx,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TxInput":
        return cls(
            prev_txid=TxID(data["prev_txid"]),
            prev_out_idx=OutIndex(data["prev_out_idx"]),
        )


@dataclass(frozen=True)
class TxOutput:
    """A newly created coin allocation."""

    value: Value
    recipient: str

    def to_dict(self) -> dict:
        return {"value": self.value, "recipient": self.recipient}

    @classmethod
    def from_dict(cls, data: dict) -> "TxOutput":
        return cls(value=Value(data["value"]), recipient=str(data["recipient"]))


@dataclass
class Block:
    """A block in the chain, linking to the previous block via prev_hash.

    For non-genesis blocks, ``prev_hash`` is the SHA-256 hash of the preceding
    block (a 64-character lowercase hex string).

    For genesis blocks, ``prev_hash`` is a unique 64-character hex string
    derived from a timestamp at block-creation time.  It is **never** ``None``
    in newly constructed chains — the ``None`` case is retained only for
    deserialising legacy JSON files.

    ``transaction`` stores the full Transaction object (including any
    authentication material attached in-memory by the student's implementation).
    The full transaction is written to JSON via ``transaction.to_dict()``,
    which students override to include their authorization data.
    """

    prev_hash: BlockHash | None
    transaction: Any  # full Transaction object (from transaction.py; includes any in-memory authorization data)

    def to_dict(self) -> dict:
        return {
            "prev_hash": self.prev_hash,
            "transaction": self.transaction.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        from transaction import Transaction  # lazy import — transaction.py imports models, not vice versa
        ph = data.get("prev_hash")
        return cls(
            prev_hash=BlockHash(ph) if ph is not None else None,
            transaction=Transaction.from_dict(data["transaction"]),
        )


@dataclass
class Blockchain:
    """An ordered list of blocks from genesis (index 0) to tip."""

    blocks: list[Block]

    def __iter__(self):
        return iter(self.blocks)

    def __len__(self) -> int:
        return len(self.blocks)

    def __getitem__(self, index):
        result = self.blocks[index]
        if isinstance(index, slice):
            return Blockchain(result)
        return result

    @property
    def tip(self) -> Block:
        if not self.blocks:
            raise ValueError("Blockchain is empty.")
        return self.blocks[-1]

    def append(self, block: Block) -> None:
        self.blocks.append(block)

    def to_list(self) -> list[dict]:
        return [block.to_dict() for block in self.blocks]

    @classmethod
    def from_list(cls, blocks: Iterable[dict]) -> "Blockchain":
        return cls([Block.from_dict(block) for block in blocks])
