"""
chain_utils.py — Chain and block utilities for the CIS 5560 blockchain project.

DO NOT MODIFY THIS FILE.

Provides:
  - Chain file loading
  - Block and transaction parsing
  - Canonical hashing for blocks and transactions
  - Blocklist loading
"""

import hashlib
import json

from models import Block, Blockchain, BlockHash, TxID


# ---------------------------------------------------------------------------
# Canonical serialization
# ---------------------------------------------------------------------------

def _canonical_json(obj) -> str:
    """
    Produce a canonical, deterministic JSON string.
    Keys are sorted; no extra whitespace.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Chain / block parsing
# ---------------------------------------------------------------------------

def parse_chain(path: str) -> Blockchain:
    """
    Load a chain from a JSON file.

    The file must contain a JSON array of block objects ordered from genesis
    (index 0) to the current tip.

    Args:
        path: File system path to the chain JSON file.

    Returns:
        A Blockchain object, genesis first.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return Blockchain([Block.from_dict(b) for b in raw])


def parse_transaction(block: Block):
    """
    Extract and return the Transaction from a Block.

    Args:
        block: A Block object.

    Returns:
        The Transaction stored in this block.
    """
    return block.transaction


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def compute_block_hash(block: Block) -> BlockHash:
    """
    Compute the canonical SHA-256 hex hash of a block.

    This hash covers both the ``prev_hash`` and ``transaction`` fields.
    The transaction is serialized via ``transaction.to_dict()``, which students
    override to include their authorization data.

    It is the value stored in the next block's ``prev_hash`` field.

    Args:
        block: A Block object.

    Returns:
        Lowercase hex SHA-256 digest (64 characters).
    """
    serialized = _canonical_json(block.to_dict()).encode("utf-8")
    return BlockHash(hashlib.sha256(serialized).hexdigest())


def compute_txid(transaction) -> TxID:
    """
    Compute the canonical txid of a transaction.

    The txid is the SHA-256 hash of the canonical JSON of ``transaction.to_dict()``.
    Students override ``to_dict()`` to include authorization data, so txid should
    be computed after ``authorize_tx()`` has been called.

    Args:
        transaction: Any object with a ``to_dict()`` method returning the
            canonical core fields (txinputs and txoutputs).

    Returns:
        Lowercase hex SHA-256 digest (64 characters).
    """
    serialized = _canonical_json(transaction.to_dict()).encode("utf-8")
    return TxID(hashlib.sha256(serialized).hexdigest())


# ---------------------------------------------------------------------------
# Blocklist
# ---------------------------------------------------------------------------

def load_blocklist(path: str) -> set[str]:
    """
    Load a blocklist JSON file.

    The file must contain a JSON array of address strings 

    Args:
        path: File system path to the blocklist JSON file.

    Returns:
        A set of address strings.
    """
    with open(path, "r", encoding="utf-8") as fh:
        return {str(addr) for addr in json.load(fh)}


# ---------------------------------------------------------------------------
# Chain file persistence
# ---------------------------------------------------------------------------

def save_chain(chain: Blockchain, path: str) -> None:
    """
    Write a chain to a JSON file.

    Args:
        chain: A Blockchain object, genesis first.
        path:  Destination file path.
    """
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([b.to_dict() for b in chain], fh, indent=2)
