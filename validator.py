from __future__ import annotations

from models import Block, Blockchain
from address import address

from chain_utils import compute_block_hash, compute_txid

from transaction import Transaction


class Validator:
    """
    A stateful validator that maintains a blockchain and its UTXO set.

    The validator is the chain authority: it receives proposed transactions,
    validates them against all applicable rules, and appends valid ones to
    the chain as new blocks.

    Attributes:
        chain (Blockchain): The chain of Block objects, genesis at index 0.
    """

    def __init__(self, genesis_block: Block) -> None:
        raise NotImplementedError

    def validate_transaction(self, authed_tx: Transaction, blocklist: set[address]) -> None:
        """
        Validate a authorized transaction against the current UTXO set.

        Raises ValueError if any of the following hold:
          - Any input references a non-existent or already-spent UTXO
          - Duplicate input outpoints exist in the transaction
          - The sum of output values does not equal the sum of input values
          - Any output pays to a blocklisted address
          - The transaction is not authorized by the rightful owners of the inputs
        """
        raise NotImplementedError

    def append_block(self, authed_tx: Transaction, blocklist: set[address] | None = None) -> None:
        """
        Validate authed_tx and, if valid, append a new Block to self.chain.

        The new block's prev_hash must equal compute_block_hash(self.chain[-1]).
        The full authorized transaction (including any in-memory authentication
        material) is stored in the block.
        If blocklist is None, treat it as an empty set (no AML check).
        Raises ValueError (unchanged chain) if the transaction is invalid.
        """
        raise NotImplementedError
