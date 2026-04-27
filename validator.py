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
        self.chain = Blockchain(blocks=[genesis_block])
        self.utxos = {}
        genesis_txid = compute_txid(genesis_block.transaction)
        for index, txout in enumerate(genesis_block.transaction.txoutputs):
            self.utxos[(genesis_txid, index)] = txout

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
        seen_inputs = set()
        input_totals = 0
        input_owners = []
        missing = object()
        for txinput in authed_tx.txinputs:
            outpoint = (txinput.prev_txid, txinput.prev_out_idx)
            if outpoint in seen_inputs:
                raise ValueError(f"Duplicate input outpoint: {outpoint}")
            prev_output = self.utxos.get(outpoint, missing)
            if prev_output is missing:
                raise ValueError(f"Input references non-existent or already-spent UTXO: {outpoint}")
            seen_inputs.add(outpoint)
            input_totals += prev_output.value
            input_owners.append(prev_output.recipient)
        
        output_totals = 0
        for txoutput in authed_tx.txoutputs:
            if txoutput.recipient in blocklist:
                raise ValueError(f"Output pays to blocklisted address: {txoutput.recipient}")
            output_totals += txoutput.value
        if input_totals != output_totals:
            raise ValueError(f"Input total {input_totals} does not equal output total {output_totals}")
        if not authed_tx.check_authorization(input_owners):
            raise ValueError("Transaction authorization failed")


    def append_block(self, authed_tx: Transaction, blocklist: set[address] | None = None) -> None:
        """
        Validate authed_tx and, if valid, append a new Block to self.chain.

        The new block's prev_hash must equal compute_block_hash(self.chain[-1]).
        The full authorized transaction (including any in-memory authentication
        material) is stored in the block.
        If blocklist is None, treat it as an empty set (no AML check).
        Raises ValueError (unchanged chain) if the transaction is invalid.
        """
        if blocklist is None:
            blocklist = set()
        self.validate_transaction(authed_tx, blocklist)
        new_block = Block(
            prev_hash=compute_block_hash(self.chain[-1]),
            transaction=authed_tx,
        )
        self.chain.append(new_block)
        for txinput in authed_tx.txinputs:
            outpoint = (txinput.prev_txid, txinput.prev_out_idx)
            del self.utxos[outpoint]
        new_txid = compute_txid(authed_tx)
        for index, txout in enumerate(authed_tx.txoutputs):
            self.utxos[(new_txid, index)] = txout