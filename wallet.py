from __future__ import annotations

import json
import os

from crypto_utils import (
    SymEncScheme, SymKey, SymCiphertext,
    PubEncScheme, PubEncPublicKey, PubEncPrivateKey, PubEncCiphertext,
)
from chain_utils import compute_txid, compute_block_hash
from models import Blockchain
from address import address, authkey, generate_addr_and_key
from transaction import Transaction


class Wallet:
    """
    An in-memory wallet that manages a keypair and interacts with the blockchain.

    Attributes:
        auth_key (authkey): The secret key used to authorize transactions.
        addr     (address): The address identifying this wallet on-chain.

    You may add any additional internal state that your design requires.
    """

    def __init__(
        self,
        auth_key: authkey,
        addr: address,
    ) -> None:
        self.auth_key = auth_key
        self.addr = addr

    # -----------------------------------------------------------------------
    # Pre-implemented accessors — do not modify
    # -----------------------------------------------------------------------

    def get_authkey(self) -> authkey:
        return self.auth_key

    def get_address(self) -> address:
        return self.addr

    # -----------------------------------------------------------------------
    # Methods to implement
    # -----------------------------------------------------------------------

    @classmethod
    def create(cls) -> "Wallet":
        """Generate a fresh keypair and return a new Wallet."""
        addr, key = generate_addr_and_key()
        return cls(key, addr)

    @classmethod
    def load(cls, wallet_file: dict, passphrase: str) -> "Wallet":
        """
        Decrypt and reconstruct a Wallet from a saved wallet file dict.
        Raises ValueError for wrong passphrase or malformed file.
        """
        raise NotImplementedError

    def save(self, passphrase: str) -> dict:
        """
        Encrypt the wallet's key material with passphrase and return a
        JSON-serializable dict. The dict must contain whatever your encryption
        scheme needs to fully recover the wallet's keypair in a new session.
        The format is up to you.

        Each call to save() must produce a different dict even when the
        passphrase is the same — use fresh randomness on every call.
        """
        raise NotImplementedError

    def scan_for_coins(self, chain: Blockchain) -> list[dict]:
        """
        Scan the blockchain and return all UTXOs currently owned by this wallet.

        Each returned UTXO dict must contain at least:
            txid, out_idx, value, recipient

        An output is owned by this wallet if output.recipient == self.get_address().
        An output is unspent if no later transaction in the chain claims it as an input.

        If the provided chain is empty, return an empty list.

        This method may be called multiple times as the chain grows. When called
        more than once, the newly supplied chain must be an extension of the chain
        this wallet has previously processed — that is, the new chain must be the
        old chain with zero or more additional blocks appended at the end. If the
        provided chain is not an extension of the previously seen chain, raise
        ValueError.

        Think carefully about how to handle repeated calls on chain extensions
        efficiently — naively rescanning the entire chain each time will not
        meet the efficiency requirements of the grading suite.

        Non-extension detection must be efficient.
        """
        raise NotImplementedError

    def classify_coins_by_taint(
        self,
        chain: Blockchain,
        blocklist: set[address],
    ) -> dict:
        """
        Classify owned UTXOs as tainted or untainted given a blocklist.

        A coin is tainted if any output anywhere in its ancestry was paid to
        an address in blocklist. Ancestry is determined by recursively following
        transaction inputs back to genesis.

        scan_for_coins will always be called before this method.

        Returns:
            {"tainted": [<utxo>, ...], "untainted": [<utxo>, ...]}

        Think carefully about how to handle repeated calls with the same or
        a changing blocklist efficiently — redundant traversal will not meet
        the efficiency requirements of the grading suite.
        """
        raise NotImplementedError

    def create_transaction(
        self,
        recipients: list[address],
        values: list[int],
    ) -> Transaction:
        """
        Construct and authorize a transaction paying each recipient the
        corresponding value, funded from this wallet's available UTXOs.

        scan_for_coins will always be called before this method.

        Steps:
          1. Sum the requested values to find the total payment amount.
          2. Select enough of this wallet's UTXOs to cover the total.
          3. If the selected inputs exceed the total, add a change output
             back to this wallet for the difference.
          4. Construct a Transaction with the chosen inputs and all outputs
             (recipients + change if needed).
          5. Authorize the transaction using this wallet's authkey.
          6. Return the fully authorized Transaction.

        Raises ValueError if the wallet's available balance is insufficient
        to cover the requested total.
        """
        raise NotImplementedError
