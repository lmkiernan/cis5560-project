from __future__ import annotations

from dataclasses import dataclass
import json

from crypto_utils import SignScheme

from models import TxInput, TxOutput
from address import address, authkey


@dataclass
class Transaction:
    """
    A transaction: a list of inputs, a list of outputs, and whatever
    authorization data your scheme requires.

    The base serialization methods (to_dict, from_dict) are pre-implemented
    with the core fields only.  Your tasks are:
      1. Implement authorize_tx and check_authorization (required).
      2. Override to_dict and from_dict to include and restore your
         authorization data so it survives save_chain / parse_chain
         round-trips.

    You may add any additional attributes to store authorization data —
    for example, a list of signatures or MAC tags.

    Implementation note — two valid approaches for storing authorization data:
      (a) Assign it directly on self inside authorize_tx() (e.g.
          ``self.my_field = ...``).  No class-level declaration needed.
      (b) Declare it as a dataclass field above.  If you do this, the field
          must have a default value (e.g. ``field(default_factory=...)``)
          so that the base from_dict(), which calls
          cls(txinputs=..., txoutputs=...), continues to work.

    Usage pattern:
        tx = Transaction(txinputs=[...], txoutputs=[...])
        tx.authorize_tx([authkey1, authkey2, ...])
        # tx is now ready to submit to the validator
    """

    txinputs: list[TxInput]
    txoutputs: list[TxOutput]

    # -----------------------------------------------------------------------
    # Base serialization — override both methods to include your auth data
    # -----------------------------------------------------------------------

    def to_dict(self) -> dict:
        """
        Serialize this transaction to a dict.

        The base implementation covers txinputs and txoutputs only.
        Override this method to also include your authorization data
        (e.g. signatures) so that it is persisted when the chain is saved.
        """
        return {
            "txinputs": [inp.to_dict() for inp in self.txinputs],
            "txoutputs": [out.to_dict() for out in self.txoutputs],
            "signatures": getattr(self, "signatures", []),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        """
        Reconstruct a Transaction from a dict produced by to_dict().

        The base implementation restores txinputs and txoutputs only.
        Override this method to also restore your authorization data so
        that check_authorization() returns True on the reconstructed object.
        Use data.get("your_field", default) to handle dicts that predate
        your auth field.
        """
        tx = cls(
            txinputs=[TxInput.from_dict(inp) for inp in data.get("txinputs", [])],
            txoutputs=[TxOutput.from_dict(out) for out in data.get("txoutputs", [])],
        )
        tx.signatures = data.get("signatures", [])
        return tx

    # -----------------------------------------------------------------------
    # To implement
    # -----------------------------------------------------------------------
    def unsigned_dict(self) -> dict:
        return { "txinputs": [inp.to_dict() for inp in self.txinputs], "txoutputs": [out.to_dict() for out in self.txoutputs]}

    def message_bytes(self) -> bytes:
        return json.dumps( self.unsigned_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def authorize_tx(self, authkeys: list[authkey]) -> None:
        """
        Attach authorization data to this transaction in-place.

        authkeys[i] is the authkey of the owner of self.txinputs[i].

        Compute whatever authorization data your scheme requires and store it
        as attributes on self. After this call, check_authorization must return
        True when passed the matching list of addresses.
        """
        if len(authkeys) != len(self.txinputs):
            raise ValueError("Number of authkeys must match number of txinputs.")
        message = self._message_bytes()
        self.signatures = [SignScheme.sign(authkey, message) for authkey in authkeys]

    def check_authorization(self, input_addresses: list[address]) -> bool:
        """
        Return True if this transaction is validly authorized for the given
        input owners, False otherwise.

        input_addresses[i] is the address of the owner of txinputs[i].

        Never raises; return False for any authorization failure including
        mismatched counts, invalid data, or wrong keys.
        """


        try:
            signatures = getattr(self, "signatures", None)
            if signatures is None:
                return False
            if len(input_addresses) != len(self.txinputs) or len(signatures) != len(self.txinputs):
                return False
            message = self.message_bytes()
            return all( SignScheme.verify(addr, message, sig) for addr, sig in zip(input_addresses, signatures))
        except Exception:
            return False

            
