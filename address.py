"""
address.py — Define your address and authkey types here.

`address` is the public identity of a wallet.  It appears as TxOutput.recipient,
in Validator blocklists, and wherever a coin's owner is identified.

`authkey` is the secret credential used to authorize spending.  It is passed to
Transaction.authorize_tx and kept private.

Assign each to the appropriate key class from crypto_utils, then implement
generate_addr_and_key() to produce a fresh (address, authkey) pair.
Your transaction.py must be consistent with whatever types you assign here.

IMPORTANT: This file must be implemented before any other file in the project.
transaction.py, validator.py, and wallet.py all import `address` and `authkey`
from this module at load time.  If those names are not defined here, every
import will fail with an ImportError.
"""

# TODO: import the key types you need from crypto_utils.

# Placeholder definitions — replace both of these with your chosen types from
# crypto_utils before implementing anything else.
address = str   # TODO: replace with your chosen address type from crypto_utils
authkey = str   # TODO: replace with your chosen authkey type from crypto_utils


def generate_addr_and_key() -> tuple["address", "authkey"]:
    """
    Generate and return a fresh (address, authkey) pair.

    Wallet.create() calls this function — you do not need to modify wallet.py.
    """
    # TODO: replace with an appropriate means of generating an address and authorization key
    (None, None)
