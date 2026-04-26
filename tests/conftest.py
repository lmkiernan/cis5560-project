"""
tests/conftest.py — Shared pytest fixtures for the CIS 5560 test suite.

All fixtures generate cryptographic test data from scratch so the test suite
is fully self-contained (no pre-generated chain files required).

Fixture dependency graph:
  keys
    └─> genesis_block, blocklist_set
          └─> simple_chain, aml_chain, utxo_simple, utxo_aml
                └─> (used by individual tests)
"""

import hashlib
import sys
import os
import time

import pytest

# Ensure project root is on the path so we can import student modules.
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _project_root)

# When a solutions/ directory is present (instructor testing), re-insert it
# at position 0 so it takes priority over the project root stubs.
_solutions_dir = os.path.join(_project_root, "solutions")
if os.path.isdir(_solutions_dir):
    # Always insert at 0 (even if already present elsewhere) so solutions
    # stays ahead of the project root that was just inserted above.
    if _solutions_dir in sys.path:
        sys.path.remove(_solutions_dir)
    sys.path.insert(0, _solutions_dir)
    # Pre-import the solution modules so sys.modules is populated before
    # pytest's prepend import mode can shadow them with project-root stubs.
    import address           # noqa: F401, E402
    import wallet            # noqa: F401, E402
    import validator         # noqa: F401, E402
    import transaction       # noqa: F401, E402

from chain_utils import compute_txid, compute_block_hash
from models import Block, BlockHash, Blockchain, TxInput, TxOutput, Value, OutIndex, TxID
from address import generate_addr_and_key

# Chain building uses the student's own authorization mechanism.
# This means the conftest fixtures exercise the student's Transaction
# end-to-end: authorize_tx() is called to build the chain, and the validator
# calls check_authorization() as a black box when validating transactions.
from transaction import Transaction


# ---------------------------------------------------------------------------
# Helpers (not fixtures)
# ---------------------------------------------------------------------------

def _make_genesis_block(tx: Transaction) -> Block:
    """
    Create a genesis block with a unique timestamp-derived prev_hash.

    Genesis blocks no longer use ``prev_hash=None``.  Instead, each genesis
    block receives a unique 64-character hex BlockHash computed from the
    current nanosecond timestamp.  This ensures that two genesis blocks
    created at different times — even with identical transaction contents —
    produce different block hashes and therefore different downstream hashes
    for every block in their respective chains.

    This property is required for the O(1) non-extension detection tests:
    chains with different genesis blocks are structurally distinct even when
    their transaction contents are identical.
    """
    ts_hash = BlockHash(hashlib.sha256(str(time.time_ns()).encode()).hexdigest())
    return Block(prev_hash=ts_hash, transaction=tx)


def _make_authorized_tx(inputs_info, outputs):
    """
    Build and authorize a transaction using the student's Transaction.authorize_tx() instance method.

    inputs_info: [(prev_txid, prev_out_idx, authkey_hex), ...]
    outputs:     [{"value": int, "recipient": address_hex}, ...]

    Returns a Transaction.
    """
    txinputs = [
        TxInput(prev_txid=TxID(txid), prev_out_idx=OutIndex(idx))
        for txid, idx, _ in inputs_info
    ]
    txoutputs = [
        TxOutput(value=Value(o["value"]), recipient=str(o["recipient"]))
        for o in outputs
    ]
    auth_keys = [ak for _, _, ak in inputs_info]
    tx = Transaction(txinputs=txinputs, txoutputs=txoutputs)
    tx.authorize_tx(auth_keys)
    return tx


def _append_block(chain, authed_tx):
    """
    Append an authorized transaction as a new block and return the updated chain.

    The full authorized transaction (including any in-memory authentication
    material) is stored in the block.
    """
    prev_hash = compute_block_hash(chain[-1])
    chain.append(Block(prev_hash=prev_hash, transaction=authed_tx))
    return chain


# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def keys():
    """
    Generate five keypairs, returned as a dict keyed by name.

    {
        "alice": (auth_key_hex, addr_hex),
        "bob":   (auth_key_hex, addr_hex),
        "carol": (auth_key_hex, addr_hex),
        "dave":  (auth_key_hex, addr_hex),
        "eve":   (auth_key_hex, addr_hex),   # will be blocklisted
    }
    """
    def _kp():
        addr, auth_key = generate_addr_and_key()
        return auth_key, addr

    return {
        "alice": _kp(),
        "bob":   _kp(),
        "carol": _kp(),
        "dave":  _kp(),
        "eve":   _kp(),
    }


@pytest.fixture(scope="session")
def blocklist_set(keys):
    """A set containing only Eve's address."""
    return {keys["eve"][1]}


@pytest.fixture(scope="session")
def genesis_block(keys):
    """
    Genesis block: Alice gets 100, Bob gets 50.

    The genesis block's prev_hash is a unique timestamp-derived BlockHash
    (not null).  This ensures that even chains with identical transaction
    contents have distinct block hashes throughout.

    Block(
        prev_hash=<timestamp-derived BlockHash>,
        transaction=Transaction(
            txinputs=[],
            txoutputs=[
                TxOutput(value=100, recipient=alice_addr),
                TxOutput(value=50,  recipient=bob_addr),
            ]
        )
    )
    """
    alice_addr = keys["alice"][1]
    bob_addr   = keys["bob"][1]
    tx = Transaction.from_dict({
        "txinputs": [],
        "txoutputs": [
            {"value": 100, "recipient": alice_addr},
            {"value": 50,  "recipient": bob_addr},
        ],
    })
    return _make_genesis_block(tx)


@pytest.fixture(scope="session")
def genesis_aml_block(keys):
    """
    AML genesis block: Alice gets 100, Eve (blocklisted) gets 50.

    Uses a timestamp-derived prev_hash (not null).
    """
    alice_addr = keys["alice"][1]
    eve_addr   = keys["eve"][1]
    tx = Transaction.from_dict({
        "txinputs": [],
        "txoutputs": [
            {"value": 100, "recipient": alice_addr},
            {"value": 50,  "recipient": eve_addr},
        ],
    })
    return _make_genesis_block(tx)


# ---------------------------------------------------------------------------
# Simple chain fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def simple_chain(keys, genesis_block):
    """
    A 5-block chain (genesis + 4 transactions) for basic UTXO testing.

    Block 0 (genesis): Alice←100, Bob←50
    Block 1: Alice (100) → 40→Bob, 60→Alice
    Block 2: Bob   (50)  → 30→Carol, 20→Bob
    Block 3: Bob   (tx1 out0=40) → 40→Dave
    Block 4: Alice (tx1 out1=60) → 60→Carol

    Final UTXOs:
        (tx2, 0): 30 → Carol
        (tx2, 1): 20 → Bob
        (tx3, 0): 40 → Dave
        (tx4, 0): 60 → Carol
    """
    alice_auth_key, alice_addr = keys["alice"]
    bob_auth_key,   bob_addr   = keys["bob"]
    carol_addr = keys["carol"][1]
    dave_addr  = keys["dave"][1]

    chain = Blockchain([genesis_block])
    g_txid = compute_txid(genesis_block.transaction)

    tx1 = _make_authorized_tx(
        [(g_txid, 0, alice_auth_key)],
        [{"value": 40, "recipient": bob_addr}, {"value": 60, "recipient": alice_addr}],
    )
    _append_block(chain, tx1)
    tx1_id = compute_txid(tx1)

    tx2 = _make_authorized_tx(
        [(g_txid, 1, bob_auth_key)],
        [{"value": 30, "recipient": carol_addr}, {"value": 20, "recipient": bob_addr}],
    )
    _append_block(chain, tx2)

    tx3 = _make_authorized_tx(
        [(tx1_id, 0, bob_auth_key)],
        [{"value": 40, "recipient": dave_addr}],
    )
    _append_block(chain, tx3)

    tx4 = _make_authorized_tx(
        [(tx1_id, 1, alice_auth_key)],
        [{"value": 60, "recipient": carol_addr}],
    )
    _append_block(chain, tx4)

    return chain


# ---------------------------------------------------------------------------
# AML chain fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def aml_chain(keys, genesis_aml_block):
    """
    A 6-block chain that exercises taint tracing and validator-side AML.

    Block 0 (genesis): Alice←100, Eve(blocklisted)←50
    Block 1: Eve  (50)        → 50→Carol           [tainted path starts]
    Block 2: Carol(50)        → 25→Dave, 25→Carol  [Dave and Carol: tainted]
    Block 3: Alice(100)       → 40→Bob, 60→Alice   [Bob and Alice: untainted]
    Block 4: Alice(60 change) → 60→Dave            [Dave's second coin: untainted]
    Block 5: Dave (tainted 25)→ 25→Bob             [Bob's second coin: tainted]

    Final owned UTXOs by holder:
        Bob:   tx3 out0 (40, untainted), tx5 out0 (25, tainted)
        Carol: tx2 out1 (25, tainted)
        Dave:  tx4 out0 (60, untainted)
    """
    alice_auth_key, alice_addr = keys["alice"]
    bob_addr             = keys["bob"][1]
    carol_auth_key, carol_addr = keys["carol"]
    dave_auth_key,  dave_addr  = keys["dave"]
    eve_auth_key,   eve_addr   = keys["eve"]

    chain = Blockchain([genesis_aml_block])
    g_txid = compute_txid(genesis_aml_block.transaction)

    # Block 1: Eve → Carol
    tx1 = _make_authorized_tx(
        [(g_txid, 1, eve_auth_key)],
        [{"value": 50, "recipient": carol_addr}],
    )
    _append_block(chain, tx1)
    tx1_id = compute_txid(tx1)

    # Block 2: Carol → Dave + Carol
    tx2 = _make_authorized_tx(
        [(tx1_id, 0, carol_auth_key)],
        [{"value": 25, "recipient": dave_addr}, {"value": 25, "recipient": carol_addr}],
    )
    _append_block(chain, tx2)
    tx2_id = compute_txid(tx2)

    # Block 3: Alice → Bob + Alice
    tx3 = _make_authorized_tx(
        [(g_txid, 0, alice_auth_key)],
        [{"value": 40, "recipient": bob_addr}, {"value": 60, "recipient": alice_addr}],
    )
    _append_block(chain, tx3)
    tx3_id = compute_txid(tx3)

    # Block 4: Alice → Dave
    tx4 = _make_authorized_tx(
        [(tx3_id, 1, alice_auth_key)],
        [{"value": 60, "recipient": dave_addr}],
    )
    _append_block(chain, tx4)

    # Block 5: Dave (tainted) → Bob
    tx5 = _make_authorized_tx(
        [(tx2_id, 0, dave_auth_key)],
        [{"value": 25, "recipient": bob_addr}],
    )
    _append_block(chain, tx5)

    return chain

