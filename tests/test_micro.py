"""
tests/test_micro.py — Micro test suite for student self-checking.

Run with:
    pytest tests/test_micro.py -v

These tests cover the core correctness behaviors of Transaction, Validator,
and Wallet. They are intentionally direct: no timing measurements, no edge-case
chains, no hidden fixtures. Each test is fully self-contained so you can read
exactly what is being built and what is being asserted.

Passing every test here does not guarantee a full grade — the complete grading
suite is larger and tests additional scenarios including security and efficiency
properties — but failing any test here means something fundamental is broken.

How this file is structured
───────────────────────────
  SECTION 1 — Shared helpers (build a tiny chain)
  SECTION 2 — Transaction: authorization and verification
  SECTION 3 — Wallet: create / save / load
  SECTION 4 — Wallet: scan_for_coins
  SECTION 5 — Wallet: classify_coins_by_taint
  SECTION 6 — Validator: construction and UTXO initialisation
  SECTION 7 — Validator: validate_transaction
  SECTION 8 — Validator: append_block
  SECTION 9 — Wallet: create_transaction
"""

import hashlib
import time

import pytest

# These import from your submission files in the project root.
# No changes needed here.
from wallet      import Wallet
from validator   import Validator
from transaction import Transaction
from address import generate_addr_and_key

from chain_utils  import compute_txid, compute_block_hash
from models       import Block, BlockHash, Blockchain, TxInput, TxOutput, Value, OutIndex, TxID


# =============================================================================
# SECTION 1 — Shared helpers
# =============================================================================

def _make_authorized_tx(inputs_info, outputs):
    """
    Build and authorize a transaction using the Transaction.authorize_tx() instance method.

    inputs_info: list of (prev_txid: str, prev_out_idx: int, authkey: str)
    outputs:     list of {"value": int, "recipient": address_hex}

    Returns a Transaction.
    """
    txinputs = [
        TxInput(TxID(txid), OutIndex(idx))
        for txid, idx, _ in inputs_info
    ]
    txoutputs = [
        TxOutput(Value(o["value"]), str(o["recipient"]))
        for o in outputs
    ]
    auth_keys = [ak for _, _, ak in inputs_info]
    tx = Transaction(txinputs=txinputs, txoutputs=txoutputs)
    tx.authorize_tx(auth_keys)
    return tx


def _make_genesis(outputs):
    """
    Build a genesis Block with a unique timestamp-derived prev_hash and the
    given outputs (no inputs).

    Each call produces a fresh unique block hash, even for identical outputs,
    because the genesis prev_hash is derived from the nanosecond timestamp at
    call time.  This prevents two otherwise-identical chains from being
    mistaken for extensions of each other.

    outputs: list of {"value": int, "recipient": address_hex}
    """
    from transaction import Transaction as BaseTx
    tx = BaseTx.from_dict({"txinputs": [], "txoutputs": outputs})
    ts_hash = BlockHash(hashlib.sha256(str(time.time_ns()).encode()).hexdigest())
    return Block(prev_hash=ts_hash, transaction=tx)


def _append_block(chain, authed_tx):
    """
    Append an authorized transaction as a new block and return the updated chain.

    The full authorized transaction (including any in-memory authentication
    material) is stored in the block.
    """
    prev_hash = compute_block_hash(chain[-1])
    chain.append(Block(prev_hash=prev_hash, transaction=authed_tx))
    return chain


# =============================================================================
# SECTION 2 — Transaction: authorization and verification
# =============================================================================

class TestTransaction:
    """
    Tests for Transaction: authorization and verification.

    Passing these tests confirms that:
      - authorize_tx() attaches authorization to the Transaction in-place
      - check_authorization() accepts a validly authorized transaction
      - check_authorization() rejects an obviously invalid/corrupt authorization

    These tests do NOT prescribe which authorization scheme you use.
    """

    def test_authorize_tx_returns_transaction(self):
        """After authorize_tx, the object must be a Transaction instance."""
        addr, auth_key = generate_addr_and_key()
        recipient_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": addr}])
        g_txid = compute_txid(genesis.transaction)
        result = _make_authorized_tx(
            [(g_txid, 0, auth_key)],
            [{"value": 100, "recipient": recipient_addr}],
        )
        assert isinstance(result, Transaction)

    def test_authorize_tx_preserves_inputs_and_outputs(self):
        """The returned Transaction must contain the correct txinputs and txoutputs."""
        addr, auth_key = generate_addr_and_key()
        recipient_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 50, "recipient": addr}])
        g_txid = compute_txid(genesis.transaction)
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, auth_key)],
            [{"value": 50, "recipient": recipient_addr}],
        )
        assert authed_tx.txinputs[0].prev_txid    == g_txid
        assert authed_tx.txinputs[0].prev_out_idx == 0
        assert authed_tx.txoutputs[0].value       == 50
        assert authed_tx.txoutputs[0].recipient   == recipient_addr

    def test_authorize_tx_multi_input_authorized_correctly(self):
        """
        A transaction with multiple inputs authorized by the correct keys must
        pass check_authorization for those same keys.
        """
        addr_a, auth_key_a = generate_addr_and_key()
        addr_b, auth_key_b = generate_addr_and_key()
        recipient_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([
            {"value": 60, "recipient": addr_a},
            {"value": 40, "recipient": addr_b},
        ])
        g_txid = compute_txid(genesis.transaction)
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, auth_key_a), (g_txid, 1, auth_key_b)],
            [{"value": 100, "recipient": recipient_addr}],
        )
        assert authed_tx.check_authorization([addr_a, addr_b]) is True

    def test_check_authorization_accepts_valid_authorization(self):
        """check_authorization must return True for a correctly authorized transaction."""
        addr, auth_key = generate_addr_and_key()
        recipient_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": addr}])
        g_txid = compute_txid(genesis.transaction)
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, auth_key)],
            [{"value": 100, "recipient": recipient_addr}],
        )
        assert authed_tx.check_authorization([addr]) is True

    def test_check_authorization_accepts_multi_input(self):
        """check_authorization must work correctly for a transaction with multiple inputs."""
        addr_a, auth_key_a = generate_addr_and_key()
        addr_b, auth_key_b = generate_addr_and_key()
        recipient_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([
            {"value": 60, "recipient": addr_a},
            {"value": 40, "recipient": addr_b},
        ])
        g_txid = compute_txid(genesis.transaction)
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, auth_key_a), (g_txid, 1, auth_key_b)],
            [{"value": 100, "recipient": recipient_addr}],
        )
        assert authed_tx.check_authorization([addr_a, addr_b]) is True

    def test_check_authorization_rejects_wrong_authorization(self):
        """
        A transaction authorized by a key that does not belong to the UTXO
        owner must cause check_authorization to return False when the correct
        owner's address is supplied.
        """
        addr, _ = generate_addr_and_key()
        _, wrong_auth_key = generate_addr_and_key()
        recipient_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": addr}])
        g_txid = compute_txid(genesis.transaction)
        # Authorize with the wrong authkey.
        bad_tx = _make_authorized_tx(
            [(g_txid, 0, wrong_auth_key)],
            [{"value": 100, "recipient": recipient_addr}],
        )
        assert bad_tx.check_authorization([addr]) is False

    def test_check_authorization_rejects_wrong_address(self):
        """
        Verifying against an address that does not match the authorizer must
        return False.
        """
        addr, auth_key = generate_addr_and_key()
        other_addr, other_auth_key = generate_addr_and_key()
        recipient_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": addr}])
        g_txid = compute_txid(genesis.transaction)
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, auth_key)],
            [{"value": 100, "recipient": recipient_addr}],
        )
        # Verify with the wrong address
        assert authed_tx.check_authorization([other_addr]) is False

    def test_check_authorization_rejects_mismatched_owner_count(self):
        """
        Supplying no input owners (empty list) for a transaction with one input
        must cause check_authorization to return False.
        """
        addr, auth_key = generate_addr_and_key()
        recipient_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": addr}])
        g_txid = compute_txid(genesis.transaction)
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, auth_key)],
            [{"value": 100, "recipient": recipient_addr}],
        )
        # Passing zero input owners for a one-input transaction must be rejected.
        assert authed_tx.check_authorization([]) is False


# =============================================================================
# SECTION 3 — Wallet: create / save / load
# =============================================================================

class TestWalletCreateSaveLoad:
    """
    Wallet.create() returns a new Wallet with a freshly generated keypair.
    Wallet.save(passphrase) encrypts the keys and returns a dict;
    Wallet.load(wallet_file, passphrase) decrypts it and reconstructs the Wallet.
    """

    def test_create_returns_wallet_instance(self):
        """Wallet.create must return a Wallet object."""
        w = Wallet.create()
        assert isinstance(w, Wallet)

    def test_wallet_exposes_address_method(self):
        """A new wallet must expose get_address()."""
        w = Wallet.create()
        assert callable(getattr(w, "get_address", None))

    def test_two_wallets_have_different_addresses(self):
        """Each Wallet.create call must generate a fresh, independent keypair."""
        w1 = Wallet.create()
        w2 = Wallet.create()
        assert w1.get_address() != w2.get_address()

    def test_save_returns_dict(self):
        """Wallet.save must return a dict."""
        wf = Wallet.create().save("pass")
        assert isinstance(wf, dict)

    def test_load_correct_passphrase_returns_wallet(self):
        """Loading with the correct passphrase must reconstruct a Wallet."""
        wf = Wallet.create().save("correct")
        w = Wallet.load(wf, "correct")
        assert isinstance(w, Wallet)
        assert isinstance(w.get_authkey(), str)
        assert isinstance(w.get_address(), str)

    def test_load_wrong_passphrase_raises(self):
        """Loading with the wrong passphrase must raise ValueError."""
        wf = Wallet.create().save("correct")
        with pytest.raises(ValueError):
            Wallet.load(wf, "wrong")

    def test_round_trip_preserves_keys(self):
        """
        A full save → load cycle must produce a wallet with the same keys as
        the original.  Calling load twice on the same file must yield identical
        keys both times.
        """
        original = Wallet.create()
        wf = original.save("roundtrip")
        recovered1 = Wallet.load(wf, "roundtrip")
        recovered2 = Wallet.load(wf, "roundtrip")
        assert recovered1.get_authkey() == original.get_authkey()
        assert recovered1.get_address() == original.get_address()
        assert recovered2.get_authkey() == original.get_authkey()

    def test_save_produces_fresh_randomness_each_call(self):
        """
        Each save call must use fresh randomness so that two saves of the same
        wallet with the same passphrase yield different outputs.
        """
        w = Wallet.create()
        wf1 = w.save("p")
        wf2 = w.save("p")
        assert wf1 != wf2


# =============================================================================
# SECTION 4 — Wallet: scan_for_coins
# =============================================================================

class TestWalletScanForCoins:
    """
    Wallet.scan_for_coins(chain) scans the blockchain and returns the list of
    UTXOs (unspent transaction outputs) owned by this wallet.

    Required UTXO fields: txid, out_idx, value, recipient.

    The wallet must also support repeated calls on chain extensions: if
    scan_for_coins is called a second time on a longer chain, the result must
    be consistent with a single full scan, and the implementation must handle
    this efficiently.
    """

    def test_returns_list(self):
        """scan_for_coins must return a list."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        wallet = Wallet(alice_auth_key, alice_addr)
        result = wallet.scan_for_coins(Blockchain([genesis]))
        assert isinstance(result, list)

    def test_finds_coin_paid_to_wallet(self):
        """A single coinbase output paid to this wallet must be returned."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        wallet = Wallet(alice_auth_key, alice_addr)
        result = wallet.scan_for_coins(Blockchain([genesis]))
        assert len(result) == 1
        assert result[0]["value"] == 100
        assert result[0]["recipient"] == alice_addr

    def test_utxo_has_required_fields(self):
        """Every returned UTXO dict must contain txid, out_idx, value, recipient."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": 50, "recipient": alice_addr}])
        wallet = Wallet(alice_auth_key, alice_addr)
        result = wallet.scan_for_coins(Blockchain([genesis]))
        assert len(result) == 1
        for field in ("txid", "out_idx", "value", "recipient"):
            assert field in result[0], f"UTXO is missing required field: '{field}'"

    def test_utxo_txid_and_out_idx_are_correct(self):
        """
        The txid in the UTXO must match compute_txid of the transaction that
        produced it.  out_idx must match the position of this output in that
        transaction's output list.
        """
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr, bob_auth_key = generate_addr_and_key()
        # Two outputs: Alice at 0, Bob at 1.
        genesis = _make_genesis([
            {"value": 100, "recipient": alice_addr},
            {"value": 50,  "recipient": bob_addr},
        ])
        expected_txid = compute_txid(genesis.transaction)

        wallet_alice = Wallet(alice_auth_key, alice_addr)
        alice_utxos = wallet_alice.scan_for_coins(Blockchain([genesis]))
        assert alice_utxos[0]["txid"]    == expected_txid
        assert alice_utxos[0]["out_idx"] == 0

        wallet_bob = Wallet(bob_auth_key, bob_addr)
        bob_utxos = wallet_bob.scan_for_coins(Blockchain([genesis]))
        assert bob_utxos[0]["txid"]    == expected_txid
        assert bob_utxos[0]["out_idx"] == 1

    def test_no_coins_found_for_unrelated_key(self):
        """A wallet whose key does not appear in the chain must return an empty list."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        stranger_addr, stranger_auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])

        wallet = Wallet(stranger_auth_key, stranger_addr)
        assert wallet.scan_for_coins(Blockchain([genesis])) == []

    def test_spent_coin_not_returned(self):
        """
        Once a coin is consumed by a transaction, it must no longer appear in
        the UTXO list.

        Chain built here:
            genesis:  Alice ← 100
            block 1:  Alice(100) → Bob(100)    [Alice's coin is spent]
        """
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr,   bob_auth_key   = generate_addr_and_key()

        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        g_txid  = compute_txid(genesis.transaction)

        tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        chain = Blockchain([genesis])
        _append_block(chain, tx)

        # Alice spent her coin; she should have nothing.
        wallet_alice = Wallet(alice_auth_key, alice_addr)
        assert wallet_alice.scan_for_coins(chain) == []

        # Bob received the coin; he should see exactly one UTXO.
        wallet_bob = Wallet(bob_auth_key, bob_addr)
        result = wallet_bob.scan_for_coins(chain)
        assert len(result) == 1
        assert result[0]["value"] == 100

    def test_non_extension_chain_raises(self):
        """Calling scan_for_coins a second time on a chain that is not an extension
        of the previously scanned chain must raise ValueError."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": 10, "recipient": alice_addr}])
        wallet = Wallet(alice_auth_key, alice_addr)
        wallet.scan_for_coins(Blockchain([genesis]))
        other_genesis = _make_genesis([{"value": 5, "recipient": alice_addr}])
        with pytest.raises(ValueError):
            wallet.scan_for_coins(Blockchain([other_genesis]))

    def test_incremental_scan_gives_same_result_as_full_scan(self):
        """
        Scanning blocks at indices 0–1 and then extending to the full
        4-block chain (indices 0–3) must yield the same UTXOs as a single
        full scan over all 4 blocks.

        Chain:
            genesis:  Alice ← 100, Bob ← 50
            block 1:  Alice(100) → Carol(40), Alice(60)
            block 2:  Bob(50)    → Carol(30), Bob(20)
            block 3:  Alice(60)  → Carol(60)   [Alice fully spent]
        """
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr,   bob_auth_key   = generate_addr_and_key()
        carol_addr, carol_auth_key = generate_addr_and_key()

        genesis = _make_genesis([
            {"value": 100, "recipient": alice_addr},
            {"value": 50,  "recipient": bob_addr},
        ])
        g_txid = compute_txid(genesis.transaction)
        chain  = Blockchain([genesis])

        tx1 = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 40, "recipient": carol_addr}, {"value": 60, "recipient": alice_addr}],
        )
        _append_block(chain, tx1)
        tx1_id = compute_txid(tx1)

        tx2 = _make_authorized_tx(
            [(g_txid, 1, bob_auth_key)],
            [{"value": 30, "recipient": carol_addr}, {"value": 20, "recipient": bob_addr}],
        )
        _append_block(chain, tx2)

        tx3 = _make_authorized_tx(
            [(tx1_id, 1, alice_auth_key)],
            [{"value": 60, "recipient": carol_addr}],
        )
        _append_block(chain, tx3)

        # Full scan.
        w_full = Wallet(carol_auth_key, carol_addr)
        full_result = w_full.scan_for_coins(chain)

        # Incremental scan: first half, then the rest.
        w_inc = Wallet(carol_auth_key, carol_addr)
        w_inc.scan_for_coins(chain[:2])         # blocks 0-1
        inc_result = w_inc.scan_for_coins(chain) # extends to blocks 2-3

        full_txids = sorted(u["txid"] for u in full_result)
        inc_txids  = sorted(u["txid"] for u in inc_result)
        assert full_txids == inc_txids, (
            "Incremental scan yielded different UTXOs than a full scan."
        )


# =============================================================================
# SECTION 5 — Wallet: classify_coins_by_taint
# =============================================================================

class TestWalletClassifyByTaint:
    """
    Wallet.classify_coins_by_taint(chain, blocklist) classifies each UTXO
    owned by this wallet as tainted or untainted.

    A coin is TAINTED if any output anywhere in its ancestry (following inputs
    back to genesis) was ever paid to an address in blocklist.

    The method must return:
        {"tainted": [<utxo>, ...], "untainted": [<utxo>, ...]}

    Call scan_for_coins before classify_coins_by_taint so the wallet knows
    which UTXOs it owns.
    """

    def _build_aml_chain(self):
        """
        Build a small chain with one tainted path and one clean path.

            genesis:  Alice ← 100, Eve(blocklisted) ← 50
            block 1:  Eve(50)   → Carol(50)              [taint starts here]
            block 2:  Alice(100)→ Bob(100)                [clean path]

        After this chain:
            Carol owns 50 (tainted: came from Eve)
            Bob   owns 100 (untainted: came from Alice)

        Returns (chain, alice_auth_key, alice_addr, bob_auth_key, bob_addr,
                 carol_auth_key, carol_addr, eve_addr, blocklist_set)
        """
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr,   bob_auth_key   = generate_addr_and_key()
        carol_addr, carol_auth_key = generate_addr_and_key()
        eve_addr,   eve_auth_key   = generate_addr_and_key()

        genesis = _make_genesis([
            {"value": 100, "recipient": alice_addr},
            {"value": 50,  "recipient": eve_addr},
        ])
        g_txid = compute_txid(genesis.transaction)
        chain  = Blockchain([genesis])

        # Block 1: Eve → Carol (tainted transfer)
        tx1 = _make_authorized_tx(
            [(g_txid, 1, eve_auth_key)],
            [{"value": 50, "recipient": carol_addr}],
        )
        _append_block(chain, tx1)

        # Block 2: Alice → Bob (clean transfer)
        tx2 = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        _append_block(chain, tx2)

        blocklist = {eve_addr}
        return (chain, alice_auth_key, alice_addr, bob_auth_key, bob_addr,
                carol_auth_key, carol_addr, eve_addr, blocklist)

    # ── Basic structure ──────────────────────────────────────────────────────

    def test_returns_tainted_and_untainted_keys(self):
        """classify_coins_by_taint must return a dict with 'tainted' and 'untainted' keys."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": 10, "recipient": alice_addr}])
        chain = Blockchain([genesis])
        wallet = Wallet(alice_auth_key, alice_addr)
        wallet.scan_for_coins(chain)
        result = wallet.classify_coins_by_taint(chain, set())
        assert "tainted"   in result
        assert "untainted" in result

    def test_empty_blocklist_means_no_taint(self):
        """With an empty blocklist, every owned coin must be classified as untainted."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": 10, "recipient": alice_addr}])
        chain = Blockchain([genesis])
        wallet = Wallet(alice_auth_key, alice_addr)
        wallet.scan_for_coins(chain)
        result = wallet.classify_coins_by_taint(chain, set())
        assert result["tainted"] == []
        assert len(result["untainted"]) == 1

    def test_all_coins_classified(self):
        """Every UTXO returned by scan_for_coins must appear in exactly one list."""
        chain, _, _, bob_auth_key, bob_addr, carol_auth_key, carol_addr, _, blocklist = (
            self._build_aml_chain()
        )
        # Test with Bob (who has one coin).
        wallet = Wallet(bob_auth_key, bob_addr)
        owned = wallet.scan_for_coins(chain)
        result = wallet.classify_coins_by_taint(chain, blocklist)
        assert len(result["tainted"]) + len(result["untainted"]) == len(owned)

    # ── Correct taint decisions ──────────────────────────────────────────────

    def test_coin_from_clean_source_is_untainted(self):
        """
        Bob's coin comes from Alice, who has no tainted ancestry → untainted.
        """
        chain, _, _, bob_auth_key, bob_addr, _, _, _, blocklist = self._build_aml_chain()
        wallet = Wallet(bob_auth_key, bob_addr)
        wallet.scan_for_coins(chain)
        result = wallet.classify_coins_by_taint(chain, blocklist)
        assert len(result["untainted"]) == 1
        assert result["tainted"]        == []

    def test_coin_from_blocklisted_source_is_tainted(self):
        """
        Carol's coin was forwarded directly from Eve (blocklisted) → tainted.
        """
        chain, _, _, _, _, carol_auth_key, carol_addr, _, blocklist = self._build_aml_chain()
        wallet = Wallet(carol_auth_key, carol_addr)
        wallet.scan_for_coins(chain)
        result = wallet.classify_coins_by_taint(chain, blocklist)
        assert len(result["tainted"])   == 1
        assert result["untainted"]      == []

    def test_taint_propagates_through_multiple_hops(self):
        """
        Taint must follow the coin through intermediate wallets.

        Chain:
            genesis:  Eve(blocklisted) ← 50
            block 1:  Eve(50) → Carol(50)    [hop 1]
            block 2:  Carol(50)→ Dave(50)    [hop 2 — Dave should be tainted]
        """
        eve_addr,   eve_auth_key   = generate_addr_and_key()
        carol_addr, carol_auth_key = generate_addr_and_key()
        dave_addr,  dave_auth_key  = generate_addr_and_key()

        genesis = _make_genesis([{"value": 50, "recipient": eve_addr}])
        g_txid  = compute_txid(genesis.transaction)
        chain   = Blockchain([genesis])

        tx1 = _make_authorized_tx(
            [(g_txid, 0, eve_auth_key)],
            [{"value": 50, "recipient": carol_addr}],
        )
        _append_block(chain, tx1)
        tx1_id = compute_txid(tx1)

        tx2 = _make_authorized_tx(
            [(tx1_id, 0, carol_auth_key)],
            [{"value": 50, "recipient": dave_addr}],
        )
        _append_block(chain, tx2)

        blocklist = {eve_addr}
        wallet = Wallet(dave_auth_key, dave_addr)
        wallet.scan_for_coins(chain)
        result = wallet.classify_coins_by_taint(chain, blocklist)
        assert len(result["tainted"]) == 1
        assert result["untainted"]    == []

    def test_no_false_positives_for_wallet_with_no_coins(self):
        """A wallet with no coins must return two empty lists."""
        chain, _, _, _, _, _, _, _, blocklist = self._build_aml_chain()
        addr, auth_key = generate_addr_and_key()  # key that never appears in the chain
        wallet = Wallet(auth_key, addr)
        wallet.scan_for_coins(chain)
        result = wallet.classify_coins_by_taint(chain, blocklist)
        assert result["tainted"]   == []
        assert result["untainted"] == []

    def test_repeat_call_with_same_blocklist_gives_same_result(self):
        """
        Calling classify_coins_by_taint twice with the same blocklist must
        produce the same classification both times.
        """
        chain, _, _, bob_auth_key, bob_addr, _, _, _, blocklist = self._build_aml_chain()
        wallet = Wallet(bob_auth_key, bob_addr)
        wallet.scan_for_coins(chain)
        r1 = wallet.classify_coins_by_taint(chain, blocklist)
        r2 = wallet.classify_coins_by_taint(chain, blocklist)
        assert len(r1["tainted"])   == len(r2["tainted"])
        assert len(r1["untainted"]) == len(r2["untainted"])


# =============================================================================
# SECTION 6 — Validator: construction and UTXO initialisation
# =============================================================================

class TestValidatorConstruction:
    """
    Validator(genesis_block) initialises the validator with a chain containing
    just the genesis block.  The genesis transaction's outputs must immediately
    be available as spendable UTXOs.
    """

    def test_chain_has_one_block_after_construction(self):
        """validator.chain must contain exactly the genesis block after construction."""
        genesis = _make_genesis([{"value": 100, "recipient": generate_addr_and_key()[0]}])
        validator = Validator(genesis)
        assert len(validator.chain) == 1

    def test_genesis_output_is_spendable(self):
        """
        validate_transaction must accept a transaction that spends the genesis
        output, confirming that output was added to the UTXO set on construction.
        """
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)

        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        validator.validate_transaction(authed_tx, set())  # must not raise

    def test_nonexistent_output_is_not_spendable(self):
        """
        An output index that does not exist (e.g. index 1 of a single-output
        genesis) must not be spendable.
        """
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)

        authed_tx = _make_authorized_tx(
            [(g_txid, 1, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx, set())


# =============================================================================
# SECTION 7 — Validator: validate_transaction
# =============================================================================

class TestValidatorValidateTransaction:
    """
    Validator.validate_transaction(authed_tx, blocklist) checks that a authorized
    transaction is valid before it is included in a block.  It must raise
    ValueError for any of these violations:

      • Non-existent input (the referenced UTXO does not exist)
      • Already-spent input (the UTXO has been consumed by a previous tx)
      • Bad authorization (check_authorization returns False)
      • Value mismatch (sum of outputs ≠ sum of inputs)
      • AML violation (any output is paid to a blocklisted address)
      • Duplicate inputs (same UTXO referenced more than once)

    A valid transaction must pass silently (no exception raised).
    """

    def _setup(self):
        """Return (validator, genesis_txid, alice_auth_key, alice_addr, bob_addr)."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)
        return validator, g_txid, alice_auth_key, alice_addr, bob_addr

    def test_valid_transaction_passes(self):
        """A correctly authorized, balanced transaction must not raise."""
        validator, g_txid, alice_auth_key, _, bob_addr = self._setup()
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        validator.validate_transaction(authed_tx, set())  # must not raise

    def test_nonexistent_utxo_rejected(self):
        """Spending a UTXO that was never created must raise ValueError."""
        validator, _, alice_auth_key, _, bob_addr = self._setup()
        fake_txid = "a" * 64
        authed_tx = _make_authorized_tx(
            [(fake_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx, set())

    def test_bad_authorization_rejected(self):
        """A transaction authorized by the wrong authkey must raise ValueError."""
        validator, g_txid, _, _, bob_addr = self._setup()
        _, wrong_auth_key = generate_addr_and_key()
        # Authorize with a key that does not own the UTXO.
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, wrong_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx, set())

    def test_wrong_authorizer_rejected(self):
        """Authorizing with the wrong authkey (not the UTXO owner) must raise ValueError."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr,   bob_auth_key   = generate_addr_and_key()
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)

        # Bob tries to spend Alice's coin by authorizing with his own key.
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, bob_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx, set())

    def test_output_value_exceeds_input_raises(self):
        """Creating coins out of thin air (outputs > inputs) must raise ValueError."""
        validator, g_txid, alice_auth_key, _, bob_addr = self._setup()
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 101, "recipient": bob_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx, set())

    def test_output_value_below_input_raises(self):
        """Destroying coins (outputs < inputs) must raise ValueError."""
        validator, g_txid, alice_auth_key, _, bob_addr = self._setup()
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 99, "recipient": bob_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx, set())

    def test_aml_output_to_blocklisted_address_rejected(self):
        """Any output paid to a blocklisted address must raise ValueError (AML check)."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        eve_addr,   eve_auth_key   = generate_addr_and_key()
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)

        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": eve_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx, {eve_addr})

    def test_duplicate_inputs_rejected(self):
        """Using the same UTXO twice in one transaction must raise ValueError."""
        validator, g_txid, alice_auth_key, _, bob_addr = self._setup()
        # Authorize the duplicate-input tx with the correct key — the validator must
        # still reject it regardless of whether authorization appears to pass.
        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key), (g_txid, 0, alice_auth_key)],
            [{"value": 200, "recipient": bob_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx, set())


# =============================================================================
# SECTION 8 — Validator: append_block
# =============================================================================

class TestValidatorAppendBlock:
    """
    Validator.append_block(authed_tx, blocklist=None) validates authed_tx,
    builds a new block with prev_hash pointing to the current chain tip, and
    appends it to validator.chain.

    After a successful append:
      - validator.chain grows by one block
      - the new block's prev_hash equals compute_block_hash(chain[-2])
      - inputs consumed by tx are no longer spendable
      - outputs created by tx are now spendable

    For invalid transactions the chain must remain unchanged.
    """

    def test_chain_grows_by_one_on_valid_tx(self):
        """A valid transaction must cause validator.chain to grow by exactly one block."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)

        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        validator.append_block(authed_tx)
        assert len(validator.chain) == 2

    def test_new_block_prev_hash_correct(self):
        """The appended block's prev_hash must equal the hash of the previous block."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)

        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        validator.append_block(authed_tx)
        assert validator.chain[1].prev_hash == compute_block_hash(genesis)

    def test_spent_input_no_longer_spendable_after_append(self):
        """After append_block, the consumed UTXO must not be spendable again."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)

        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        validator.append_block(authed_tx)

        # Try to spend the same coin again — must fail.
        authed_tx2 = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        with pytest.raises(ValueError):
            validator.validate_transaction(authed_tx2, set())

    def test_new_output_spendable_after_append(self):
        """After append_block, the newly created output must be spendable."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr,   bob_auth_key   = generate_addr_and_key()
        carol_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        g_txid  = compute_txid(genesis.transaction)

        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        validator.append_block(authed_tx)
        new_txid = compute_txid(authed_tx)

        # Bob's new output should be spendable.
        authed_tx2 = _make_authorized_tx(
            [(new_txid, 0, bob_auth_key)],
            [{"value": 100, "recipient": carol_addr}],
        )
        validator.validate_transaction(authed_tx2, set())  # must not raise

    def test_invalid_tx_does_not_mutate_chain(self):
        """If append_block raises, validator.chain must remain unchanged."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator   = Validator(genesis)
        original_len = len(validator.chain)

        fake_txid = "f" * 64
        authed_tx = _make_authorized_tx(
            [(fake_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": alice_addr}],
        )
        try:
            validator.append_block(authed_tx)
        except ValueError:
            pass

        assert len(validator.chain) == original_len

    def test_double_spend_rejected(self):
        """Spending the same UTXO in two separate blocks must fail on the second attempt."""
        alice_addr, alice_auth_key = generate_addr_and_key()
        bob_addr   = generate_addr_and_key()[0]
        carol_addr = generate_addr_and_key()[0]
        genesis  = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator    = Validator(genesis)
        g_txid   = compute_txid(genesis.transaction)

        authed_tx1 = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": bob_addr}],
        )
        validator.append_block(authed_tx1)  # valid

        authed_tx2 = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": carol_addr}],
        )
        with pytest.raises(ValueError):
            validator.append_block(authed_tx2)  # double-spend — must fail

    def test_aml_block_rejected(self):
        """
        append_block must also apply the AML check, not just validate_transaction:
        a block whose transaction pays a blocklisted address must raise ValueError.
        """
        alice_addr, alice_auth_key = generate_addr_and_key()
        eve_addr = generate_addr_and_key()[0]
        genesis = _make_genesis([{"value": 100, "recipient": alice_addr}])
        validator = Validator(genesis)
        g_txid = compute_txid(genesis.transaction)

        authed_tx = _make_authorized_tx(
            [(g_txid, 0, alice_auth_key)],
            [{"value": 100, "recipient": eve_addr}],
        )
        with pytest.raises(ValueError):
            validator.append_block(authed_tx, blocklist={eve_addr})


# =============================================================================
# SECTION 9 — Wallet: create_transaction
# =============================================================================

class TestWalletCreateTransaction:
    """
    Wallet.create_transaction(recipients, values) selects UTXOs owned by this
    wallet, builds a balanced transaction paying each recipient the specified
    value, adds change back to the wallet when needed, authorizes it using the
    wallet's own authkey, and returns the Transaction.

    Call scan_for_coins before create_transaction so the wallet has a UTXO set.
    """

    def _funded_wallet(self, value=100):
        """
        Return (wallet, chain, genesis_txid) where the wallet owns one UTXO
        worth `value` coins after scanning the chain.
        """
        addr, auth_key = generate_addr_and_key()
        genesis = _make_genesis([{"value": value, "recipient": addr}])
        chain = Blockchain([genesis])
        wallet = Wallet(auth_key, addr)
        wallet.scan_for_coins(chain)
        return wallet, chain, compute_txid(genesis.transaction)

    # ── Return type and structure ────────────────────────────────────────────

    def test_returns_transaction_instance(self):
        """create_transaction must return a Transaction."""
        wallet, _, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        result = wallet.create_transaction([recipient_addr], [100])
        assert isinstance(result, Transaction)

    def test_transaction_has_txinputs_and_txoutputs(self):
        """The returned Transaction must have txinputs and txoutputs attributes."""
        wallet, _, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([recipient_addr], [100])
        assert hasattr(tx, "txinputs")
        assert hasattr(tx, "txoutputs")

    # ── Single-recipient payment ─────────────────────────────────────────────

    def test_single_recipient_output_present(self):
        """The recipient must appear in the transaction outputs."""
        wallet, _, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([recipient_addr], [60])
        recipients_in_tx = [o.recipient for o in tx.txoutputs]
        assert recipient_addr in recipients_in_tx

    def test_single_recipient_correct_value(self):
        """The recipient's output value must match the requested amount."""
        wallet, _, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([recipient_addr], [60])
        recipient_output = next(
            o for o in tx.txoutputs if o.recipient == recipient_addr
        )
        assert recipient_output.value == 60

    # ── Multi-recipient payment ──────────────────────────────────────────────

    def test_multiple_recipients_all_present(self):
        """All requested recipients must appear in the transaction outputs."""
        wallet, _, _ = self._funded_wallet(100)
        bob_addr   = generate_addr_and_key()[0]
        carol_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([bob_addr, carol_addr], [30, 40])
        recipients_in_tx = [o.recipient for o in tx.txoutputs]
        assert bob_addr   in recipients_in_tx
        assert carol_addr in recipients_in_tx

    def test_multiple_recipients_correct_values(self):
        """Each recipient's output must carry the correct value."""
        wallet, _, _ = self._funded_wallet(100)
        bob_addr   = generate_addr_and_key()[0]
        carol_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([bob_addr, carol_addr], [30, 40])
        out_map = {o.recipient: o.value for o in tx.txoutputs}
        assert out_map[bob_addr]   == 30
        assert out_map[carol_addr] == 40

    # ── Change output ────────────────────────────────────────────────────────

    def test_change_output_returned_to_wallet(self):
        """When inputs exceed outputs, change must be paid back to the wallet."""
        wallet, _, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([recipient_addr], [60])
        change_outputs = [
            o for o in tx.txoutputs
            if o.recipient == wallet.get_address()
        ]
        assert len(change_outputs) == 1
        assert change_outputs[0].value == 40

    def test_no_change_output_when_exact_spend(self):
        """When inputs equal outputs exactly, no change output must be created."""
        wallet, _, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([recipient_addr], [100])
        change_outputs = [
            o for o in tx.txoutputs
            if o.recipient == wallet.get_address()
        ]
        assert change_outputs == []

    # ── Value conservation ───────────────────────────────────────────────────

    def test_value_is_conserved(self):
        """Sum of outputs must equal sum of inputs (no value created or destroyed)."""
        wallet, chain, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([recipient_addr], [60])

        # Sum inputs by looking up their values in the chain.
        genesis_tx = chain[0].transaction
        utxo_values = {
            (compute_txid(genesis_tx), i): o.value
            for i, o in enumerate(genesis_tx.txoutputs)
        }
        input_total = sum(
            utxo_values[(inp.prev_txid, inp.prev_out_idx)]
            for inp in tx.txinputs
        )
        output_total = sum(o.value for o in tx.txoutputs)
        assert input_total == output_total

    # ── Authorization ────────────────────────────────────────────────────────

    def test_transaction_is_authorized(self):
        """
        check_authorization must return True when called with the UTXO owners
        resolved from the wallet's own address.
        """
        wallet, _, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([recipient_addr], [100])
        # Every input was owned by this wallet, so all owners are this wallet's address.
        input_owners = [wallet.get_address()] * len(tx.txinputs)
        assert tx.check_authorization(input_owners) is True

    def test_validator_accepts_created_transaction(self):
        """
        A transaction built by create_transaction must be accepted by a validator
        that has the same UTXO set as the wallet's chain.
        """
        wallet, chain, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        tx = wallet.create_transaction([recipient_addr], [60])

        validator = Validator(chain[0])
        validator.validate_transaction(tx, set())  # must not raise

    # ── Insufficient funds ───────────────────────────────────────────────────

    def test_insufficient_funds_raises(self):
        """Requesting more than the wallet's balance must raise ValueError."""
        wallet, _, _ = self._funded_wallet(100)
        recipient_addr = generate_addr_and_key()[0]
        with pytest.raises(ValueError):
            wallet.create_transaction([recipient_addr], [101])
