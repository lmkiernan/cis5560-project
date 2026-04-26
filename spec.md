# CIS 5560 — Blockchain Project Specification

---

## 1. Preliminaries

This section gives you the conceptual background you need before diving into the project. None of it assumes prior experience with blockchains or cryptography.

---

### What is a Blockchain?

A **blockchain** is a data structure that stores a list of records in a way that makes tampering detectable. Think of it as a ledger — a running log of events — where each entry is cryptographically linked to the one before it.

Each record in the list is called a **block**. A block contains some data (in a cryptocurrency context, usually a transaction) and a **hash** of the previous block. A hash is a fixed-length fingerprint computed from a piece of data: the same input always produces the same fingerprint, but even a tiny change to the input produces a completely different one. By embedding the previous block's hash in the current block, every block is chained to every block before it. If someone tries to alter an old block, its hash changes — which breaks the link to the next block, and to every block after that. This makes the history tamper-evident without requiring a trusted central authority.

The very first block has no predecessor, so its "previous hash" is set to a unique value derived from a timestamp at the time the block is created. This block is called the **genesis block**.

In a real-world system like Bitcoin, many computers each maintain their own copy of the chain and must agree on which chain is the "true" one. This agreement mechanism is called a **consensus protocol**. Our project does not use one — there is a single authoritative chain and a single party maintaining it.

---

### What is a Coin?

In a blockchain-based currency, a **coin** (or more precisely, a coin output) is a record that says: *"some amount of value belongs to this address."* Coins are not physical objects or even stored as a balance somewhere. They are entries in the ledger that have been created (as an output of some past transaction) and not yet consumed (spent as an input to a later transaction).

The quantity of a coin is its **value** (represented by an integer in our system). A coin is always associated with a **recipient**, which is a key or public address that names who owns it.

---

### What is a Transaction?

A **transaction** is the mechanism by which coins move from one owner to another. It has two parts:

- **Inputs**, which are references to existing coins that the sender wants to spend. Each input names a specific coin output from a previous transaction.
- **Outputs**, which are new coin allocations created by this transaction, each specifying a value and a recipient.

For a transaction to be valid, the sender must *prove* they own the coins they are spending. This proof is called **authorization**. The validator checks this authorization before accepting the transaction.

A transaction that creates coins without consuming any inputs is called a **genesis transaction**. Every coin in the system is ultimately traceable back to one.

---

### What is a Validator?

In a blockchain system, a **validator** is responsible for:

1. Receiving proposed transactions from users.
2. **Validating** those transactions by (a) checking that the sender owns the coins they are trying to spend, that (b) no coins are created from thin air, and that (c) no rules are violated.
3. **Appending** valid transactions to the chain as new blocks.

In a real network with proof-of-work, many competing nodes race to add the next block and earn a reward. Our project does not use proof-of-work or any mining mechanism; instead, there is a single authoritative validator that validates and appends.

---

### What is a Wallet?

A **wallet** is the user-facing component of a blockchain system. Its core responsibilities are:

1. **Generating and storing key material**: an address that is meant to be shared, so that users can send coins to each other, and an authorization key that should be kept secret to allow proving ownership of coins.
2. **Scanning the blockchain** to find which outputs belong to you and which are still unspent.
3. **Building transactions** that spend your coins to pay others.

Because your authorization key is the only thing that lets you spend your coins, losing it means losing your coins forever. This is why wallet software must support saving the wallet to an encrypted file and loading it back in a new session.

---

### The UTXO Model

The **UTXO model** (Unspent Transaction Output model) is the bookkeeping approach used by Bitcoin and by our project. Rather than maintaining per-user balances, the ledger tracks individual coin outputs and whether each one has been spent.

Here is the intuition: when Alice sends 5 coins to Bob, the system does not subtract 5 from Alice's balance and add 5 to Bob's. Instead, it creates a *new output* that says "5 coins belong to Bob," and marks Alice's old output as consumed. Bob's "balance" is simply the sum of all outputs currently addressed to him that have not yet been spent.

A coin output that has not yet been consumed is called a **UTXO** (Unspent Transaction Output). The set of all UTXOs at any moment represents the total value in circulation. Every transaction:
- **Consumes** one or more existing UTXOs as inputs (proving ownership with an appropriate authorization mechanism).
- **Creates** one or more new UTXOs as outputs (assigning value to recipients).
- Must be **value-preserving**: the total value in equals the total value out.

The only exception is the **genesis transaction**, which is the very first transaction that creates coins from nothing. Every coin in the system is ultimately traceable back to a genesis output.

---

### Anti-Money Laundering (AML)

AML is the practice of preventing proceeds from illegal activity from circulating freely. In this system, a **blocklist** is a set of addresses associated with sanctioned entities.

The system enforces AML at two levels:

1. **Validator-side:** The validator refuses to include any transaction that pays an output to a blocklisted address. This stops new tainted funds from entering circulation.

2. **Wallet-side:** Even if tainted funds already exist on the chain, a wallet owner may want to know whether any of their own coins can be traced back to a blocklisted address. A coin is **tainted** if any output anywhere in its full ancestry (following transaction inputs recursively back to genesis) was ever paid to a blocklisted address.

---

### Setup

#### Install Python

This project requires Python 3.10 or later. If you do not have it:

- **macOS / Linux:** We recommend [pyenv](https://github.com/pyenv/pyenv) or downloading directly from [python.org](https://www.python.org/downloads/).
- **Windows:** Download the installer from [python.org](https://www.python.org/downloads/). Make sure "Add Python to PATH" is checked during installation.

Verify your installation:

```bash
python3 --version   # should print 3.10 or higher
```

#### Set up the project environment

From the project root directory:

```bash
# Create a virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate        # macOS / Linux
.venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

The only dependencies are `cryptography` and `pytest` (for testing).

#### Read the provided files

Before writing any code, read through these files:

| File | Purpose |
|------|---------|
| `crypto_utils.py` | Key generation, MACs, signatures, KDF, and symmetric and asymmetric encryption schemes |
| `chain_utils.py` | Block/transaction parsing and hashing helpers |
| `models.py` | Data model classes: `Block`, `Blockchain`, and domain types |
| `address.py` | Defines `address` and `authkey` types and `generate_addr_and_key()` |
| `transaction.py` | Your implementation stub for the `Transaction` class |
| `validator.py` | Your implementation stub for the `Validator` class |
| `wallet.py` | Your implementation stub for the `Wallet` class |
| `tests/test_micro.py` | The student-facing test suite |

---

> **Implementation order:** `address.py` must be the first file you implement. Every other file (`transaction.py`, `validator.py`, `wallet.py`) imports `address` and `authkey` from `address.py` at module scope, so those imports will fail until `address.py` is at least partially complete. Assign `address` and `authkey` before writing or running anything else.

---

## 2. Overview

### What You Are Building

In this project you will implement four interacting components of a simplified, local blockchain system in Python:

| Component | File | What you implement |
|-----------|------|--------------------|
| **Address types** | `address.py` | The `address` and `authkey` type bindings and keypair generation |
| **Transaction** | `transaction.py` | Transaction authorization and verification |
| **Validator** | `validator.py` | UTXO tracking, transaction validation, block appending |
| **Wallet** | `wallet.py` | Encrypted key storage, chain scanning, taint classification, transaction construction |

All four files are provided as stubs. Your task is to implement every method or assignment marked with a `TODO` comment or `raise NotImplementedError`. You are free to add helper methods, attributes, or internal data structures — the only requirement is that the public API (method names and signatures) stays exactly as specified.

You may import from `crypto_utils`, `chain_utils`, `models`, and the Python standard library. **Do not add third-party packages.**

The following files are provided and **must not be modified**:

| File | Purpose |
|------|---------|
| `crypto_utils.py` | Authentication schemes, encryption schemes, KDF, hashing, and supporting key/ciphertext classes |
| `chain_utils.py` | Block/transaction parsing and hashing helpers |
| `models.py` | Data model classes |

> **Note on genesis blocks:** The genesis block's `prev_hash` is **not** `null`/`None`. Instead, each genesis block receives a unique 64-character hex value derived from a timestamp at the time it is created. This ensures that two chains with identical transaction contents but different genesis blocks have completely different block hashes at every position, which is a prerequisite for correct chain-identity checking in `scan_for_coins`.

---

### System Architecture

The three components have distinct roles and interact through well-defined interfaces:

**`Transaction`** (`transaction.py`) is the authorization layer. Before any transaction can be submitted to the validator, it must be authorized by the owners of the coins being spent. `Transaction` wraps unauthorized transaction contents with whatever authorization data your implementation requires. The validator treats this as a black box: it asks `Transaction` whether the authorization is valid and acts on the boolean result.

**`Validator`** (`validator.py`) is the chain authority. It maintains the blockchain and the set of currently unspent outputs (the UTXO set). When a user submits a `Transaction`, the validator validates it against all applicable rules and, if valid, appends it to the chain as a new block.

**`Wallet`** (`wallet.py`) is the user-facing client. It generates and securely stores a keypair, scans the blockchain to discover which coins belong to it, classifies those coins by taint status, and constructs transactions to spend them.

**Data models** (`models.py`) define the shared data structures — `Block`, `Blockchain`, and supporting types — used throughout the system.

**Provided utilities** (`crypto_utils.py`, `chain_utils.py`) give you the low-level building blocks. You do not need to implement any cryptography yourself.

---

### Block and Chain Structure

Our chain follows the general blockchain structure described in §1: an ordered, append-only list of blocks, each linked to its predecessor by a hash. Two simplifications apply to this project:

- **One transaction per block.** Real blockchains batch many transactions into each block. Ours contains exactly one, which keeps the data model simple.
- **No consensus, no networking.** There is a single `Validator` instance that maintains the only copy of the chain. There are no competing validators and no proof-of-work puzzle to solve.

---

### Transactions and UTXOs

Our project uses the UTXO model described in §1. Concretely, a transaction contains:

- **txinputs** — references to previously created outputs, each identified by a `prev_txid` (the transaction ID of the prior transaction) and a `prev_out_idx` (the index of the specific output within that transaction).
- **txoutputs** — new coin allocations, each specifying a `value` (integer) and a `recipient` (an `address`).

`Transaction` (defined in `transaction.py`) stores `txinputs`, `txoutputs`, and whatever authorization data your scheme requires. `Transaction.to_dict()` is what gets written to disk and hashed — students override it to include their authorization data alongside the core fields. A transaction's **txid** is computed from `to_dict()` output, so it should always be computed after `authorize_tx()` has been called.

The `models.py` file defines:

```python
TxInput(prev_txid: TxID, prev_out_idx: OutIndex)
TxOutput(value: Value, recipient: address)
Block(prev_hash: BlockHash, transaction: Any)   # full Transaction stored in-memory
Blockchain(blocks: list[Block])
```

Each class provides `to_dict()` / `from_dict()` helpers for JSON serialization. `Block.to_dict()` calls `transaction.to_dict()`, and `Block.from_dict()` calls `Transaction.from_dict()` — students override both to include and restore authorization data. The `chain_utils` hashing functions (`compute_block_hash`, `compute_txid`) accept the typed objects directly. `Blockchain` supports Python indexing and slicing — `chain[i]` returns a `Block`, and `chain[i:]` returns a new `Blockchain` (not a plain list).

The domain wrapper types (`TxID`, `BlockHash`, `Value`, `OutIndex`) can be used anywhere their underlying primitive (`str` or `int`) is accepted. The `address` and `authkey` types are defined in `address.py` — see §4.1 for the full specification. Note that `TxOutput.recipient` is stored as plain `str` in the `models.py` implementation — this keeps `models.py` independent of student code in `address.py`. Because your `address` type will be a `str` subclass, equality comparisons such as `output.recipient == self.get_address()` work correctly across both.

A **transaction identifier** (`txid`) is the SHA-256 hash of the canonical JSON of the transaction's core fields (txinputs and txoutputs only), encoded as a 64-character lowercase hex string. `compute_txid(transaction)` from `chain_utils.py` computes this for you.

---

### Implementation Note

The test suite — both the public tests and the private grading tests — builds test chains by constructing a `Transaction` and calling `.authorize_tx(authkeys)` on it. If `Transaction` is not yet implemented, the `Validator` and `Wallet` tests will not run correctly regardless of how well those components are otherwise implemented. Keep this dependency in mind as you plan your work.

---

## 3. Threat Model

The grading suite includes adversarial tests. This section describes the adversaries you should defend against. **The threat model carries the security expectations for this project.** When you design each component, ask yourself whether an adversary with the capabilities described below could subvert your implementation.

---

### 3.1 Chain Adversary

The chain adversary interacts directly with the validator and the transaction layer. They are capable of submitting any number of transactions to the validator, and can intercept, modify, and reorder transactions or other chain-facing data as it passes through the system. This adversary is motivated by personal gain: they will use these capabilities in whatever way financially benefits or otherwise advantages them.

When designing your transaction authorization and validation logic, consider what an adversary with these capabilities could accomplish — and ensure that your implementation denies them that advantage.

---

### 3.2 Wallet Adversary

The wallet adversary's target is the wallet's saved state. They can obtain and read a saved wallet file from disk or storage, but they have no access to the wallet's in-memory state, and, in particular, cannot observe the wallet during an active session. Whatever they are able to extract from the saved file, they will use for personal gain.

The wallet adversary operates entirely outside the running system.
They cannot submit transactions, interact with the validator, or observe in-memory key material.
Their only foothold is the wallet file at rest.

When designing your wallet storage scheme, consider what an adversary who possesses a copy of the wallet file could do with it, and ensure that your design denies them meaningful advantage.

---

## 4. Function and File Responsibilities

This section describes what you are responsible for implementing in each file. It explains the **interface and correctness-level behavior** of each component. How you design the internals-—-data structures, authorization mechanisms, encryption formats-—-is up to you. The threat model in §3 carries the security expectations.

---

### 4.1 `address.py` — Address and Authorization Key Types

`address.py` is a short stub file where you bind the abstract `address` and `authkey` types to concrete key classes from `crypto_utils.py`, and implement one function.

`address` is the public identity of a wallet: it appears as `TxOutput.recipient`, in `Validator` blocklists, and wherever a coin's owner is identified on-chain. `authkey` is the corresponding secret credential: it is passed to `authorize_tx` and kept private by the wallet. **Your `transaction.py` must be consistent with the types you assign here.**

You must assign both types and implement:

```python
def generate_addr_and_key() -> tuple[address, authkey]:
```

This function must return a freshly generated `(address, authkey)` pair. `Wallet.create()` is pre-implemented in `wallet.py` and calls this function — so your type assignments here propagate automatically without any changes to `wallet.py`.

---

### 4.2 `transaction.py` — `Transaction`

`transaction.py` defines the `Transaction` class. Base implementations of `to_dict` and `from_dict` are provided that cover the core fields only. Your tasks are to implement the two authorization methods below, and to override `to_dict` and `from_dict` to include and restore your authorization data so it survives `save_chain` / `parse_chain` round-trips.

---

#### `Transaction.to_dict()` / `Transaction.from_dict(data)` *(override both)*

```python
def to_dict(self) -> dict:
    ...
@classmethod
def from_dict(cls, data: dict) -> "Transaction":
    ...
```

Base implementations are pre-provided. `to_dict` returns only `txinputs` and `txoutputs`; `from_dict` restores only those fields.

Override both to include and restore your authorization data. `Block.to_dict()` calls `transaction.to_dict()` when saving the chain, and `Block.from_dict()` calls `Transaction.from_dict()` when loading. If you do not override these, authorization data will not make it onto the chain.

Use `data.get("your_field", default)` in `from_dict` so that dicts without your auth field (e.g. genesis transactions) are handled gracefully.

Note: `compute_txid()` also calls `to_dict()`, so always call `authorize_tx()` before `compute_txid()`.

---

#### `Transaction.authorize_tx(authkeys)`

```python
def authorize_tx(self, authkeys: list[authkey]) -> None:
```

Given a list of authorization keys (one `authkey` per input, in input order), compute whatever authorization data your scheme requires and attach it to `self` in-place. After this call, `check_authorization` must return `True` when passed the matching list of addresses.

Callers first construct a `Transaction(txinputs=..., txoutputs=...)`, then call `.authorize_tx(authkeys)` on it before submitting to the validator.

You decide what authorization data to compute, how to compute it, and how to store it as attributes on `self`. The data must appear in `to_dict()` output.

---

#### `Transaction.check_authorization(input_addresses)` → `bool`

```python
def check_authorization(self, input_addresses: list[address]) -> bool:
```

Given a list of addresses (one per input, in input order), return `True` if `self`'s authorization data is valid for those owners and for `self`'s inputs and outputs. Return `False` for any failure-—-mismatched counts, invalid data, wrong keys---and **never raise an exception**.

The validator calls this method as a black box. It passes the `address` of each UTXO owner in input order and trusts the result. Whether the authorization check provides genuine security is entirely determined by your design.

`crypto_utils.py` provides several cryptographic primitives, including symmetric and asymmetric encryption, and MACs and signatures. You will likely need to use one of these to implement your authorization; read the docstrings in `crypto_utils.py` to understand what is available.

---

### 4.3 `validator.py` — `Validator`

The `Validator` class maintains the blockchain and the UTXO set. It validates and appends transactions.

```python
class Validator:
    chain: Blockchain   # Blocks from genesis (index 0) to tip
```

---

#### `Validator.__init__(genesis_block)`

```python
def __init__(self, genesis_block: Block) -> None:
```

Initialize the validator from a genesis block. After construction, `self.chain` must be a `Blockchain` containing exactly the genesis block, and the genesis transaction's outputs must be immediately available as spendable UTXOs.

You must choose a data structure to track unspent outputs. **Include a short comment in your code** explaining what you chose and why it is appropriate for the operations the validator needs to perform. Consider both the lookup and update paths, and think carefully about worst-case performance, as the grading suite includes efficiency tests.

---

#### `Validator.validate_transaction(authed_tx, blocklist)`

```python
def validate_transaction(self, authed_tx: Transaction, blocklist: set[address]) -> None:
```

Validate a `Transaction` against the current UTXO state. Raise `ValueError` (with a descriptive message) if any validation rule is violated; return `None` implicitly if the transaction is valid.

The validator enforces the following rules on every submitted transaction:

1. **No duplicate inputs**: the same output cannot be referenced more than once within a single transaction.
2. **All inputs exist**: every referenced `(prev_txid, prev_out_idx)` pair must be a currently unspent output.
3. **Value conservation**: the sum of output values must equal the sum of input values.
4. **AML compliance**: no output may pay to an address in `blocklist`.
5. **Transaction authorization**: the transaction must be authorized by the rightful owners of all inputs, verified by calling `authed_tx.check_authorization(input_owners)` where `input_owners` is the list of addresses of the UTXO owners in input order.

---

#### `Validator.append_block(authed_tx, blocklist=None)`

```python
def append_block(self, authed_tx: Transaction, blocklist: set[address] | None = None) -> None:
```

Validate the authorized transaction, then append it to `self.chain` as a new block. The new block's `prev_hash` must equal `compute_block_hash(self.chain[-1])`. The full `authed_tx` is stored in the block, and its authorization data is persisted via `to_dict()`, so `check_authorization` can be called on blocks retrieved from the chain in any session.

If `blocklist` is `None`, treat it as an empty set, which means that AML checks can be skipped.

If validation fails, raise `ValueError` and leave the chain and UTXO state entirely unchanged.

---

### 4.4 `wallet.py` — `Wallet`

The `Wallet` class stores key material (an `address` and `authkey`), scans the blockchain, and interacts with the validator on the user's behalf.

The `__init__(self, auth_key, addr)` constructor stores the wallet's key material. The stub also pre-implements `get_authkey()`, `get_address()`, and `create()` — do not modify those. Your task is to implement the remaining methods below.

**Wallet assumptions.** Your wallet may assume that any `Blockchain` it receives is internally valid. That is, it can assume that every block links correctly to its predecessor, every transaction is properly authorized, and UTXO references are consistent. You do not need to validate the chain.

**Chain continuity.** `scan_for_coins` may be called more than once as the chain grows. On each call after the first, the provided chain must be an extension of the chain previously processed. That is, the new chain must be the old chain with zero or more additional blocks appended at the end; the previously seen blocks must still be there, unchanged, at the beginning. If the provided chain is not an extension of the previously processed chain, raise `ValueError`. Raising on a non-extension protects the wallet from accidentally mixing state from incompatible chains.

**Calling convention.** `scan_for_coins` will always be called before `classify_coins_by_taint` or `create_transaction`. You may rely on this ordering.

**Efficiency.** The grading suite tests that repeated calls do not redo work unnecessarily. `scan_for_coins` must process only new blocks on subsequent calls, not rescan the entire chain from genesis. `classify_coins_by_taint` must carry forward taint state between calls and avoid re-examining coins whose status has not changed.

---

#### `Wallet.create()` *(class method — pre-implemented)*

```python
@classmethod
def create(cls) -> Wallet:
    addr, key = generate_addr_and_key()
    return cls(key, addr)
```

This method is already implemented in the stub. It delegates key generation to `generate_addr_and_key()` from `address.py`, so your type assignments there propagate here automatically. **Do not modify this method.**

---

#### `Wallet.save(passphrase)` → `dict`

```python
def save(self, passphrase: str) -> dict:
```

Encrypt the wallet's key material with the given passphrase and return a wallet-file dict. The dict must be JSON-serializable and contain whatever fields your encryption scheme needs to fully reconstruct the wallet's address and authorization key in a new session. The format is up to you; design it around the encryption scheme you choose.

`crypto_utils.py` provides two encryption schemes; read their docstrings to understand what each one offers and what security properties it provides. Each call to `save()` must produce a different result even when the passphrase is the same; your chosen scheme must use fresh randomness on every call.

---

#### `Wallet.load(wallet_file, passphrase)` *(class method)*

```python
@classmethod
def load(cls, wallet_file: dict, passphrase: str) -> Wallet:
```

Decrypt a wallet-file dict and return the reconstructed `Wallet`. Raise `ValueError` if the passphrase is incorrect or the file is malformed. 

---

#### `Wallet.scan_for_coins(chain)` → `list[dict]`

```python
def scan_for_coins(self, chain: Blockchain) -> list[dict]:
```

Scan the blockchain and return the list of UTXOs currently owned by this wallet. `chain` is a `Blockchain` with genesis at index 0. Each returned UTXO dict must contain at least:

```python
{"txid": str, "out_idx": int, "value": int, "recipient": address}
```

An output is owned by this wallet if `output.recipient == self.get_address()`. An output is unspent if no later transaction in the chain claims it as an input via `txinputs`.

**Repeated calls.** `scan_for_coins` may be called more than once as the chain grows. Each call must return the complete current UTXO set, and not just the newly discovered outputs. If the provided chain is empty, return an empty list. On the first non-empty call, scan from genesis. On subsequent calls, if the provided chain is not an extension of the previously processed chain, raise `ValueError`. Consider your design's efficiency when this method is called repeatedly on a growing chain.

---

#### `Wallet.classify_coins_by_taint(chain, blocklist)` → `dict`

```python
def classify_coins_by_taint(self, chain: Blockchain, blocklist: set[address]) -> dict:
```

Classify each UTXO owned by this wallet as tainted or untainted given the blocklist. Return:

```python
{"tainted": [<utxo>, ...], "untainted": [<utxo>, ...]}
```

A UTXO is **tainted** if any output anywhere in its ancestry (tracing transaction inputs back to genesis) was ever owned by a blocklisted address. This is the same definition given in §1 (Anti-Money Laundering).

Efficiency matters here. The grading suite tests that repeated calls with the same or changing blocklist avoid redundant traversal work. Think carefully about what taint state you can carry forward between calls.
Note that the blocklist only grows, and never shrinks. That is, entries are only added to the list, and are never removed.

---

#### `Wallet.create_transaction(recipients, values)` → `Transaction`

```python
def create_transaction(self, recipients: list[address], values: list[int]) -> Transaction:
```

Construct and authorize a transaction that pays each recipient the corresponding value, funded from this wallet's currently known UTXOs.

`scan_for_coins` will always be called *before* this method, so the wallet's UTXO set is up to date. If the wallet's available balance is insufficient to cover the total requested value, raise `ValueError`.
When selecting UTXOs to fund this transaction, any selection that covers the requested value is acceptable.
When inputs exceed the total payment, include a change output back to this wallet for the difference. Return a fully authorized `Transaction`.

---

## 5. Testing Structure

### Public Test Suite — `tests/test_micro.py`

`tests/test_micro.py` is the student-facing test suite. It covers the major correctness behaviors of all three components:

- **Transaction:** authorization round-trips, rejection of wrong keys, rejection of mismatched input counts.
- **Validator:** chain initialization, UTXO availability, validation rules, block appending, spent-output removal, atomicity on failure.
- **Wallet:** key generation, save/load round-trips, encrypted format requirements, coin detection, spent-output removal, repeated-call correctness on chain extensions, non-extension rejection, taint classification, transaction construction.

Run the tests with:

```bash
pytest tests/test_micro.py -v
```

### Private Grading Tests

Beyond `test_micro.py`, the Gradescope autograder runs a larger private test suite. The private tests check:

- **Security properties of your authorization scheme.** For example, whether your authorization actually binds the transaction contents, or whether an adversary could substitute inputs or outputs after authorization.
- **Efficiency.** Whether your UTXO lookup is fast enough to handle large UTXO sets, whether incremental scanning processes only new blocks, and whether taint classification avoids redundant traversal across repeated calls.
- **Additional correctness edge cases** beyond what `test_micro.py` covers.

**Passing all public and private tests is necessary but not sufficient for a full grade.** A correct-looking implementation that is insecure or inefficient will not receive full credit. Use the public tests as an integration and correctness baseline, and the private tests as a baseline for efficiency and security. Course staff will ultimately review your implementations when determining a final grade.

---

## 6. Deliverables and Dates

### Deliverable 1 — Design Document (due April 17)

Submit a design document, **typeset in LaTeX**, via Gradescope by **April 15**. Your document must address each of the following prompts.

#### Adversarial Threat Model

Identify at least two plausible attacks that the chain adversary might attempt in pursuit of personal gain, and at least two plausible attacks that the wallet adversary might attempt in pursuit of personal gain. Ground your analysis in the threat model described in §3: reason from what each adversary is capable of doing and explain how those capabilities could be exploited to their benefit.

#### Addresses

Explain how you represent addresses and authorization keys in your implementation. What concrete types did you choose, and why are they appropriate for the roles these values play in the system?


#### Transaction

1. Explain how transaction authorization works in your design. What data does your authorization cover, how is it produced, and how is it verified? What security guarantees is your scheme intended to provide?

2. Why is it important to include the authorization data on the chain (and therefore in the `to_dict` and `from_dict`)? What could a malicious validator hope to achive if they were omitted?

#### Validator

Explain your validation strategy for incoming transactions. How does your design address the threat posed by the chain adversary described in §3? Be specific about which adversarial capabilities your validation logic is designed to counter.

#### Wallet

Address the following aspects of your wallet design:

1. **Wallet storage.** Explain how wallet state is saved and loaded. How does your storage design protect against the wallet adversary described in §3?
2. **Scan-for-coins algorithm.** Describe your algorithm for scanning the blockchain to identify coins owned by this wallet. Analyze its efficiency, including the behavior of repeated calls on a growing chain.
3. **Taint-identification algorithm.** Describe your algorithm for classifying coins by taint. Analyze its efficiency, including how your implementation handles repeated calls with a changing blocklist.

We will provide feedback on the design document before the implementation deadline.

### Deliverable 2 — Implementation (due April 27)

Submit your completed `address.py`, `transaction.py`, `validator.py`, and `wallet.py` via Gradescope. An autograder will run the full test suite and report your score. You may resubmit as many times as you like before the deadline — use Gradescope to check your progress incrementally. As a reminder, passing all the gradescope tests is necessary but not sufficient for full points. The course staff will review your implementation directly during grading, examining security and efficiency properties.
