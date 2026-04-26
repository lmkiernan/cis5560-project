"""
crypto_utils.py — Cryptographic primitives for the CIS 5560 blockchain project.

DO NOT MODIFY THIS FILE.

Provides:
  - Two cryptographic algorithm families: a signature scheme (SignScheme) and a
    MAC-like scheme (MacScheme), each with keygen / sign-or-tag / verify.
  - Distinct key classes for each scheme: SignPublicKey, SignPrivateKey,
    and a single MacKey (MAC is symmetric — one key for both tagging and verification).
  - Two authenticated-encryption scheme classes for wallet key storage:
      SymEncScheme  — passphrase-derived AES-256-GCM (secret-key encryption)
      PubEncScheme  — passphrase-derived ECIES on secp256k1 (public-key encryption)
    Each scheme exposes keygen(passphrase) / enc / dec and dedicated key/ciphertext
    classes (SymKey, SymCiphertext, PubEncPublicKey, PubEncPrivateKey, PubEncCiphertext).
  - SHA-256 hashing, scrypt key derivation, and raw AES-256-GCM helpers.

Pedagogical note
----------------
SignScheme and MacScheme both expose a parallel keygen / sign-or-tag / verify
interface.  SymEncScheme and PubEncScheme both expose a parallel keygen / enc /
dec interface backed by passphrase-based key derivation.  Read the individual
class docstrings to understand the semantics of each.
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Key classes — Signature scheme
# ---------------------------------------------------------------------------

class Signature(str):
    """
    A DER-encoded ECDSA signature, hex-encoded.

    DER encoding of a secp256k1 ECDSA signature is variable-length: the r and
    s integers are each 32 bytes but may be padded to 33 bytes to preserve the
    sign bit, so the total ranges from 70 to 72 bytes (140–144 hex chars).
    No fixed-length check is enforced here because the length is determined by
    the signing library and is not under the caller's control.
    """


class SignPublicKey(str):
    """
    Signature public key for the ECDSA signature scheme.
    Internally it is hex-encoded as 66 hex chars or 33 bytes.
    """

    def __new__(cls, value: str) -> "SignPublicKey":
        if len(value) != 66:
            raise ValueError(
                f"SignPublicKey must be 66 hex characters (33 bytes); got {len(value)}"
            )
        return super().__new__(cls, value)


class SignPrivateKey(str):
    """
    Signature secret key for the ECDSA signature scheme.
    Internally it is hex-encoded as 64 hex chars or 32 bytes.
    """

    def __new__(cls, value: str) -> "SignPrivateKey":
        if len(value) != 64:
            raise ValueError(
                f"SignPrivateKey must be 64 hex characters (32 bytes); got {len(value)}"
            )
        return super().__new__(cls, value)


# ---------------------------------------------------------------------------
# Key classes — MAC scheme
# ---------------------------------------------------------------------------

class MacTag(str):
    """
    An HMAC-SHA256 authentication tag.
    Internally it is hex-encoded as 64 hex chars or 32 bytes.
    """

    def __new__(cls, value: str) -> "MacTag":
        if len(value) != 64:
            raise ValueError(
                f"MacTag must be 64 hex characters (32 bytes); got {len(value)}"
            )
        return super().__new__(cls, value)


class MacKey(str):
    """
    HMAC-SHA256 secret key.
    Internally it is hex-encoded as 64 hex chars or 32 bytes.
    """

    def __new__(cls, value: str) -> "MacKey":
        if len(value) != 64:
            raise ValueError(
                f"MacKey must be 64 hex characters (32 bytes); got {len(value)}"
            )
        return super().__new__(cls, value)


# ---------------------------------------------------------------------------
# Signature scheme (secp256k1 ECDSA + SHA-256)
# ---------------------------------------------------------------------------

class SignScheme:
    """
    A digital signature scheme built on secp256k1 ECDSA.

    Interface
    ---------
    keygen()             -> (SignPublicKey, SignPrivateKey)
    sign(sk, msg)        -> Signature
    verify(pk, msg, sig) -> bool
    """

    @staticmethod
    def keygen() -> tuple[SignPublicKey, SignPrivateKey]:
        """
        Generate a fresh ECDSA keypair.

        Returns:
            (pk, sk) where:
              pk — SignPublicKey 
              sk — SignPrivateKey
        """
        private_key = ec.generate_private_key(ec.SECP256K1())
        sk_int = private_key.private_numbers().private_value
        sk_hex = sk_int.to_bytes(32, "big").hex()
        pk_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )
        pk_hex = pk_bytes.hex()
        return SignPublicKey(pk_hex), SignPrivateKey(sk_hex)

    @staticmethod
    def sign(sk: SignPrivateKey, message_bytes: bytes) -> str:
        """
        Sign message_bytes with the given secret key.

        Internally hashes message_bytes with SHA-256 before signing.

        Args:
            sk:            SignPrivateKey
            message_bytes: Arbitrary bytes to sign.

        Returns:
            ``Signature`` (hex string).
        """
        sk_int = int(sk, 16)
        private_key = ec.derive_private_key(sk_int, ec.SECP256K1())
        signature = private_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
        return Signature(signature.hex())

    @staticmethod
    def verify(pk: SignPublicKey, message_bytes: bytes, signature_hex: str) -> bool:
        """
        Verify a DER-encoded ECDSA signature.

        Args:
            pk:            SignPublicKey
            message_bytes: The original message bytes that were signed.
            signature_hex: ECDSA signature as a hex string.

        Returns:
            True if the signature is valid, False otherwise.
            Never raises on malformed or invalid input.
        """
        try:
            pub_bytes = bytes.fromhex(pk)
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_bytes)
            sig_bytes = bytes.fromhex(signature_hex)
            public_key.verify(sig_bytes, message_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# MAC scheme (HMAC-SHA256, symmetric shared key)
# ---------------------------------------------------------------------------

class MacScheme:
    """
    A MAC authentication scheme built on HMAC-SHA256.

    Interface
    ---------
    keygen()              -> MacKey
    tag(key, msg)         -> MacTag
    verify(key, msg, tag) -> bool
    """

    @staticmethod
    def keygen() -> MacKey:
        """
        Generate a fresh random HMAC-SHA256 key.

        Returns:
            MacKey
        """
        return MacKey(os.urandom(32).hex())

    @staticmethod
    def tag(key: MacKey, message_bytes: bytes) -> MacTag:
        """
        Compute an HMAC-SHA256 authentication tag over message_bytes.

        Args:
            key:           MacKey
            message_bytes: Arbitrary bytes to authenticate.

        Returns:
            MacTag
        """
        return MacTag(hmac.new(bytes.fromhex(key), message_bytes, hashlib.sha256).hexdigest())

    @staticmethod
    def verify(key: MacKey, message_bytes: bytes, tag_hex: str) -> bool:
        """
        Verify an HMAC-SHA256 tag.

        Args:
            key:           MacKey
            message_bytes: The original message bytes that were tagged.
            tag_hex:       Hex-encoded HMAC-SHA256 tag to verify.

        Returns:
            True if the tag is valid, False otherwise.
            Never raises on malformed or invalid input.
        """
        try:
            expected = hmac.new(bytes.fromhex(key), message_bytes, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, tag_hex)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Key classes — Symmetric encryption scheme
# ---------------------------------------------------------------------------

class SymKey(str):
    """
    AES-256-GCM secret key derived from a passphrase via scrypt.

    Hex-encoded 32-byte derived key (64 hex characters).

    Properties
    ----------
    key_bytes — 32-byte derived AES key
    """

    def __new__(cls, value: str) -> "SymKey":
        if len(value) != 64:
            raise ValueError(
                f"SymKey must be 64 hex characters (32-byte key); got {len(value)}"
            )
        return super().__new__(cls, value)

    @property
    def key_bytes(self) -> bytes:
        """32-byte derived AES key."""
        return bytes.fromhex(self)


class SymCiphertext(str):
    """
    AES-256-GCM ciphertext produced by ``SymEncScheme.enc()``.

    Hex-encoded: 12-byte random nonce (24 hex chars) followed by the
    variable-length AES-GCM ciphertext with its 16-byte authentication tag
    appended.
    Minimum total length: 24 + 32 = 56 hex chars.

    Properties
    ----------
    nonce_hex      — 24 hex chars (12-byte AES-GCM nonce)
    ciphertext_hex — remaining hex chars (ciphertext with GCM tag appended)
    """

    def __new__(cls, value: str) -> "SymCiphertext":
        if len(value) < 56:
            raise ValueError(
                f"SymCiphertext must be at least 56 hex chars (nonce + GCM tag); got {len(value)}"
            )
        return super().__new__(cls, value)

    @property
    def nonce_hex(self) -> str:
        """12-byte AES-GCM nonce, hex-encoded (24 hex chars)."""
        return self[:24]

    @property
    def ciphertext_hex(self) -> str:
        """AES-GCM ciphertext with 16-byte tag appended, hex-encoded."""
        return self[24:]


# ---------------------------------------------------------------------------
# Key classes — Public-key encryption scheme
# ---------------------------------------------------------------------------

class PubEncPublicKey(str):
    """
    Public key for ECIES encryption.
    Internally represented as 66 hex chars / 33 bytes.

    Used as the *encryption* key: anyone holding this key can encrypt a message;
    only the holder of the corresponding ``PubEncPrivateKey`` can decrypt it.
    """

    def __new__(cls, value: str) -> "PubEncPublicKey":
        if len(value) != 66:
            raise ValueError(
                f"PubEncPublicKey must be 66 hex characters (33 bytes); got {len(value)}"
            )
        return super().__new__(cls, value)


class PubEncPrivateKey(str):
    """
    Private key for ECIES encryption.
    Internally represented as 64 hex chars / 32 bytes.

    Used as the *decryption* key: the holder can decrypt any ``PubEncCiphertext``
    produced by ``PubEncScheme.enc()`` with the corresponding ``PubEncPublicKey``.
    """

    def __new__(cls, value: str) -> "PubEncPrivateKey":
        if len(value) != 64:
            raise ValueError(
                f"PubEncPrivateKey must be 64 hex characters (32 bytes); got {len(value)}"
            )
        return super().__new__(cls, value)


class PubEncCiphertext(str):
    """
    ECIES ciphertext produced by ``PubEncScheme.enc()``.

    Hex-encoded concatenation:
      - 33-byte ephemeral secp256k1 public key (compressed)  — 66 hex chars  (fixed)
      - 12-byte AES-GCM nonce                                — 24 hex chars  (fixed)
      - variable-length AES-GCM ciphertext with 16-byte tag  — ≥ 32 hex chars

    Minimum total length: 66 + 24 + 32 = 122 hex chars.

    Properties
    ----------
    ephem_pk_hex — 66 hex chars (ephemeral EC public key used during encryption)
    nonce_hex    — 24 hex chars (AES-GCM nonce)
    body_hex     — remaining hex chars (ciphertext with GCM tag appended)
    """

    def __new__(cls, value: str) -> "PubEncCiphertext":
        if len(value) < 122:
            raise ValueError(
                f"PubEncCiphertext must be at least 122 hex chars; got {len(value)}"
            )
        return super().__new__(cls, value)

    @property
    def ephem_pk_hex(self) -> str:
        """33-byte ephemeral public key, hex-encoded (66 hex chars)."""
        return self[:66]

    @property
    def nonce_hex(self) -> str:
        """12-byte AES-GCM nonce, hex-encoded (24 hex chars)."""
        return self[66:90]

    @property
    def body_hex(self) -> str:
        """AES-GCM ciphertext with 16-byte tag appended, hex-encoded."""
        return self[90:]


# ---------------------------------------------------------------------------
# Fixed domain-separation salt for symmetric key derivation from a passphrase.
# A constant salt is intentional: the passphrase is the sole entropy source, and
# scrypt's cost parameters make brute-force expensive.
# Value: ASCII "cis5560-symkey-v" (16 bytes).
_SYMENC_KDF_SALT = "636973353536302d73796d6b65792d76"

# Symmetric encryption scheme (AES-256-GCM with scrypt KDF)
# ---------------------------------------------------------------------------

class SymEncScheme:
    """
    A passphrase-based symmetric authenticated-encryption scheme.

    Uses scrypt with a fixed domain-separation salt to derive a 32-byte AES
    key from the passphrase, then encrypts with AES-256-GCM.  The same
    passphrase always produces the same key (like PubEncScheme); randomness
    per encryption comes from the fresh nonce generated in enc().

    Interface
    ---------
    keygen(passphrase)   -> SymKey
    enc(key, plaintext)  -> SymCiphertext
    dec(key, ciphertext) -> bytes
    """

    @staticmethod
    def keygen(passphrase: str) -> "SymKey":
        """
        Derive a ``SymKey`` from *passphrase* using scrypt.

        Uses a fixed domain-separation salt so the same passphrase always
        produces the same key.  Randomness per save comes from the fresh
        nonce generated in enc().

        Args:
            passphrase: The user's passphrase (unicode string).

        Returns:
            SymKey — 64 hex chars (32-byte derived AES key).
        """
        derived = kdf(passphrase, _SYMENC_KDF_SALT)
        return SymKey(derived.hex())

    @staticmethod
    def enc(key: "SymKey", plaintext: bytes) -> "SymCiphertext":
        """
        Encrypt *plaintext* with AES-256-GCM using a freshly generated nonce.

        Args:
            key:       SymKey produced by ``keygen()``.
            plaintext: Bytes to encrypt.

        Returns:
            SymCiphertext — 12-byte nonce (24 hex chars) followed by the
            AES-GCM ciphertext with 16-byte authentication tag appended.
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(key.key_bytes)
        ciphertext_body = aesgcm.encrypt(nonce, plaintext, None)
        return SymCiphertext(nonce.hex() + ciphertext_body.hex())

    @staticmethod
    def dec(key: "SymKey", ciphertext: "SymCiphertext") -> bytes:
        """
        Decrypt a ``SymCiphertext``.

        Args:
            key:        SymKey produced by ``keygen()``.
            ciphertext: SymCiphertext produced by ``enc()``.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If the authentication tag check fails (wrong key or
                        corrupted ciphertext).
        """
        try:
            nonce = bytes.fromhex(ciphertext.nonce_hex)
            ciphertext_body = bytes.fromhex(ciphertext.ciphertext_hex)
            aesgcm = AESGCM(key.key_bytes)
            return aesgcm.decrypt(nonce, ciphertext_body, None)
        except Exception as exc:
            raise ValueError("Decryption failed: wrong passphrase or corrupted data") from exc


# ---------------------------------------------------------------------------
# Public-key encryption scheme (ECIES: secp256k1 ECDH + AES-256-GCM)
# ---------------------------------------------------------------------------

# Fixed domain-separation salt used when deriving the EC keypair from a passphrase.
# A constant salt is intentional: the passphrase is the sole entropy source, and
# scrypt's cost parameters make brute-force expensive.
# Value: ASCII "cis5560-pubkey-v" (16 bytes).
_PUBENC_KDF_SALT = "636973353536302d7075626b65792d76"


class PubEncScheme:
    """
    A passphrase-based public-key authenticated-encryption scheme using ECIES.

    ``keygen(passphrase)`` derives a ECIES keypair *deterministically* from
    the passphrase (via scrypt with a fixed domain-separation salt), so the same
    passphrase always reproduces the same keypair without storing any extra state.

    Interface
    ---------
    keygen(passphrase)   -> (PubEncPublicKey, PubEncPrivateKey)
    enc(pk, plaintext)   -> PubEncCiphertext
    dec(sk, ciphertext)  -> bytes
    """

    @staticmethod
    def keygen(passphrase: str) -> tuple["PubEncPublicKey", "PubEncPrivateKey"]:
        """
        Derive a secp256k1 keypair deterministically from *passphrase*.

        Uses scrypt with a fixed domain-separation salt so that the same
        passphrase always reproduces the same keypair — enabling decryption
        in a future session without storing any additional state.

        Args:
            passphrase: The user's passphrase (unicode string).

        Returns:
            (pk, sk) where:
              pk — PubEncPublicKey (66 hex chars, 33-byte compressed SEC point)
              sk — PubEncPrivateKey (64 hex chars, 32-byte private scalar)
        """
        seed = kdf(passphrase, _PUBENC_KDF_SALT)
        sk_int = int.from_bytes(seed, "big")
        private_key = ec.derive_private_key(sk_int, ec.SECP256K1())
        pk_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )
        return PubEncPublicKey(pk_bytes.hex()), PubEncPrivateKey(seed.hex())

    @staticmethod
    def enc(pk: "PubEncPublicKey", plaintext: bytes) -> "PubEncCiphertext":
        """
        Encrypt *plaintext* for the holder of *pk* using ECIES.

        Generates a fresh ephemeral secp256k1 keypair, performs ECDH with *pk*
        to derive a shared secret, hashes the secret with SHA-256 to obtain a
        32-byte AES key, then encrypts with AES-256-GCM.

        Args:
            pk:        PubEncPublicKey (66 hex chars).
            plaintext: Bytes to encrypt.

        Returns:
            PubEncCiphertext — ephemeral pk (66 hex) || nonce (24 hex) ||
            AES-GCM ciphertext with 16-byte tag appended.
        """
        pk_bytes = bytes.fromhex(pk)
        recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk_bytes)

        ephemeral_sk = ec.generate_private_key(ec.SECP256K1())
        shared_secret = ephemeral_sk.exchange(ec.ECDH(), recipient_pub)
        aes_key = sha256(shared_secret)

        nonce = os.urandom(12)
        ciphertext_body = AESGCM(aes_key).encrypt(nonce, plaintext, None)

        ephem_pk_bytes = ephemeral_sk.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )
        return PubEncCiphertext(ephem_pk_bytes.hex() + nonce.hex() + ciphertext_body.hex())

    @staticmethod
    def dec(sk: "PubEncPrivateKey", ciphertext: "PubEncCiphertext") -> bytes:
        """
        Decrypt a ``PubEncCiphertext`` using the recipient's private key.

        Args:
            sk:         PubEncPrivateKey (64 hex chars).
            ciphertext: PubEncCiphertext produced by ``enc()``.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ValueError: If the authentication tag check fails (wrong key or
                        corrupted ciphertext).
        """
        try:
            ephem_pk_bytes = bytes.fromhex(ciphertext.ephem_pk_hex)
            ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), ephem_pk_bytes
            )
            private_key = ec.derive_private_key(int(sk, 16), ec.SECP256K1())
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pub)
            aes_key = sha256(shared_secret)

            nonce = bytes.fromhex(ciphertext.nonce_hex)
            ciphertext_body = bytes.fromhex(ciphertext.body_hex)
            return AESGCM(aes_key).decrypt(nonce, ciphertext_body, None)
        except Exception as exc:
            raise ValueError("Decryption failed: wrong passphrase or corrupted data") from exc


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def derive_public_key(secret_key_hex: str) -> str:
    """
    Derive a compressed public key from a private key.

    Args:
        secret_key_hex: 64-character hex string (32-byte private scalar).

    Returns:
        66-character hex string (33-byte compressed SEC public key).
    """
    sk_int = int(secret_key_hex, 16)
    private_key = ec.derive_private_key(sk_int, ec.SECP256K1())
    pk_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    return pk_bytes.hex()


def sha256(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of data."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of data."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Key derivation (scrypt)
# ---------------------------------------------------------------------------

# Fixed scrypt parameters — do not change; these define the wallet file format.
# Use these constants when building the "kdf_params" field in your wallet file dict.
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def kdf(passphrase: str, salt_hex: str) -> bytes:
    """
    Derive a 32-byte AES key from a passphrase using scrypt.

    Parameters are fixed at n=16384, r=8, p=1 (matching the wallet file format).

    Args:
        passphrase: The user's passphrase (unicode string).
        salt_hex:   Hex-encoded 16-byte random salt.

    Returns:
        32-byte derived key suitable for AES-256-GCM.
    """
    salt = bytes.fromhex(salt_hex)
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )


# ---------------------------------------------------------------------------
# Authenticated encryption (AES-256-GCM)
# ---------------------------------------------------------------------------

def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[str, str]:
    """
    Encrypt plaintext using AES-256-GCM with a freshly generated random nonce.

    Args:
        key:       32-byte AES key (e.g., from kdf()).
        plaintext: Bytes to encrypt.

    Returns:
        (nonce_hex, ciphertext_hex) where ciphertext already includes the
        16-byte GCM authentication tag appended at the end.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce.hex(), ciphertext.hex()


def aes_decrypt(key: bytes, nonce_hex: str, ciphertext_hex: str) -> bytes:
    """
    Decrypt an AES-256-GCM ciphertext (with appended authentication tag).

    Args:
        key:            32-byte AES key.
        nonce_hex:      Hex-encoded 12-byte nonce used during encryption.
        ciphertext_hex: Hex-encoded ciphertext with 16-byte GCM tag appended.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If the authentication tag check fails (wrong key, wrong
                    nonce, or corrupted ciphertext).
    """
    try:
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("Decryption failed: wrong passphrase or corrupted wallet file") from exc
