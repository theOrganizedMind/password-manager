"""Authenticated encryption helpers for the local password vault."""

import base64
from contextlib import contextmanager
import errno
import json
import math
import os
import tempfile
import time

if os.name == "nt":
    import msvcrt

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


FORMAT_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
AAD = b"password-manager-vault-v1"


class VaultCryptoError(ValueError):
    """Raised when a vault cannot be safely decrypted or validated."""


class VaultLockError(VaultCryptoError):
    """Raised when exclusive access to a vault transaction is unavailable."""


@contextmanager
def vault_transaction_lock(path, timeout=5.0):
    """Hold a Windows process lock around a complete vault read-modify-write.

    Every cooperating writer must use this context before loading the vault and
    leave it only after saving. The persistent ``<vault>.lock`` sidecar is never
    truncated or removed; locking the replaceable vault file would not work.
    """
    if os.name != "nt":
        raise VaultLockError("Vault transaction locking requires Windows.")
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 0:
        raise ValueError("timeout must be a finite non-negative number")

    # Resolve parent aliases while preserving the vault name across os.replace.
    # A symlink at the vault file would change that identity on replacement.
    try:
        absolute_path = os.path.abspath(os.fspath(path))
        parent = os.path.dirname(absolute_path)
        os.makedirs(parent, exist_ok=True)
        if os.path.islink(absolute_path):
            raise VaultLockError("Vault file aliases are not supported.")
        canonical_parent = os.path.realpath(parent, strict=True)
        canonical_path = os.path.normcase(
            os.path.join(canonical_parent, os.path.basename(absolute_path))
        )
        if os.path.islink(canonical_path):
            raise VaultLockError("Vault file aliases are not supported.")
        try:
            if os.stat(canonical_path).st_nlink != 1:
                raise VaultLockError("Hard-linked vault files are not supported.")
        except FileNotFoundError:
            pass
        lock_path = canonical_path + ".lock"
        if os.path.islink(lock_path):
            raise VaultLockError("Vault lock aliases are not supported.")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_BINARY, 0o600)
    except OSError as exc:
        raise VaultLockError("Unable to open the vault transaction lock.") from exc

    acquired = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                acquired = True
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN) and getattr(exc, "winerror", None) != 33:
                    raise VaultLockError("Unable to acquire the vault transaction lock.") from exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise VaultLockError("Timed out waiting for the vault transaction lock.") from exc
                time.sleep(min(0.05, remaining))
        yield
    finally:
        try:
            if acquired:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)


def _derive_key(master_password, salt):
    if not isinstance(master_password, str) or len(master_password) < 12:
        raise VaultCryptoError("Master password must contain at least 12 characters.")
    return Scrypt(
        salt=salt,
        length=KEY_BYTES,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(master_password.encode("utf-8"))


def encrypt_payload(payload, master_password):
    """Return a JSON-safe authenticated-encryption envelope."""
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(master_password, salt)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)
    return {
        "version": FORMAT_VERSION,
        "kdf": "scrypt",
        "kdf_n": SCRYPT_N,
        "kdf_r": SCRYPT_R,
        "kdf_p": SCRYPT_P,
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_payload(envelope, master_password):
    """Decrypt and validate a vault envelope, failing closed on any error."""
    try:
        if not isinstance(envelope, dict) or envelope.get("version") != FORMAT_VERSION:
            raise VaultCryptoError("Unsupported vault format.")
        if envelope.get("kdf") != "scrypt" or envelope.get("cipher") != "AES-256-GCM":
            raise VaultCryptoError("Unsupported vault cryptography.")
        if (
            envelope.get("kdf_n") != SCRYPT_N
            or envelope.get("kdf_r") != SCRYPT_R
            or envelope.get("kdf_p") != SCRYPT_P
        ):
            raise VaultCryptoError("Unsupported vault KDF parameters.")
        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES or len(ciphertext) < 16:
            raise VaultCryptoError("Invalid vault envelope.")
        key = _derive_key(master_password, salt)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, AAD)
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload, dict):
            raise VaultCryptoError("Vault payload must be an object.")
        return payload
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, InvalidTag) as exc:
        raise VaultCryptoError("Unable to unlock vault. Check the master password or file integrity.") from exc


def save_encrypted_file(path, payload, master_password, *, overwrite=True):
    """Write encrypted data; exports may use an atomic no-overwrite commit."""
    requested_parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(requested_parent, exist_ok=True)
    # Pin the staging directory when a backup path may traverse a mutable alias.
    parent = requested_parent if overwrite else os.path.realpath(requested_parent)
    envelope = encrypt_payload(payload, master_password)
    fd, temp_path = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(envelope, file, indent=2)
            file.flush()
            os.fsync(file.fileno())
        if overwrite:
            os.replace(temp_path, path)
        elif os.name == "nt":
            # Windows rename refuses an existing destination and moves the
            # staged file in one step, so a crash cannot leave a second hard
            # link to a newly restored live vault.
            os.rename(temp_path, path)
        else:
            # POSIX rename may replace an existing destination. Link creation
            # fails atomically if it already exists, even after an alias swap.
            os.link(temp_path, path)
            os.unlink(temp_path)
        # On platforms that support directory handles, also flush the rename.
        # Windows may reject opening a directory; the atomic replace remains the
        # safe fallback there and the exception is intentionally non-fatal.
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except (AttributeError, OSError):
            pass
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def load_encrypted_file(path, master_password):
    """Load and decrypt an encrypted vault file."""
    try:
        with open(path, "r", encoding="utf-8") as file:
            envelope = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VaultCryptoError("Unable to read the vault file. It may be damaged or incomplete.") from exc
    return decrypt_payload(envelope, master_password)
