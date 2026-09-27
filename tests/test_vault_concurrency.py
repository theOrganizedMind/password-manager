"""Synthetic Windows process checks for the vault transaction lock."""

import multiprocessing
import os
import queue
import time

import pytest

from vault_crypto import VaultLockError, vault_transaction_lock


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows CRT lock only")


def _hold_lock(path, entered, release):
    with vault_transaction_lock(path, timeout=2):
        entered.set()
        if not release.wait(10):
            raise AssertionError("Parent did not release the worker")


def _try_lock(path, timeout, result, ready=None):
    started = time.monotonic()
    if ready is not None:
        ready.set()
    try:
        with vault_transaction_lock(path, timeout=timeout):
            result.put(("acquired", time.monotonic() - started))
    except VaultLockError:
        result.put(("unavailable", time.monotonic() - started))


def _exit_while_locked(path, entered):
    with vault_transaction_lock(path, timeout=2):
        entered.set()
        os._exit(17)


def _finish(process, *, expected=0):
    process.join(12)
    if process.is_alive():
        process.terminate()
        process.join(5)
        pytest.fail("Lock worker did not finish")
    assert process.exitcode == expected


def test_processes_exclude_each_other_and_timeout(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    vault = tmp_path / "new" / "vault.vault"
    entered, release = ctx.Event(), ctx.Event()
    result = ctx.Queue()
    holder = ctx.Process(target=_hold_lock, args=(str(vault), entered, release))
    alias = vault.parent / ".." / "new" / "vault.vault"
    contender = ctx.Process(target=_try_lock, args=(str(alias), 0.4, result))
    try:
        holder.start()
        assert entered.wait(6)
        contender.start()
        status, elapsed = result.get(timeout=6)
        assert status == "unavailable"
        assert 0.3 <= elapsed < 1.5
        _finish(contender)
    finally:
        release.set()
        _finish(holder)

    successor = ctx.Process(target=_try_lock, args=(str(vault), 2, result))
    successor.start()
    assert result.get(timeout=6)[0] == "acquired"
    _finish(successor)
    assert (vault.parent / "vault.vault.lock").exists()


def test_waiting_process_acquires_only_after_release(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    vault = tmp_path / "vault.vault"
    entered, release = ctx.Event(), ctx.Event()
    ready = ctx.Event()
    result = ctx.Queue()
    holder = ctx.Process(target=_hold_lock, args=(str(vault), entered, release))
    contender = ctx.Process(target=_try_lock, args=(str(vault), 4, result, ready))
    try:
        holder.start()
        assert entered.wait(6)
        contender.start()
        assert ready.wait(6)
        with pytest.raises(queue.Empty):
            # A queued result here would mean two exclusive sections overlapped.
            result.get(timeout=0.3)
        release.set()
        assert result.get(timeout=6)[0] == "acquired"
        _finish(contender)
    finally:
        release.set()
        _finish(holder)


def test_crashed_owner_releases_lock_without_deleting_sidecar(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    vault = tmp_path / "vault.vault"
    entered = ctx.Event()
    worker = ctx.Process(target=_exit_while_locked, args=(str(vault), entered))
    worker.start()
    assert entered.wait(6)
    _finish(worker, expected=17)
    sidecar = tmp_path / "vault.vault.lock"
    assert sidecar.exists()
    with vault_transaction_lock(vault, timeout=2):
        pass
    assert sidecar.exists()


def test_alias_uses_same_sidecar_and_preserves_contents(tmp_path):
    directory = tmp_path / "vaults"
    directory.mkdir()
    vault = directory / "vault.vault"
    alias = directory / ".." / "vaults" / "vault.vault"
    sidecar = directory / "vault.vault.lock"
    sidecar.write_bytes(b"persistent")
    with vault_transaction_lock(alias, timeout=1):
        assert sidecar.exists()
    assert sidecar.read_bytes() == b"persistent"
    with vault_transaction_lock(vault, timeout=1):
        pass


def test_invalid_timeout_fails_without_sidecar(tmp_path):
    vault = tmp_path / "vault.vault"
    with pytest.raises(ValueError):
        with vault_transaction_lock(vault, timeout=-1):
            pass
    assert not (tmp_path / "vault.vault.lock").exists()


def test_hard_linked_vault_fails_closed(tmp_path):
    vault = tmp_path / "vault.vault"
    vault.write_bytes(b"synthetic only")
    try:
        os.link(vault, tmp_path / "alias.vault")
    except OSError as exc:
        pytest.skip(f"File system does not support hard links: {exc}")
    with pytest.raises(VaultLockError):
        with vault_transaction_lock(vault, timeout=0):
            pass
    assert not (tmp_path / "vault.vault.lock").exists()


def test_body_exception_releases_lock(tmp_path):
    vault = tmp_path / "vault.vault"
    with pytest.raises(RuntimeError):
        with vault_transaction_lock(vault, timeout=1):
            raise RuntimeError("synthetic failure")
    with vault_transaction_lock(vault, timeout=0):
        pass
    assert (tmp_path / "vault.vault.lock").exists()


def test_unavailable_sidecar_fails_closed(tmp_path):
    vault = tmp_path / "vault.vault"
    (tmp_path / "vault.vault.lock").mkdir()
    with pytest.raises(VaultLockError):
        with vault_transaction_lock(vault, timeout=0):
            pytest.fail("Entered without a lock")


def test_sidecar_symlink_fails_closed_when_supported(tmp_path):
    vault = tmp_path / "vault.vault"
    target = tmp_path / "other.lock"
    target.write_bytes(b"synthetic only")
    try:
        os.symlink(target, tmp_path / "vault.vault.lock")
    except OSError as exc:
        pytest.skip(f"File system does not allow symlinks: {exc}")
    with pytest.raises(VaultLockError):
        with vault_transaction_lock(vault, timeout=0):
            pytest.fail("Entered through a sidecar alias")
