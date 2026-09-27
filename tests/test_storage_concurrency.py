"""Synthetic conflict and transaction checks for the single-owner vault."""

import threading
from contextlib import contextmanager
from datetime import datetime

import pytest

import password_manager as pm
from vault_crypto import load_encrypted_file, save_encrypted_file


MASTER = "synthetic-master-password-123"


def _record(name, password="synthetic-password"):
    return {
        "employee_name": "Synthetic Owner",
        "account_name": name,
        "username": name.lower(),
        "account_password": password,
        "notes": "",
    }


def test_two_instances_keep_both_adds(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    first = pm.StorageManager(MASTER)
    second = pm.StorageManager(MASTER)
    first_loaded = threading.Event()
    release_first = threading.Event()
    second_loaded = threading.Event()
    errors = []

    first_load = first._load_json
    second_load = second._load_json

    def pause_first_after_load():
        data = first_load()
        first_loaded.set()
        if not release_first.wait(10):
            raise AssertionError("Timed out waiting to release the first writer")
        return data

    def observe_second_load():
        data = second_load()
        second_loaded.set()
        return data

    monkeypatch.setattr(first, "_load_json", pause_first_after_load)
    monkeypatch.setattr(second, "_load_json", observe_second_load)

    def add(manager, name):
        try:
            manager.add_record("password_book", _record(name))
        except Exception as exc:
            errors.append(exc)

    a = threading.Thread(target=add, args=(first, "Alpha"))
    b = threading.Thread(target=add, args=(second, "Beta"))
    try:
        a.start()
        assert first_loaded.wait(10)
        b.start()
        assert not second_loaded.wait(0.4), "Second writer loaded during first transaction"
    finally:
        release_first.set()
        a.join(10)
        b.join(10)

    assert not a.is_alive() and not b.is_alive()
    assert errors == []
    rows = pm.StorageManager(MASTER).fetch_records("password_book")
    assert {row["account_name"] for row in rows} == {"Alpha", "Beta"}
    assert len({row["password_id"] for row in rows}) == 2


def test_stale_update_and_delete_fail_without_changing_current_record(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    first = pm.StorageManager(MASTER)
    second = pm.StorageManager(MASTER)
    first.add_record("password_book", _record("Account"))
    original = first.fetch_records("password_book")[0]
    record_id = original["password_id"]

    changed = _record("Account", "synthetic-updated-password")
    second.update_record("password_book", record_id, changed, expected_record=original)

    with pytest.raises(pm.RecordConflictError):
        first.update_record("password_book", record_id, _record("Account", "stale-value"), expected_record=original)
    with pytest.raises(pm.RecordConflictError):
        first.delete_record("password_book", record_id, expected_record=original)

    current = first.fetch_record("password_book", record_id)
    assert current["account_password"] == "synthetic-updated-password"


def test_mutations_require_an_explicit_selection_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account"))
    original = manager.fetch_records("password_book")[0]
    record_id = original["password_id"]

    with pytest.raises(TypeError, match="expected_record"):
        manager.update_record("password_book", record_id, _record("Account", "new"))
    with pytest.raises(TypeError, match="expected_record"):
        manager.delete_record("password_book", record_id)
    with pytest.raises(pm.RecordConflictError):
        manager.update_record("password_book", record_id, _record("Account", "new"), expected_record=None)
    assert manager.fetch_record("password_book", record_id) == original


def test_disappearing_vault_is_not_reseeded(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account"))
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.unlink()

    with pytest.raises(pm.VaultCryptoError):
        manager.fetch_records("password_book")
    assert not vault.exists()


def test_missing_vault_after_restart_is_not_reseeded(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account"))
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.rename(tmp_path / "synthetic-recoverable-vault.vault")

    with pytest.raises(pm.VaultCryptoError, match="missing|Missing"):
        pm.StorageManager(MASTER)
    assert not vault.exists()


def test_stale_selection_rejected_after_aba_even_in_same_timestamp_second(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    first = pm.StorageManager(MASTER)
    second = pm.StorageManager(MASTER)
    first.add_record("password_book", _record("Account", "A"))
    original = first.fetch_records("password_book")[0]
    record_id = original["password_id"]

    fixed_time = datetime.fromisoformat(original["updated_at"])

    class SameSecond(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed_time

    monkeypatch.setattr(pm, "datetime", SameSecond)

    second.update_record("password_book", record_id, _record("Account", "B"), expected_record=original)
    changed = second.fetch_record("password_book", record_id)
    second.update_record("password_book", record_id, _record("Account", "A"), expected_record=changed)
    current = second.fetch_record("password_book", record_id)
    assert current["account_password"] == original["account_password"]

    with pytest.raises(pm.RecordConflictError):
        first.delete_record("password_book", record_id, expected_record=original)
    with pytest.raises(pm.RecordConflictError):
        first.update_record("password_book", record_id, _record("Account", "C"), expected_record=original)
    assert first.fetch_record("password_book", record_id) == current


def test_existing_vault_without_revisions_migrates_on_unlock(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account"))
    vault = tmp_path / "json_files" / "password_data.vault"
    old_payload = load_encrypted_file(str(vault), MASTER)
    old_payload["password_book"][0].pop("_revision")
    save_encrypted_file(str(vault), old_payload, MASTER)

    reopened = pm.StorageManager(MASTER)
    record = reopened.fetch_records("password_book")[0]
    assert record["_revision"] == 1
    reopened.update_record("password_book", record["password_id"], _record("Account", "changed"), expected_record=record)
    assert reopened.fetch_record("password_book", record["password_id"])["_revision"] == 2


def test_synthetic_missing_vault_recovery_from_full_backup(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account", " synthetic-recovery-value "))
    backup = tmp_path / "separate-full-backup.vault"
    manager.export_all_records_to_file(str(backup))
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.rename(tmp_path / "synthetic-vault-quarantine.vault")

    with pytest.raises(pm.VaultCryptoError, match="missing"):
        pm.StorageManager(MASTER)
    assert not vault.exists()
    pm.StorageManager.restore_missing_vault_from_full_backup(str(backup), MASTER)
    reopened = pm.StorageManager(MASTER)
    assert reopened.fetch_records("password_book")[0]["account_password"] == " synthetic-recovery-value "
    assert (tmp_path / ".password-vault-initialized").exists()


def test_missing_vault_restore_rejects_partial_backup_without_creating_empty_vault(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account"))
    backup = tmp_path / "partial.vault"
    manager.export_records_to_file("password_book", str(backup))
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.rename(tmp_path / "synthetic-vault-quarantine.vault")

    with pytest.raises(pm.VaultCryptoError, match="full backup"):
        pm.StorageManager.restore_missing_vault_from_full_backup(str(backup), MASTER)
    assert not vault.exists()
    with pytest.raises(pm.VaultCryptoError, match="missing"):
        pm.StorageManager(MASTER)


def test_restore_does_not_replace_an_existing_vault(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account"))
    backup = tmp_path / "full.vault"
    manager.export_all_records_to_file(str(backup))
    vault = tmp_path / "json_files" / "password_data.vault"
    before = vault.read_bytes()
    with pytest.raises(pm.VaultCryptoError, match="not missing"):
        pm.StorageManager.restore_missing_vault_from_full_backup(str(backup), MASTER)
    assert vault.read_bytes() == before


def test_restore_wrong_master_password_leaves_vault_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account"))
    backup = tmp_path / "full.vault"
    manager.export_all_records_to_file(str(backup))
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.rename(tmp_path / "synthetic-vault-quarantine.vault")

    with pytest.raises(pm.VaultCryptoError):
        pm.StorageManager.restore_missing_vault_from_full_backup(str(backup), "wrong-synthetic-master-password")
    assert not vault.exists()
    assert (tmp_path / ".password-vault-initialized").exists()


def test_restore_rejects_unknown_backup_category_without_dropping_it(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    backup = tmp_path / "future-full.vault"
    payload = {category: [] for category in pm.CATEGORY_LABELS}
    payload["future_category"] = [{
        "password_id": 1, "employee_name": "Synthetic", "account_name": "Future",
        "username": "future", "account_password": "synthetic-value",
    }]
    save_encrypted_file(str(backup), payload, MASTER)
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.rename(tmp_path / "synthetic-vault-quarantine.vault")

    with pytest.raises(pm.VaultCryptoError, match="unsupported fields"):
        pm.StorageManager.restore_missing_vault_from_full_backup(str(backup), MASTER)
    assert not vault.exists()
    assert (tmp_path / ".password-vault-initialized").exists()


def test_restore_write_failure_leaves_missing_marker_state(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    backup = tmp_path / "full.vault"
    manager.export_all_records_to_file(str(backup))
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.rename(tmp_path / "synthetic-vault-quarantine.vault")
    real_save = pm.save_encrypted_file

    def fail_restore(path, payload, master_password, *, overwrite=True):
        if path == str(vault):
            raise OSError("synthetic interruption before commit")
        return real_save(path, payload, master_password, overwrite=overwrite)

    monkeypatch.setattr(pm, "save_encrypted_file", fail_restore)
    with pytest.raises(OSError, match="synthetic interruption"):
        pm.StorageManager.restore_missing_vault_from_full_backup(str(backup), MASTER)
    assert not vault.exists()
    assert (tmp_path / ".password-vault-initialized").exists()


def test_import_preflight_observes_cooperating_writer_update(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    importer = pm.StorageManager(MASTER)
    writer = pm.StorageManager(MASTER)
    writer.add_record("password_book", _record("Original Account"))
    original = writer.fetch_records("password_book")[0]
    incoming = {
        "category": "password_book",
        "employee_name": "Synthetic Owner",
        "account_name": "Updated Account",
        "username": "updated account",
        "account_password": "synthetic-backup-password",
    }
    backup = tmp_path / "concurrent-import.vault"
    payload = {category: [] for category in pm.CATEGORY_LABELS}
    payload["password_book"] = [incoming]
    save_encrypted_file(str(backup), payload, MASTER)

    import_at_lock = threading.Event()
    writer_done = threading.Event()
    actual_lock = pm.vault_transaction_lock

    @contextmanager
    def pause_import_before_lock(path):
        if threading.current_thread().name == "synthetic-importer":
            import_at_lock.set()
            if not writer_done.wait(10):
                raise AssertionError("Writer did not finish before import lock acquisition")
        with actual_lock(path):
            yield

    monkeypatch.setattr(pm, "vault_transaction_lock", pause_import_before_lock)
    import_errors = []

    def run_import():
        try:
            importer.import_all_records_from_file(str(backup))
        except Exception as exc:
            import_errors.append(exc)

    import_thread = threading.Thread(target=run_import, name="synthetic-importer")
    import_thread.start()
    try:
        assert import_at_lock.wait(10)
        updated = _record("Updated Account", "synthetic-writer-update")
        writer.update_record(
            "password_book", original["password_id"], updated, expected_record=original
        )
        writer_done.set()
    finally:
        writer_done.set()
        import_thread.join(10)

    assert not import_thread.is_alive()
    assert len(import_errors) == 1
    assert isinstance(import_errors[0], pm.RecordConflictError)
    current = writer.fetch_records("password_book")
    assert len(current) == 1
    assert current[0]["account_name"] == "Updated Account"
    assert current[0]["account_password"] == "synthetic-writer-update"


def test_missing_whole_vault_directory_after_restart_is_not_reseeded(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(MASTER)
    manager.add_record("password_book", _record("Account"))
    vault_dir = tmp_path / "json_files"
    vault_dir.rename(tmp_path / "synthetic-vault-directory-quarantine")

    with pytest.raises(pm.VaultCryptoError, match="missing"):
        pm.StorageManager(MASTER)
    assert not (vault_dir / "password_data.vault").exists()
