import os
from pathlib import Path

import pytest

from password_manager import (
    CATEGORY_LABELS,
    BackupUnlockError,
    RecordConflictError,
    StorageManager,
)
from vault_crypto import VaultCryptoError, load_encrypted_file, save_encrypted_file


PROFILE_A_MASTER = "synthetic-profile-a-master-123"
PROFILE_B_MASTER = "synthetic-profile-b-master-456"


def _make_profile(monkeypatch, profile_dir, master_password):
    monkeypatch.setattr("password_manager.BASE_DIR", str(profile_dir))
    return StorageManager(master_password)


def _synthetic_record(employee, account, username, password):
    return {
        "employee_name": employee,
        "account_name": account,
        "username": username,
        "phone_number": "555-0100",
        "website_url": "https://synthetic.example",
        "account_password": password,
        "notes": "synthetic import fixture",
    }


def test_category_backup_imports_between_distinct_profiles(tmp_path, monkeypatch):
    profile_a = _make_profile(monkeypatch, tmp_path / "profile-a", PROFILE_A_MASTER)
    profile_a.add_record(
        "mobile_devices",
        _synthetic_record("Source Owner", "Source Phone", "source-phone", "synthetic-source-secret"),
    )
    backup = tmp_path / "mobile-category.vault"
    profile_a.export_records_to_file("mobile_devices", str(backup))

    profile_b = _make_profile(monkeypatch, tmp_path / "profile-b", PROFILE_B_MASTER)
    profile_b.add_record(
        "mobile_devices",
        _synthetic_record("Destination Owner", "Existing Phone", "existing-phone", "synthetic-existing-secret"),
    )
    before_unrelated = profile_b.fetch_records("mobile_devices")[0]

    imported, skipped = profile_b.import_records_from_file(
        "mobile_devices", str(backup), backup_password=PROFILE_A_MASTER
    )

    records = profile_b.fetch_records("mobile_devices")
    assert (imported, skipped) == (1, 0)
    assert len(records) == 2
    assert before_unrelated in records
    source_copy = next(row for row in records if row["username"] == "source-phone")
    assert source_copy["account_password"] == "synthetic-source-secret"
    assert source_copy["account_name"] == "Source Phone"
    assert source_copy["phone_number"] == "555-0100"
    assert source_copy["website_url"] == "https://synthetic.example"
    assert source_copy["notes"] == "synthetic import fixture"


def test_full_backup_imports_between_distinct_profiles_and_preserves_destination(
    tmp_path, monkeypatch
):
    profile_a = _make_profile(monkeypatch, tmp_path / "profile-a", PROFILE_A_MASTER)
    source_records = {}
    for index, category in enumerate(CATEGORY_LABELS):
        record = _synthetic_record(
            f"Source Owner {index}", f"Source {category}", f"source-{category}", f"synthetic-{category}-secret"
        )
        profile_a.add_record(category, record)
        source_records[category] = record
    backup = tmp_path / "full-profile-a.vault"
    profile_a.export_all_records_to_file(str(backup))

    profile_b = _make_profile(monkeypatch, tmp_path / "profile-b", PROFILE_B_MASTER)
    profile_b.add_record(
        "password_book",
        _synthetic_record("Destination Owner", "Unrelated Account", "destination-only", "synthetic-destination-secret"),
    )
    unrelated_before = profile_b.fetch_records("password_book")[0]

    summary = profile_b.import_all_records_from_file(
        str(backup), backup_password=PROFILE_A_MASTER
    )

    assert summary == {category: 1 for category in CATEGORY_LABELS}
    assert unrelated_before in profile_b.fetch_records("password_book")
    for category, expected in source_records.items():
        imported = [row for row in profile_b.fetch_records(category) if row["username"] == expected["username"]]
        assert len(imported) == 1
        assert imported[0]["account_password"] == expected["account_password"]
        assert imported[0]["account_name"] == expected["account_name"]
        assert imported[0]["phone_number"] == expected["phone_number"]
        assert imported[0]["website_url"] == expected["website_url"]
        assert imported[0]["notes"] == expected["notes"]


@pytest.mark.parametrize("full_backup", [False, True])
def test_wrong_backup_password_leaves_destination_vault_bytes_unchanged(
    tmp_path, monkeypatch, full_backup
):
    profile_a = _make_profile(monkeypatch, tmp_path / "profile-a", PROFILE_A_MASTER)
    profile_a.add_record(
        "password_book",
        _synthetic_record("Source", "Source Account", "source-user", "synthetic-source-secret"),
    )
    backup = tmp_path / "wrong-password.vault"
    if full_backup:
        profile_a.export_all_records_to_file(str(backup))
    else:
        profile_a.export_records_to_file("password_book", str(backup))

    profile_b = _make_profile(monkeypatch, tmp_path / "profile-b", PROFILE_B_MASTER)
    profile_b.add_record(
        "admin",
        _synthetic_record("Destination", "Kept Account", "kept-user", "synthetic-kept-secret"),
    )
    before = Path(profile_b.vault_path).read_bytes()

    with pytest.raises(BackupUnlockError):
        if full_backup:
            profile_b.import_all_records_from_file(str(backup), backup_password="synthetic-wrong-master")
        else:
            profile_b.import_records_from_file(
                "password_book", str(backup), backup_password="synthetic-wrong-master"
            )

    assert Path(profile_b.vault_path).read_bytes() == before
    assert len(profile_b.fetch_records("admin")) == 1


def test_full_backup_key_collision_is_atomic_case_insensitively(tmp_path, monkeypatch):
    profile_a = _make_profile(monkeypatch, tmp_path / "profile-a", PROFILE_A_MASTER)
    profile_a.add_record(
        "admin",
        _synthetic_record("New Owner", "Noncolliding", "new-user", "synthetic-new-secret"),
    )
    profile_a.add_record(
        "admin",
        _synthetic_record("Owner", "Shared Account", "shared-user", "synthetic-backup-secret"),
    )
    backup = tmp_path / "case-collision.vault"
    profile_a.export_all_records_to_file(str(backup))
    assert [
        row["username"]
        for row in load_encrypted_file(str(backup), PROFILE_A_MASTER)["admin"]
    ] == ["new-user", "shared-user"]

    profile_b = _make_profile(monkeypatch, tmp_path / "profile-b", PROFILE_B_MASTER)
    profile_b.add_record(
        "admin",
        _synthetic_record("oWnEr", "sHaReD aCcOuNt", "SHARED-USER", "synthetic-destination-secret"),
    )
    before = Path(profile_b.vault_path).read_bytes()

    with pytest.raises(RecordConflictError):
        profile_b.import_all_records_from_file(str(backup), backup_password=PROFILE_A_MASTER)

    assert Path(profile_b.vault_path).read_bytes() == before
    records = profile_b.fetch_records("admin")
    assert len(records) == 1
    assert records[0]["account_password"] == "synthetic-destination-secret"


@pytest.mark.parametrize("full_backup", [False, True])
def test_backup_with_duplicate_normalized_keys_is_atomic(
    tmp_path, monkeypatch, full_backup
):
    profile = _make_profile(monkeypatch, tmp_path / "profile", PROFILE_B_MASTER)
    profile.add_record(
        "password_book",
        _synthetic_record("Unrelated Owner", "Unrelated Account", "unrelated-user", "synthetic-kept-secret"),
    )
    before = Path(profile.vault_path).read_bytes()

    first = {
        "password_id": 81001,
        "employee_name": "Owner",
        "account_name": "Shared Account",
        "username": "Shared User",
        "account_password": "synthetic-backup-secret-one",
    }
    second = {
        "password_id": 81002,
        "employee_name": " owner ",
        "account_name": "shared account ",
        "username": " shared user ",
        "account_password": "synthetic-backup-secret-two",
    }
    backup = tmp_path / "duplicate-normalized-keys.vault"
    if full_backup:
        payload = {category: [] for category in CATEGORY_LABELS}
        payload["password_book"] = [first, second]
    else:
        payload = {"password_book": [first, second]}
    save_encrypted_file(str(backup), payload, PROFILE_A_MASTER)

    with pytest.raises(RecordConflictError):
        if full_backup:
            profile.import_all_records_from_file(str(backup), backup_password=PROFILE_A_MASTER)
        else:
            profile.import_records_from_file(
                "password_book", str(backup), backup_password=PROFILE_A_MASTER
            )

    assert Path(profile.vault_path).read_bytes() == before
    records = profile.fetch_records("password_book")
    assert len(records) == 1
    assert records[0]["username"] == "unrelated-user"


def test_storage_creates_encrypted_vault_and_crud(tmp_path, monkeypatch):
    monkeypatch.setattr("password_manager.BASE_DIR", str(tmp_path))
    monkeypatch.setattr("password_manager.LOG_DIR", str(tmp_path / "logs"))
    manager = StorageManager("correct horse battery staple")

    assert manager.vault_path.endswith("password_data.vault")
    assert manager.fetch_records("password_book") == []

    record = {
        "employee_name": "Owner",
        "account_name": "Example",
        "username": "owner@example.com",
        "phone_number": "",
        "website_url": "https://example.com",
        "account_password": "real-secret-for-test-only",
        "notes": "test",
    }
    manager.add_record("password_book", record)
    records = manager.fetch_records("password_book")
    assert len(records) == 1
    assert records[0]["website_url"] == "https://example.com"
    assert records[0]["account_password"] == record["account_password"]
    assert manager.fetch_record("password_book", records[0]["password_id"])["account_name"] == "Example"
    assert record["account_password"].encode() not in open(manager.vault_path, "rb").read()


def test_mobile_device_phone_number_is_stored(tmp_path, monkeypatch):
    monkeypatch.setattr("password_manager.BASE_DIR", str(tmp_path))
    manager = StorageManager("correct horse battery staple")

    manager.add_record(
        "mobile_devices",
        {
            "employee_name": "Owner",
            "account_name": "Phone",
            "username": "owner-phone",
            "phone_number": "+1-555-0100",
            "website_url": "https://carrier.example",
            "account_password": "mobile-secret",
            "notes": "primary device",
        },
    )

    records = manager.fetch_records("mobile_devices")
    assert len(records) == 1
    assert records[0]["phone_number"] == "+1-555-0100"
    assert records[0]["website_url"] == "https://carrier.example"


def test_storage_rejects_legacy_plaintext_file(tmp_path, monkeypatch):
    monkeypatch.setattr("password_manager.BASE_DIR", str(tmp_path))
    legacy = tmp_path / "json_files" / "password_data.json"
    legacy.parent.mkdir()
    legacy.write_text(json_text := '{"password_book": []}', encoding="utf-8")

    with pytest.raises(VaultCryptoError):
        StorageManager("correct horse battery staple")


def test_malformed_encrypted_backup_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("password_manager.BASE_DIR", str(tmp_path))
    manager = StorageManager("correct horse battery staple")
    backup = tmp_path / "malformed.vault"
    save_encrypted_file(str(backup), {"unexpected": "shape"}, "correct horse battery staple")

    with pytest.raises(ValueError, match="recognized password categories"):
        manager.import_all_records_from_file(str(backup))


@pytest.mark.parametrize("full_backup", [False, True])
@pytest.mark.parametrize("alias", ["direct", "relative", "symlink", "hardlink"])
def test_export_rejects_live_vault_destination_without_changing_it(
    tmp_path, monkeypatch, full_backup, alias
):
    monkeypatch.setattr("password_manager.BASE_DIR", str(tmp_path))
    manager = StorageManager("correct horse battery staple")
    manager.add_record("password_book", {
        "employee_name": "Synthetic", "account_name": "Example", "username": "user",
        "account_password": " synthetic-only ", "notes": "",
    })
    before = (tmp_path / "json_files" / "password_data.vault").read_bytes()
    destination = manager.vault_path
    if alias == "relative":
        destination = os.path.join(tmp_path, "json_files", "..", "json_files", "password_data.vault")
    elif alias in ("symlink", "hardlink"):
        destination = str(tmp_path / f"{alias}.vault")
        try:
            if alias == "symlink":
                os.symlink(manager.vault_path, destination)
            else:
                os.link(manager.vault_path, destination)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"{alias} unavailable: {exc}")

    with pytest.raises(ValueError, match="active vault"):
        if full_backup:
            manager.export_all_records_to_file(destination)
        else:
            manager.export_records_to_file("password_book", destination)

    assert (tmp_path / "json_files" / "password_data.vault").read_bytes() == before
    assert len(manager.fetch_records("password_book")) == 1


@pytest.mark.parametrize("full_backup", [False, True])
def test_export_refuses_to_replace_existing_backup(tmp_path, monkeypatch, full_backup):
    monkeypatch.setattr("password_manager.BASE_DIR", str(tmp_path))
    manager = StorageManager("correct horse battery staple")
    backup = tmp_path / "backup.vault"
    if full_backup:
        manager.export_all_records_to_file(str(backup))
    else:
        manager.export_records_to_file("password_book", str(backup))
    original = backup.read_bytes()

    with pytest.raises(FileExistsError):
        if full_backup:
            manager.export_all_records_to_file(str(backup))
        else:
            manager.export_records_to_file("password_book", str(backup))
    assert backup.read_bytes() == original


@pytest.mark.parametrize("full_backup", [False, True])
def test_export_does_not_overwrite_vault_after_guard_alias_swap(tmp_path, monkeypatch, full_backup):
    monkeypatch.setattr("password_manager.BASE_DIR", str(tmp_path))
    manager = StorageManager("correct horse battery staple")
    vault = tmp_path / "json_files" / "password_data.vault"
    safe_dir = tmp_path / "safe"
    safe_dir.mkdir()
    alias = tmp_path / "export-alias"
    try:
        alias.symlink_to(safe_dir, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    destination = alias / "password_data.vault"
    before = vault.read_bytes()
    actual_save = __import__("password_manager").save_encrypted_file

    def swap_then_save(*args, **kwargs):
        alias.unlink()
        alias.symlink_to(vault.parent, target_is_directory=True)
        return actual_save(*args, **kwargs)

    monkeypatch.setattr("password_manager.save_encrypted_file", swap_then_save)
    with pytest.raises(FileExistsError):
        if full_backup:
            manager.export_all_records_to_file(str(destination))
        else:
            manager.export_records_to_file("password_book", str(destination))
    assert vault.read_bytes() == before
