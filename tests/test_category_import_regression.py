"""Focused regressions for encrypted, category-only backup imports."""

import hashlib
from pathlib import Path

import pytest

import password_manager as pm


SOURCE_MASTER = "synthetic-category-source-master-123"
DESTINATION_MASTER = "synthetic-category-destination-master-456"


def _record(employee, account, username, password):
    return {
        "employee_name": employee,
        "account_name": account,
        "username": username,
        "account_password": password,
        "notes": "synthetic category import regression",
    }


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_category_vault_wrong_password_then_cancel_preserves_destination(
    tmp_path, monkeypatch
):
    source_dir = tmp_path / "source-profile"
    monkeypatch.setattr(pm, "BASE_DIR", str(source_dir))
    source = pm.StorageManager(SOURCE_MASTER)
    source.add_record(
        "password_book",
        _record("Source Owner", "Source Account", "source-user", "synthetic-source-value"),
    )
    backup = tmp_path / "source-category.vault"
    source.export_records_to_file("password_book", str(backup))

    destination_dir = tmp_path / "destination-profile"
    monkeypatch.setattr(pm, "BASE_DIR", str(destination_dir))
    destination = pm.StorageManager(DESTINATION_MASTER)
    destination.add_record(
        "password_book",
        _record(
            "Destination Owner", "Kept Account", "kept-user", "synthetic-kept-value"
        ),
    )
    destination_path = destination.vault_path
    before_hash = _sha256(destination_path)
    before_value = destination.fetch_records("password_book")

    app = object.__new__(pm.PasswordManagerApp)
    app.storage = destination
    app._prompt_backup_password = lambda: "synthetic-wrong-source-password"
    app.load_tab_data = lambda _category: pytest.fail("cancelled import refreshed the tab")
    app.refresh_reminder_tab = lambda: pytest.fail("cancelled import refreshed reminders")
    app.handle_ui_exception = lambda *args: pytest.fail(
        f"cancelled import unexpectedly raised: {args!r}"
    )
    monkeypatch.setattr(pm.filedialog, "askopenfilename", lambda **_kwargs: str(backup))
    retry_dialogs = []
    monkeypatch.setattr(
        pm.messagebox,
        "askretrycancel",
        lambda *args: retry_dialogs.append(args) or False,
    )
    monkeypatch.setattr(
        pm.messagebox,
        "showinfo",
        lambda *args: pytest.fail(f"cancelled import reported success: {args!r}"),
    )

    app.import_records("password_book")

    assert len(retry_dialogs) == 1
    assert "Backup Unlock Failed" == retry_dialogs[0][0]
    assert _sha256(destination_path) == before_hash
    assert destination.fetch_records("password_book") == before_value
    assert before_value[0]["account_password"] == "synthetic-kept-value"


def test_category_vault_normalized_destination_collision_preserves_value_and_bytes(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path / "source-profile"))
    source = pm.StorageManager(SOURCE_MASTER)
    source.add_record(
        "password_book",
        _record("Source Owner", "Shared Account", "Shared User", "synthetic-source-value"),
    )
    backup = tmp_path / "colliding-category.vault"
    source.export_records_to_file("password_book", str(backup))

    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path / "destination-profile"))
    destination = pm.StorageManager(DESTINATION_MASTER)
    destination.add_record(
        "password_book",
        _record(" source owner ", "shared account", "SHARED USER", "synthetic-kept-value"),
    )
    destination_path = destination.vault_path
    before_hash = _sha256(destination_path)
    before_records = destination.fetch_records("password_book")

    with pytest.raises(pm.RecordConflictError):
        destination.import_records_from_file(
            "password_book", str(backup), backup_password=SOURCE_MASTER
        )

    assert _sha256(destination_path) == before_hash
    assert destination.fetch_records("password_book") == before_records
    assert before_records[0]["account_password"] == "synthetic-kept-value"
