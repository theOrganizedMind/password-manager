"""Scripted Windows headed Tk backup smoke tests; no human clicks.

Real Tk roots, PasswordManagerApp widgets, and encrypted vault I/O are used.
Only native file/password/message dialogs are mocked for unattended execution.
Every vault and backup path is derived from pytest's disposable tmp_path.
The app's fixed logging path may still append operation-only entries in this checkout.
"""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk

import pytest

import password_manager as pm
from vault_crypto import load_encrypted_file


SOURCE_MASTER = "synthetic-headed-source-master-123"
DESTINATION_MASTER = "synthetic-headed-destination-master-456"
SOURCE_SECRET = "synthetic-headed-source-secret"
SECOND_SECRET = "synthetic-headed-computer-secret"
DESTINATION_SECRET = "synthetic-headed-kept-secret"
CATEGORY = "password_book"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _button(parent, label):
    matches = []

    def visit(widget):
        for child in widget.winfo_children():
            if isinstance(child, ttk.Button) and child.cget("text") == label:
                matches.append(child)
            visit(child)

    visit(parent)
    assert len(matches) == 1, f"Expected one {label!r} button, found {len(matches)}"
    return matches[0]


def _category_tab(app, category):
    return {
        "password_book": app.tab_password_book,
        "computers": app.tab_computer_book,
        "admin": app.tab_admin,
    }[category]


@pytest.fixture(scope="module")
def tk_root():
    """Reuse one real Tcl/Tk interpreter across both Windows smoke cases."""
    root = tk.Tk()
    try:
        assert root.winfo_exists() == 1
        yield root
    finally:
        root.destroy()


@contextmanager
def _headed_app(monkeypatch, root, profile_path, password):
    """Open and always tear down real app widgets for one synthetic profile."""
    assert profile_path.is_dir() and profile_path.name in {"profile-a", "profile-b"}
    monkeypatch.setattr(pm, "BASE_DIR", str(profile_path))
    try:
        app = pm.PasswordManagerApp(root, password)
        root.update()
        assert root.winfo_ismapped()
        assert isinstance(app.notebook, ttk.Notebook)
        assert isinstance(app.tabs[CATEGORY]["tree"], ttk.Treeview)
        yield app
    finally:
        for child in root.winfo_children():
            child.destroy()


def _add_through_form(app, category, employee, account, username, secret):
    tab = app.tabs[category]
    tab["employee_var"].set(employee)
    tab["account_var"].set(account)
    tab["username_var"].set(username)
    tab["password_var"].set(secret)
    _button(_category_tab(app, category), "Add").invoke()
    rows = app.storage.fetch_records(category)
    assert any(row["username"] == username and row["account_password"] == secret for row in rows)
    assert len(tab["tree"].get_children()) == len(rows)


@pytest.mark.skipif(os.name != "nt", reason="Windows headed Tk and vault locks required")
@pytest.mark.parametrize("full_backup", [False, True], ids=["category", "full"])
def test_headed_backup_export_refusal_cancel_import_and_reopen(
    tmp_path, monkeypatch, tk_root, full_backup
):
    profile_a = tmp_path / "profile-a"
    profile_b = tmp_path / "profile-b"
    profile_a.mkdir()
    profile_b.mkdir()
    backup = tmp_path / ("full-backup.vault" if full_backup else "category-backup.vault")
    assert not backup.exists()

    # Avoid reading any real generator settings while exercising the app UI.
    monkeypatch.setattr(
        pm.password_generator,
        "get_password_settings",
        lambda: {**pm.password_generator.DEFAULT_PASSWORD_SETTINGS, "reminder_days": "off"},
    )
    messages = []
    monkeypatch.setattr(pm.messagebox, "showinfo", lambda *args: messages.append(("info", args)))
    monkeypatch.setattr(pm.messagebox, "showwarning", lambda *args: messages.append(("warning", args)))
    monkeypatch.setattr(
        pm.messagebox,
        "showerror",
        lambda *args: pytest.fail(f"unexpected app error dialog: {args!r}"),
    )
    save_options = []

    def choose_backup(**options):
        save_options.append(options)
        return str(backup)

    monkeypatch.setattr(pm.filedialog, "asksaveasfilename", choose_backup)
    monkeypatch.setattr(pm.filedialog, "askopenfilename", lambda **_options: str(backup))

    with _headed_app(monkeypatch, tk_root, profile_a, SOURCE_MASTER) as source:
        assert Path(source.storage.vault_path).is_relative_to(profile_a)
        _add_through_form(
            source, CATEGORY, "Source Owner", "Source Account", "source-user", SOURCE_SECRET
        )
        _add_through_form(
            source, "computers", "Source Owner", "Source Computer", "source-pc", SECOND_SECRET
        )
        export_button = _button(
            source.tab_reminders if full_backup else source.tab_password_book,
            "Export All" if full_backup else "Export",
        )
        messages.clear()
        export_button.invoke()
        assert backup.is_file()
        assert save_options[-1]["confirmoverwrite"] is False
        assert messages == [("info", ("Export Complete", f"{'Full backup' if full_backup else 'Backup'} saved to:\n{backup}"))]

        payload = load_encrypted_file(str(backup), SOURCE_MASTER)
        assert payload[CATEGORY][0]["account_password"] == SOURCE_SECRET
        assert ("computers" in payload) is full_backup
        if full_backup:
            assert payload["computers"][0]["account_password"] == SECOND_SECRET
        assert SOURCE_SECRET.encode() not in backup.read_bytes()
        backup_hash = _sha256(backup)

        messages.clear()
        export_button.invoke()
        assert _sha256(backup) == backup_hash
        assert messages == [
            ("warning", ("Backup Exists", "Choose a new backup filename; existing files are not replaced."))
        ]
        assert len(save_options) == 2
        assert all(options["confirmoverwrite"] is False for options in save_options)

    with _headed_app(monkeypatch, tk_root, profile_b, DESTINATION_MASTER) as destination:
        _add_through_form(
            destination, "admin", "Destination Owner", "Kept Account", "kept-user", DESTINATION_SECRET
        )
        vault_path = Path(destination.storage.vault_path)
        assert vault_path.is_file() and vault_path.is_relative_to(profile_b)
        assert DESTINATION_SECRET.encode() not in vault_path.read_bytes()
        before_hash = _sha256(vault_path)
        before_admin = destination.storage.fetch_records("admin")
        import_button = _button(
            destination.tab_reminders if full_backup else destination.tab_password_book,
            "Import All" if full_backup else "Import",
        )
        retry_prompts = []
        monkeypatch.setattr(
            pm.simpledialog, "askstring", lambda *args, **_kwargs: "synthetic-wrong-password"
        )
        monkeypatch.setattr(
            pm.messagebox,
            "askretrycancel",
            lambda *args: retry_prompts.append(args) or False,
        )
        messages.clear()
        import_button.invoke()
        assert len(retry_prompts) == 1
        assert retry_prompts[0][0] == "Backup Unlock Failed"
        assert "no records were imported" in retry_prompts[0][1]
        assert messages == []
        assert _sha256(vault_path) == before_hash
        assert destination.storage.fetch_records("admin") == before_admin
        assert destination.storage.fetch_records(CATEGORY) == []
        assert len(destination.tabs["admin"]["tree"].get_children()) == 1

        monkeypatch.setattr(pm.simpledialog, "askstring", lambda *args, **_kwargs: SOURCE_MASTER)
        messages.clear()
        import_button.invoke()
        assert len(messages) == 1 and messages[0][0] == "info"
        assert messages[0][1][0] == "Import Complete"
        assert destination.storage.fetch_records("admin") == before_admin
        imported = destination.storage.fetch_records(CATEGORY)
        assert len(imported) == 1
        assert imported[0]["username"] == "source-user"
        assert imported[0]["account_password"] == SOURCE_SECRET
        assert len(destination.tabs[CATEGORY]["tree"].get_children()) == 1
        displayed = destination.tabs[CATEGORY]["tree"].item(
            destination.tabs[CATEGORY]["tree"].get_children()[0], "values"
        )
        assert displayed[0:3] == ("Source Owner", "Source Account", "source-user")
        assert displayed[4] == "••••••••"
        assert all(SOURCE_SECRET not in str(cell) for cell in displayed)
        assert len(destination.tabs["admin"]["tree"].get_children()) == 1
        assert bool(destination.storage.fetch_records("computers")) is full_backup
        first_destination_storage = destination.storage

    with _headed_app(monkeypatch, tk_root, profile_b, DESTINATION_MASTER) as reopened:
        assert reopened.storage is not first_destination_storage
        assert reopened.storage.fetch_records("admin") == before_admin
        assert reopened.storage.fetch_records(CATEGORY)[0]["account_password"] == SOURCE_SECRET
        assert len(reopened.tabs[CATEGORY]["tree"].get_children()) == 1
        reopened_display = reopened.tabs[CATEGORY]["tree"].item(
            reopened.tabs[CATEGORY]["tree"].get_children()[0], "values"
        )
        assert reopened_display == displayed
        assert len(reopened.tabs["admin"]["tree"].get_children()) == 1
        assert bool(reopened.storage.fetch_records("computers")) is full_backup
