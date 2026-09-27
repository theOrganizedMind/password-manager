"""Synthetic UI error-path checks without opening a desktop window."""

import pytest

import password_manager as pm
from vault_crypto import save_encrypted_file


PROFILE_MASTER = "synthetic-profile-master-123"


class FakeVar:
    def __init__(self):
        self.value = ""

    def set(self, value):
        self.value = value

    def get(self):
        return self.value


@pytest.mark.parametrize("full_backup", [False, True])
def test_backup_export_dialog_disables_replace_prompt_and_refuses_existing_file(
    tmp_path, monkeypatch, full_backup
):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    storage = pm.StorageManager(PROFILE_MASTER)
    backup = tmp_path / "existing.vault"
    if full_backup:
        storage.export_all_records_to_file(str(backup))
    else:
        storage.export_records_to_file("password_book", str(backup))
    original = backup.read_bytes()

    dialog_options = []
    warnings = []
    monkeypatch.setattr(
        pm.filedialog,
        "asksaveasfilename",
        lambda **kwargs: dialog_options.append(kwargs) or str(backup),
    )
    monkeypatch.setattr(pm.messagebox, "showwarning", lambda *args: warnings.append(args))
    app = object.__new__(pm.PasswordManagerApp)
    app.storage = storage

    if full_backup:
        app.export_all_records()
    else:
        app.export_records("password_book")

    assert len(dialog_options) == 1
    assert dialog_options[0]["confirmoverwrite"] is False
    assert backup.read_bytes() == original
    assert warnings == [
        ("Backup Exists", "Choose a new backup filename; existing files are not replaced.")
    ]


@pytest.mark.parametrize("full_template", [False, True])
def test_template_export_dialog_keeps_default_overwrite_options(
    tmp_path, monkeypatch, full_template
):
    dialog_options = []
    monkeypatch.setattr(
        pm.filedialog,
        "asksaveasfilename",
        lambda **kwargs: dialog_options.append(kwargs) or "",
    )
    app = object.__new__(pm.PasswordManagerApp)

    if full_template:
        app.export_all_template_records()
    else:
        app.export_template_records("password_book")

    assert len(dialog_options) == 1
    assert "confirmoverwrite" not in dialog_options[0]


@pytest.mark.parametrize("failure", [
    ValueError("SYNTHETIC_SECRET: weak settings"),
    FileNotFoundError("SYNTHETIC_SECRET: word list path"),
])
@pytest.mark.parametrize("preview", [False, True])
def test_generator_validation_failure_shows_safe_guidance(monkeypatch, failure, preview):
    app = object.__new__(pm.PasswordManagerApp)
    app.tabs = {"password_book": {"password_var": FakeVar()}}
    app.settings_preview_var = FakeVar()
    warnings = []
    monkeypatch.setattr(pm.password_generator, "generate_password", lambda: (_ for _ in ()).throw(failure))
    monkeypatch.setattr(pm.messagebox, "showwarning", lambda title, message: warnings.append((title, message)))

    if preview:
        app.generate_settings_preview()
        assert app.settings_preview_var.get() == ""
    else:
        app.generate_and_fill_password("password_book")
        assert app.tabs["password_book"]["password_var"].get() == ""

    assert len(warnings) == 1
    assert warnings[0][0] == "Generator Settings"
    assert "Settings" in warnings[0][1]
    assert "SYNTHETIC_SECRET" not in warnings[0][1]


def test_missing_vault_can_cancel_restore_before_master_password_prompt(tmp_path, monkeypatch):
    (tmp_path / ".password-vault-initialized").write_text("initialized\n", encoding="ascii")
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))

    class FakeRoot:
        destroyed = False

        def withdraw(self):
            pass

        def destroy(self):
            self.destroyed = True

    root = FakeRoot()
    questions = []
    monkeypatch.setattr(pm.tk, "Tk", lambda: root)
    monkeypatch.setattr(pm.messagebox, "askyesno", lambda *args, **kwargs: questions.append(args) or False)
    monkeypatch.setattr(pm.simpledialog, "askstring", lambda *args, **kwargs: pytest.fail("prompted for a new master password"))

    pm.main()

    assert root.destroyed
    assert len(questions) == 1
    assert questions[0][0] == "Vault Missing"
    assert "Choose No to exit without modifying or creating a vault." in questions[0][1]
    assert not (tmp_path / "json_files" / "password_data.vault").exists()


def test_missing_vault_ui_restores_full_backup_without_empty_intermediate(tmp_path, monkeypatch):
    master = "synthetic-master-password-123"
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    manager = pm.StorageManager(master)
    manager.add_record("password_book", {
        "employee_name": "Synthetic", "account_name": "Account", "username": "user",
        "account_password": "synthetic-value", "notes": "",
    })
    backup = tmp_path / "full.vault"
    manager.export_all_records_to_file(str(backup))
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.rename(tmp_path / "synthetic-quarantine.vault")

    class FakeRoot:
        def withdraw(self):
            pass

        def deiconify(self):
            self.visible = True

        def mainloop(self):
            pass

        def destroy(self):
            pytest.fail("The restore workflow aborted")

    root = FakeRoot()
    prompts = []
    monkeypatch.setattr(pm.tk, "Tk", lambda: root)
    monkeypatch.setattr(pm.messagebox, "askyesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(pm.filedialog, "askopenfilename", lambda *args, **kwargs: str(backup))
    monkeypatch.setattr(pm.simpledialog, "askstring", lambda *args, **kwargs: prompts.append(args[0]) or master)
    monkeypatch.setattr(pm.messagebox, "showinfo", lambda *args, **kwargs: None)
    monkeypatch.setattr(pm.PasswordManagerApp, "__init__", lambda self, _root, _master: None)

    pm.main()

    assert prompts == ["Unlock Backup"]
    assert root.visible
    assert pm.StorageManager(master).fetch_records("password_book")[0]["account_password"] == "synthetic-value"


@pytest.mark.parametrize("cancel_retry", [False, True])
def test_category_vault_import_prompts_and_retries_or_exits_on_cancel(
    tmp_path, monkeypatch, cancel_retry
):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    backup = tmp_path / "source.vault"
    backup.write_bytes(b"synthetic encrypted backup placeholder")
    passwords = iter(["synthetic-wrong-password", "synthetic-correct-password"])
    prompts = []
    prompt_options = []
    calls = []
    errors = []
    completions = []

    class FakeStorage:
        def import_records_from_file(self, category, path, *, backup_password):
            calls.append((category, path, backup_password))
            if len(calls) == 1:
                raise pm.BackupUnlockError("synthetic unlock failure")
            return 1, 0

    app = object.__new__(pm.PasswordManagerApp)
    app.storage = FakeStorage()
    app.load_tab_data = lambda _category: None
    app.refresh_reminder_tab = lambda: None
    app.handle_ui_exception = lambda *args: errors.append(args)
    monkeypatch.setattr(pm.filedialog, "askopenfilename", lambda **_kwargs: str(backup))
    monkeypatch.setattr(
        pm.simpledialog,
        "askstring",
        lambda *args, **kwargs: prompts.append(args) or prompt_options.append(kwargs) or next(passwords),
    )
    monkeypatch.setattr(pm.messagebox, "askretrycancel", lambda *_args: not cancel_retry)
    monkeypatch.setattr(pm.messagebox, "showinfo", lambda *args: completions.append(args))
    monkeypatch.setattr(pm.messagebox, "showerror", lambda *args: errors.append(args))

    app.import_records("password_book")

    assert len(prompts) == (1 if cancel_retry else 2)
    assert all(args[0] == "Unlock Backup" for args in prompts)
    assert all("may differ" in args[1] for args in prompts)
    assert all(options["show"] == "*" for options in prompt_options)
    assert calls[0][0] == "password_book"
    assert calls[0][2] == "synthetic-wrong-password"
    if cancel_retry:
        assert len(calls) == 1
        assert completions == []
        assert errors == []
    else:
        assert calls[1][2] == "synthetic-correct-password"
        assert len(completions) == 1
        assert errors == []


def test_decryptable_malformed_backup_is_not_reported_as_password_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    storage = pm.StorageManager(PROFILE_MASTER)
    backup = tmp_path / "malformed-but-decryptable.vault"
    save_encrypted_file(str(backup), {"unrecognized": "synthetic shape"}, PROFILE_MASTER)

    app = object.__new__(pm.PasswordManagerApp)
    app.storage = storage
    app._prompt_backup_password = lambda: PROFILE_MASTER
    handled = []
    retry_prompts = []
    app.handle_ui_exception = lambda *args: handled.append(args)
    monkeypatch.setattr(pm.filedialog, "askopenfilename", lambda **_kwargs: str(backup))
    monkeypatch.setattr(
        pm.messagebox,
        "askretrycancel",
        lambda *args: retry_prompts.append(args) or pytest.fail("malformed structure was treated as a password error"),
    )

    app.import_records("password_book")

    assert len(handled) == 1
    assert handled[0][2] == "import_records"
    assert retry_prompts == []


def test_missing_vault_empty_backup_selection_exits_without_starting_event_loop(tmp_path, monkeypatch):
    initialized = tmp_path / ".password-vault-initialized"
    initialized.write_text("initialized\n", encoding="ascii")
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))

    class FakeRoot:
        destroyed = False
        loop_started = False

        def withdraw(self):
            pass

        def destroy(self):
            self.destroyed = True

        def deiconify(self):
            pytest.fail("startup continued without a selected restore backup")

        def mainloop(self):
            self.loop_started = True

    root = FakeRoot()
    monkeypatch.setattr(pm.tk, "Tk", lambda: root)
    monkeypatch.setattr(pm.messagebox, "askyesno", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(pm.filedialog, "askopenfilename", lambda **_kwargs: "")
    monkeypatch.setattr(
        pm.simpledialog,
        "askstring",
        lambda *args, **kwargs: pytest.fail("startup prompted for a password without a backup"),
    )

    pm.main()

    assert root.destroyed
    assert not root.loop_started
    assert not (tmp_path / "json_files" / "password_data.vault").exists()


def test_full_backup_import_retries_wrong_password_then_succeeds(tmp_path, monkeypatch):
    master = "synthetic-full-backup-master-123"
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    monkeypatch.setattr(pm, "BASE_DIR", str(source_dir))
    source = pm.StorageManager(master)
    source.add_record("password_book", {
        "employee_name": "Synthetic Source", "account_name": "Imported Account",
        "username": "source-user", "account_password": "synthetic-imported-value", "notes": "",
    })
    backup = source_dir / "full-source.vault"
    source.export_all_records_to_file(str(backup))

    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    destination = pm.StorageManager("synthetic-destination-master-123")
    destination.add_record("admin", {
        "employee_name": "Synthetic Existing", "account_name": "Existing Account",
        "username": "existing-user", "account_password": "synthetic-existing-value", "notes": "",
    })
    app = object.__new__(pm.PasswordManagerApp)
    app.storage = destination
    app._prompt_backup_password = lambda: next(passwords)
    app.load_all_tabs = lambda: None
    app.refresh_reminder_tab = lambda: None
    app.handle_ui_exception = lambda *args: pytest.fail(f"full import failed unexpectedly: {args!r}")
    passwords = iter(["synthetic-wrong-password", master])
    retry_prompts = []
    completions = []
    monkeypatch.setattr(pm.filedialog, "askopenfilename", lambda **_kwargs: str(backup))
    monkeypatch.setattr(
        pm.messagebox,
        "askretrycancel",
        lambda *args: retry_prompts.append(args) or True,
    )
    monkeypatch.setattr(pm.messagebox, "showinfo", lambda *args: completions.append(args))

    app.import_all_records()

    assert len(retry_prompts) == 1
    assert retry_prompts[0][0] == "Backup Unlock Failed"
    assert "no records were imported" in retry_prompts[0][1]
    assert len(completions) == 1
    assert destination.fetch_records("password_book")[0]["account_password"] == "synthetic-imported-value"
    assert destination.fetch_records("admin")[0]["account_password"] == "synthetic-existing-value"


def test_full_backup_import_wrong_password_cancel_preserves_destination_bytes(tmp_path, monkeypatch):
    master = "synthetic-cancel-source-master-123"
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    monkeypatch.setattr(pm, "BASE_DIR", str(source_dir))
    source = pm.StorageManager(master)
    source.add_record("password_book", {
        "employee_name": "Synthetic Source", "account_name": "Unimported Account",
        "username": "source-user", "account_password": "synthetic-unimported-value", "notes": "",
    })
    backup = source_dir / "cancel-source.vault"
    source.export_all_records_to_file(str(backup))

    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    destination = pm.StorageManager("synthetic-destination-master-456")
    destination.add_record("admin", {
        "employee_name": "Synthetic Existing", "account_name": "Preserved Account",
        "username": "existing-user", "account_password": "synthetic-preserved-value", "notes": "",
    })
    vault_path = tmp_path / "json_files" / "password_data.vault"
    original_vault_bytes = vault_path.read_bytes()
    app = object.__new__(pm.PasswordManagerApp)
    app.storage = destination
    app._prompt_backup_password = lambda: "synthetic-wrong-password"
    app.load_all_tabs = lambda: pytest.fail("cancelled import refreshed the UI")
    app.refresh_reminder_tab = lambda: pytest.fail("cancelled import refreshed reminders")
    app.handle_ui_exception = lambda *args: pytest.fail(f"cancelled import raised unexpectedly: {args!r}")
    retry_prompts = []
    monkeypatch.setattr(pm.filedialog, "askopenfilename", lambda **_kwargs: str(backup))
    monkeypatch.setattr(
        pm.messagebox,
        "askretrycancel",
        lambda *args: retry_prompts.append(args) or False,
    )
    monkeypatch.setattr(
        pm.messagebox,
        "showinfo",
        lambda *args: pytest.fail("cancelled import reported completion"),
    )

    app.import_all_records()

    assert len(retry_prompts) == 1
    assert vault_path.read_bytes() == original_vault_bytes
    assert destination.fetch_records("admin")[0]["account_password"] == "synthetic-preserved-value"
    assert destination.fetch_records("password_book") == []


def test_startup_warns_about_vault_temp_remnant_without_changing_it(tmp_path, monkeypatch):
    master = "synthetic-startup-master-123"
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    storage = pm.StorageManager(master)
    storage.add_record("password_book", {
        "employee_name": "Synthetic", "account_name": "Startup Account",
        "username": "startup-user", "account_password": "synthetic-startup-value", "notes": "",
    })
    vault_dir = tmp_path / "json_files"
    remnant = vault_dir / ".vault-synthetic.tmp"
    remnant_bytes = b"synthetic interrupted-save evidence"
    remnant.write_bytes(remnant_bytes)
    vault_path = vault_dir / "password_data.vault"
    original_vault_bytes = vault_path.read_bytes()

    class FakeRoot:
        def withdraw(self):
            pass

        def deiconify(self):
            self.visible = True

        def mainloop(self):
            pass

    root = FakeRoot()
    warnings = []
    monkeypatch.setattr(pm.tk, "Tk", lambda: root)
    monkeypatch.setattr(pm.simpledialog, "askstring", lambda *args, **kwargs: master)
    monkeypatch.setattr(pm.PasswordManagerApp, "__init__", lambda self, _root, _master: None)
    monkeypatch.setattr(pm.messagebox, "showwarning", lambda *args, **kwargs: warnings.append((args, kwargs)))

    pm.main()

    assert root.visible
    assert len(warnings) == 1
    assert warnings[0][0][0] == "Vault Files Need Review"
    warning_text = warnings[0][0][1]
    assert str(vault_dir) in warning_text
    assert "Preserve them" in warning_text
    assert "review these files, the vault, and your backups" in warning_text
    assert "scanned only this folder" in warning_text
    assert "has not deleted anything" in warning_text
    assert remnant.exists()
    assert remnant.read_bytes() == remnant_bytes
    assert vault_path.read_bytes() == original_vault_bytes


def test_clear_fields_clears_selected_row_and_avoids_empty_selection_remove():
    class FakeVar:
        def __init__(self, value="stale"):
            self.value = value

        def set(self, value):
            self.value = value

    class FakeEntry:
        def configure(self, **kwargs):
            self.show = kwargs["show"]

    class FakeTree:
        def __init__(self, selected):
            self.selected = selected
            self.removed = []

        def selection(self):
            return self.selected

        def selection_remove(self, selection):
            self.removed.append(selection)
            self.selected = ()

    app = object.__new__(pm.PasswordManagerApp)
    tree = FakeTree(("row-7",))
    app.tabs = {
        "password_book": {
            "employee_var": FakeVar(), "account_var": FakeVar(),
            "username_var": FakeVar(), "password_var": FakeVar(),
            "notes_var": FakeVar(), "show_password_var": FakeVar(True),
            "password_entry": FakeEntry(), "tree": tree,
            "selected_id": "row-7", "selected_snapshot": {"account_password": "synthetic-secret"},
        }
    }

    app.clear_fields("password_book")

    tab = app.tabs["password_book"]
    assert tab["selected_id"] is None
    assert tab["selected_snapshot"] is None
    assert tab["password_var"].value == ""
    assert tree.selected == ()
    assert tree.removed == [("row-7",)]

    tree.selected = ()
    app.clear_fields("password_book")
    assert tree.removed == [("row-7",)]
