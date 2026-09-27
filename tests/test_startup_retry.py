"""Synthetic, headless checks for startup password retry and cancellation."""

import json

import password_manager as pm


MASTER = "synthetic-startup-master-123"
WRONG = "synthetic-wrong-master-123"


class FakeRoot:
    def __init__(self):
        self.destroyed = False
        self.visible = False
        self.loops = 0

    def withdraw(self):
        pass

    def destroy(self):
        self.destroyed = True

    def deiconify(self):
        self.visible = True

    def mainloop(self):
        self.loops += 1


def setup_startup(monkeypatch, tmp_path, passwords, retry_answers):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    root = FakeRoot()
    prompts = []
    retries = []
    opened = []
    errors = []
    answers = iter(passwords)
    decisions = iter(retry_answers)

    monkeypatch.setattr(pm.tk, "Tk", lambda: root)

    def askstring(title, *args, **kwargs):
        prompts.append(title)
        assert kwargs["show"] == "*"
        return next(answers)

    def askretrycancel(title, message, **kwargs):
        retries.append((title, message))
        return next(decisions)

    def open_app(self, _root, master_password):
        self.storage = pm.StorageManager(master_password)
        opened.append(master_password)

    monkeypatch.setattr(pm.simpledialog, "askstring", askstring)
    monkeypatch.setattr(pm.messagebox, "askretrycancel", askretrycancel)
    monkeypatch.setattr(pm.messagebox, "showerror", lambda *args, **kwargs: errors.append(args))
    monkeypatch.setattr(pm.PasswordManagerApp, "__init__", open_app)
    return root, prompts, retries, opened, errors


def test_confirmation_mismatch_retry_then_success(tmp_path, monkeypatch):
    root, prompts, retries, opened, errors = setup_startup(
        monkeypatch, tmp_path, [MASTER, WRONG, MASTER, MASTER], [True]
    )

    pm.main()

    assert prompts == ["Create Master Password", "Confirm Master Password"] * 2
    assert [title for title, _ in retries] == ["Password Mismatch"]
    assert opened == [MASTER]
    assert errors == []
    assert root.visible and root.loops == 1 and not root.destroyed
    assert (tmp_path / "json_files" / "password_data.vault").exists()


def test_confirmation_mismatch_cancel_does_not_create_vault(tmp_path, monkeypatch):
    root, _, retries, opened, _ = setup_startup(
        monkeypatch, tmp_path, [MASTER, WRONG], [False]
    )

    pm.main()

    assert len(retries) == 1
    assert opened == []
    assert root.destroyed and root.loops == 0
    assert not (tmp_path / "json_files" / "password_data.vault").exists()
    assert not (tmp_path / ".password-vault-initialized").exists()


def test_wrong_existing_password_retry_then_success(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    pm.StorageManager(MASTER)
    root, prompts, retries, opened, errors = setup_startup(
        monkeypatch, tmp_path, [WRONG, MASTER], [True]
    )

    pm.main()

    assert prompts == ["Unlock Vault", "Unlock Vault"]
    assert [title for title, _ in retries] == ["Vault Locked"]
    assert opened == [MASTER]
    assert errors == []
    assert root.visible and root.loops == 1 and not root.destroyed


def test_wrong_existing_password_cancel_preserves_vault_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    pm.StorageManager(MASTER)
    vault = tmp_path / "json_files" / "password_data.vault"
    original = vault.read_bytes()
    root, prompts, retries, opened, _ = setup_startup(
        monkeypatch, tmp_path, [WRONG], [False]
    )

    pm.main()

    assert prompts == ["Unlock Vault"]
    assert len(retries) == 1
    assert opened == []
    assert root.destroyed and root.loops == 0
    assert vault.read_bytes() == original


def test_short_existing_password_retries_before_opening_vault(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    pm.StorageManager(MASTER)
    root, prompts, retries, opened, errors = setup_startup(
        monkeypatch, tmp_path, ["short", MASTER], [True]
    )

    pm.main()

    assert prompts == ["Unlock Vault", "Unlock Vault"]
    assert [title for title, _ in retries] == ["Password Too Short"]
    assert opened == [MASTER]
    assert errors == []
    assert root.visible and root.loops == 1 and not root.destroyed


def test_short_password_retry_then_unsupported_vault_stays_locked(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    pm.StorageManager(MASTER)
    vault = tmp_path / "json_files" / "password_data.vault"
    envelope = json.loads(vault.read_text(encoding="utf-8"))
    envelope["version"] = 999
    vault.write_text(json.dumps(envelope), encoding="utf-8")
    damaged = vault.read_bytes()
    root, prompts, retries, opened, errors = setup_startup(
        monkeypatch, tmp_path, ["short", MASTER], [True]
    )

    pm.main()

    assert prompts == ["Unlock Vault", "Unlock Vault"]
    assert [title for title, _ in retries] == ["Password Too Short"]
    assert opened == []
    assert len(errors) == 1 and errors[0][0] == "Vault Locked"
    assert root.destroyed and root.loops == 0
    assert vault.read_bytes() == damaged


def test_damaged_vault_never_unlocks_or_offers_password_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    pm.StorageManager(MASTER)
    vault = tmp_path / "json_files" / "password_data.vault"
    vault.write_bytes(b"synthetic damaged envelope")
    damaged = vault.read_bytes()
    root, prompts, retries, opened, errors = setup_startup(
        monkeypatch, tmp_path, [MASTER], []
    )

    pm.main()

    assert prompts == ["Unlock Vault"]
    assert retries == []
    assert opened == []
    assert len(errors) == 1
    assert root.destroyed and root.loops == 0
    assert vault.read_bytes() == damaged


def test_tampered_ciphertext_retry_does_not_unlock(tmp_path, monkeypatch):
    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    pm.StorageManager(MASTER)
    vault = tmp_path / "json_files" / "password_data.vault"
    envelope = json.loads(vault.read_text(encoding="utf-8"))
    ciphertext = envelope["ciphertext"]
    envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    vault.write_text(json.dumps(envelope), encoding="utf-8")
    damaged = vault.read_bytes()
    root, prompts, retries, opened, errors = setup_startup(
        monkeypatch, tmp_path, [MASTER, MASTER], [True, False]
    )

    pm.main()

    assert prompts == ["Unlock Vault", "Unlock Vault"]
    assert len(retries) == 2
    assert opened == []
    assert errors == []
    assert root.destroyed and root.loops == 0
    assert vault.read_bytes() == damaged
