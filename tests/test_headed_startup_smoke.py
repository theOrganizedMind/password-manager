"""Bounded Tk startup checks using only synthetic vaults under tmp_path."""

import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk

import pytest

import password_manager as pm

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows desktop Tk test")


MASTER = "synthetic-headed-master-123"
WRONG = "synthetic-headed-wrong-123"


def _widgets(parent):
    for child in parent.winfo_children():
        yield child
        yield from _widgets(child)


def _destroyed(root):
    try:
        return root.winfo_exists() == 0
    except tk.TclError as exc:
        assert "application has been destroyed" in str(exc)
        return True


@pytest.fixture
def startup(monkeypatch, tmp_path, request):
    # This Windows Tcl installation sometimes fails to load a different .tcl
    # file when a second full app root is created in the same process.
    if os.environ.get("PASSWORD_HEADED_STARTUP_CHILD") != "1":
        env = os.environ.copy()
        env["PASSWORD_HEADED_STARTUP_CHILD"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", request.node.nodeid],
            capture_output=True,
            text=True,
            timeout=45,
            env=env,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "1 passed" in result.stdout and "skipped" not in result.stdout, (
            "Headed child did not execute its selected test:\n" + result.stdout + result.stderr
        )
        yield None
        return

    monkeypatch.setattr(pm, "BASE_DIR", str(tmp_path))
    monkeypatch.setattr(
        pm.password_generator,
        "get_password_settings",
        lambda: {**pm.password_generator.DEFAULT_PASSWORD_SETTINGS, "reminder_days": "off"},
    )
    roots = []
    prompts = []
    retries = []
    loops = []
    answers = iter(())
    decisions = iter(())

    def record_root(parent):
        assert isinstance(parent, tk.Tk)
        if roots:
            assert parent is roots[0]
        else:
            roots.append(parent)

    def askstring(title, message, *, show, parent):
        record_root(parent)
        assert show == "*"
        prompts.append(title)
        return next(answers)

    def askretrycancel(title, message, *, parent):
        record_root(parent)
        if title == "Password Mismatch":
            assert not (tmp_path / "json_files" / "password_data.vault").exists()
            assert not (tmp_path / ".password-vault-initialized").exists()
        retries.append(title)
        return next(decisions)

    def unexpected_dialog(*args, **kwargs):
        pytest.fail(f"Unexpected startup dialog: {args!r}")

    def bounded_mainloop(root, *args, **kwargs):
        record_root(root)
        loops.append(root)
        root.update()

    monkeypatch.setattr(pm.simpledialog, "askstring", askstring)
    monkeypatch.setattr(pm.messagebox, "askretrycancel", askretrycancel)
    for name in ("askyesno", "showerror", "showinfo", "showwarning"):
        monkeypatch.setattr(pm.messagebox, name, unexpected_dialog)
    monkeypatch.setattr(pm.filedialog, "askopenfilename", unexpected_dialog)
    monkeypatch.setattr(tk.Tk, "mainloop", bounded_mainloop)

    def run(passwords, retry_answers):
        nonlocal answers, decisions
        answers = iter(passwords)
        decisions = iter(retry_answers)
        pm.main()
        assert len(roots) == 1
        assert next(answers, None) is None, "Unused credential answer"
        assert next(decisions, None) is None, "Unused retry decision"
        return roots[0], prompts, retries, loops

    yield run

    for root in roots:
        if not _destroyed(root):
            root.destroy()


def _assert_responsive_app(root, loops):
    assert loops == [root]
    assert root.winfo_exists() == 1
    assert root.state() == "normal"
    notebooks = [widget for widget in _widgets(root) if isinstance(widget, ttk.Notebook)]
    assert len(notebooks) == 1
    assert len(notebooks[0].tabs()) == 6
    assert sum(isinstance(widget, ttk.Treeview) for widget in _widgets(root)) == 5

    clear_buttons = [
        widget for widget in _widgets(root)
        if isinstance(widget, ttk.Button) and widget.cget("text") == "Clear"
    ]
    assert len(clear_buttons) == 4
    entries = [widget for widget in _widgets(root) if isinstance(widget, ttk.Entry)]
    assert entries
    entries[0].insert(0, "synthetic-clear-sentinel")
    assert entries[0].get() == "synthetic-clear-sentinel"
    clear_buttons[0].invoke()
    assert entries[0].get() == ""

    fired = []
    root.after(0, lambda: fired.append(True))
    root.update()
    assert fired == [True]


def test_first_time_mismatch_retry_builds_responsive_app(startup, tmp_path):
    if startup is None:
        return
    vault = tmp_path / "json_files" / "password_data.vault"
    marker = tmp_path / ".password-vault-initialized"
    assert not vault.exists() and not marker.exists()

    root, prompts, retries, loops = startup(
        [MASTER, WRONG, MASTER, MASTER], [True]
    )

    assert prompts == [
        "Create Master Password", "Confirm Master Password",
        "Create Master Password", "Confirm Master Password",
    ]
    assert retries == ["Password Mismatch"]
    assert vault.is_file() and marker.is_file()
    assert pm.StorageManager(MASTER).fetch_records("password_book") == []
    _assert_responsive_app(root, loops)


def test_existing_wrong_password_retry_preserves_vault_and_opens_app(startup, tmp_path):
    if startup is None:
        return
    storage = pm.StorageManager(MASTER)
    vault = tmp_path / "json_files" / "password_data.vault"
    marker = tmp_path / ".password-vault-initialized"
    before = vault.read_bytes()
    marker_before = marker.read_bytes()

    root, prompts, retries, loops = startup([WRONG, MASTER], [True])

    assert prompts == ["Unlock Vault", "Unlock Vault"]
    assert retries == ["Vault Locked"]
    assert vault.read_bytes() == before
    assert marker.read_bytes() == marker_before
    assert storage.fetch_records("password_book") == []
    _assert_responsive_app(root, loops)


def test_existing_wrong_password_cancel_preserves_vault_and_closes_root(startup, tmp_path):
    if startup is None:
        return
    pm.StorageManager(MASTER)
    vault = tmp_path / "json_files" / "password_data.vault"
    marker = tmp_path / ".password-vault-initialized"
    before = vault.read_bytes()
    marker_before = marker.read_bytes()

    root, prompts, retries, loops = startup([WRONG], [False])

    assert prompts == ["Unlock Vault"]
    assert retries == ["Vault Locked"]
    assert loops == []
    assert _destroyed(root)
    assert vault.read_bytes() == before
    assert marker.read_bytes() == marker_before
    assert pm.StorageManager(MASTER).fetch_records("password_book") == []
