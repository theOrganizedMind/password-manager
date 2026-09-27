# Password Manager — encrypted local vault (Stage 1)

A Windows desktop password manager built with Python and Tkinter.

This review proposes changes to the original prototype for a first-stage,
single-owner vault. Password records are stored in an encrypted local `.vault`
file protected by a master password. The master password is never saved by the
application.

## What this stage supports

- Password Book, Mobile Devices, Computers, and Admin tabs
- Add, update, delete, search, and 90-day update reminders
- Passwords masked in the table and form until the owner chooses **Show**
- Password generation using Python's cryptographically secure `secrets` module
- Encrypted per-category and full-vault backups using AES-256-GCM and scrypt
- Encrypted backup imports can use the backup's own master password when it
  differs from the currently open vault password. Import refuses any account
  identity already present or repeated in the incoming batch, without changing
  the destination vault.
- A new backup filename is required for every export; existing backups and the
  active vault are never deliberately replaced by the export action
- CSV/XLSX header-only templates for preparing imports
- CSV/XLSX imports as a deliberate one-time migration path

Imported CSV/XLSX files are plaintext source files. Importing them does not
encrypt, move, or erase those originals; handle and retire them separately.

## What this stage does not claim

- This is not yet a multi-user team service.
- There are no team accounts, roles, sharing rules, audit logs, or recovery
  workflow yet.
- PostgreSQL is intentionally not used in this stage because the original
  PostgreSQL schema stores passwords as plaintext. Import into that backend is
  unsupported; the inactive backend is not activated by this review.
- The application cannot protect secrets from someone who controls the Windows
  account, machine, or process running it.
- Same-host Windows instances coordinate vault writes, but this is not a
  network-synchronized vault and the lock does not coordinate other programs.
- Automated tests and a synthetic startup check do not prove the visible
  desktop workflow, backup recovery, or power-loss durability on your PC.
- The running app holds the unlocked master password in process memory. Its
  generator can copy a password to the system clipboard; clipboard history and
  other local programs may retain it. There is no automatic idle lock yet.

Do not call this production-ready for team use until Stage 2 has separately
specified and verified identities, authorization, recovery, auditability,
concurrency, deployment, and operational backup/restore.

## Security rules

- The master password must be at least 12 characters. If it is forgotten, the
  application cannot recover the vault.
- The encrypted vault is `json_files/password_data.vault`.
- The non-secret `.password-vault-initialized` marker is in the app directory,
  outside `json_files`; a persistent `password_data.vault.lock` file is beside
  the vault. Preserve both when moving the app and vault together.
  If a previously initialized vault disappears, the app refuses to create an
  empty replacement; restore a verified backup instead.
- A legacy `json_files/password_data.json` is rejected. It is not silently read
  or converted because it may contain plaintext credentials.
- Password backups must use `.vault`. Plaintext JSON/CSV/XLSX password exports
  are disabled.
- Exports do not overwrite an existing filename. Choose a fresh name for each
  backup, and verify that the saved file can be unlocked before relying on it.
- The export dialog suggests a timestamped filename. If startup finds
  temporary encrypted files beside the vault, it warns you to preserve and
  review them; it does not delete them automatically.
- A selected record must be reloaded if another app window changed it; the app
  refuses a stale edit or deletion instead of silently overwriting that change.
- Empty CSV/XLSX templates are allowed because they contain no credentials.
- Keep vault backups private and test that they can be unlocked before relying
  on them.

If the active vault goes missing, the app deliberately stops instead of making
an empty replacement. Preserve the whole app/vault directory first. On the
next launch, choose **Restore** and select a **full** encrypted backup; enter
the master password used for that backup. The app validates the complete
backup and restores it directly, without first opening an empty vault. A
one-category backup cannot be used for full recovery. Do not move/delete the
initialization marker to bypass this guard. Verify the restored records and
make a new backup. The restore has synthetic automated tests. Nick reports a
person-clicked restore with fake data on a disposable Windows profile; see
`docs/single-user-hardening-review.md` for its scope and limits. That report
does not establish recovery through a physical power failure.

## Installation

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Running

```powershell
python password_manager.py
```

The first run asks the owner to create a master password. Later runs ask to
unlock the existing vault.

## Testing

Run from this repository. The `--confcutdir=.` option prevents an unrelated
parent-folder pytest configuration from being loaded.

```powershell
python -m pytest -q --override-ini addopts= --confcutdir=.
```

## Repository structure

```text
password_manager.py                 # Tkinter UI and encrypted-vault CRUD
password_generator.py               # secure password generation
vault_crypto.py                     # scrypt + AES-GCM vault envelope
tests/                              # focused security and behavior tests
sql_functions/                      # retained source reference; not used in Stage 1
word_list.json                      # public word list for generation
requirements.txt
```

## License

This project is licensed under the MIT License. See `LICENSE.txt`.
