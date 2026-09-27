# Single-user hardening review — proposal for Brandon

This branch starts from `theOrganizedMind/password-manager` at
`276e5c0a668a77234b95e22ce0ea87884fbc04a0`, copied exactly into an
isolated review base before these edits. It is a Windows, one-owner desktop
vault review. It is **not** the separate Azure/multi-user project, a release, or
proof that the app is production-ready.

## Evidence-backed changes

| Finding on the exact base | Proposed change | Reproduction/check |
| --- | --- | --- |
| An export path could be the live vault, or an alias that points to it. A directory alias switched after a path check could still redirect a save into the vault. | Reject obvious aliases and commit backup files with an atomic create-if-absent operation. Existing backup names are refused. | `tests/test_storage.py` checks direct, relative, symlink and hardlink aliases, existing backups, and a directory-alias switch for both export paths. |
| An exception string or traceback could contain a credential and reach a plaintext log. | Record only a fixed operation identifier in plaintext logs, without exception content. Unexpected add/update failures get a generic UI error; selected validation `ValueError` messages still appear in the UI. | `tests/test_adversarial_repairs.py` and `tests/test_ui_security.py` inject synthetic secret markers into the unexpected-failure paths and assert they do not appear in logs or prompts. These tests do not establish that every possible validation message is secret-free. |
| Passwords with meaningful leading/trailing spaces were modified by form/import cleanup. | Preserve the password field byte-for-byte as text; still reject empty or whitespace-only values. | `tests/test_adversarial_repairs.py` checks forms, imports, and whitespace-only refusal. |
| A one-character generator setting could yield a trivially guessable password. A custom word list could appear to have many choices while producing ambiguous, colliding outputs. | Use `secrets`, validate bounded settings and a conservative estimated randomness floor, and require distinct prefix-free rendered word tokens. | `tests/test_password_generator.py` checks weak settings, token collisions, and output formats. Randomness estimates depend on the quality of the configured word list. |
| Two app instances could read the same vault and silently lose one writer's change. A stale selection could edit/delete even after the record changed away and back within one timestamp second. | Lock full local transactions and require a selection-time snapshot with a monotonic per-record revision; migrate earlier encrypted vault records on unlock. | `tests/test_storage_concurrency.py` and `tests/test_vault_concurrency.py` cover competing writers, stale edits/deletes, the A→B→A sequence, and old-vault revision migration. |
| A vanished vault was rejected by an already-running instance but silently re-created as empty on restart. A manual “create empty vault, then import backup” recovery could overwrite newer data after an interruption. | Persist a non-secret initialization marker outside the vault directory. When the vault is missing, validate and restore a complete encrypted backup directly, without an intermediate empty vault. Reject unknown top-level backup fields rather than silently drop data from a future format. | `tests/test_storage_concurrency.py` checks same-instance loss, full-directory loss after restart, partial/unknown-format refusal, existing-vault refusal, and synthetic full-backup recovery. The marker is not tamper-proof; deleting both vault and marker defeats this accidental-loss signal. A visible missing-vault recovery and true power-loss durability remain unproven. |
| A contradictory encrypted backup with both flat `records` and category-keyed data could be accepted through category import. | Reject mixed shapes before either import path writes. Keep legitimate partial-category backups supported. | `tests/test_adversarial_repairs.py` checks rejection without vault change and accepted partial backups. |
| A backup encrypted under another profile's master password could not be imported into an open destination vault. Matching account identities could silently upsert and replace destination passwords. | Accept an optional backup password for category and full imports. Label only selected-backup decryption failures as backup unlock failures. Under the local vault lock, reject any normalized case-insensitive account identity already in the destination or repeated in the batch before one write. | Focused synthetic storage and UI checks passed. Deep reports a current-head person-clicked full-backup and category-import walkthrough on disposable profiles, partially corroborated by screenshots; the attached package does not independently establish every step or on-disk result. No real vault data was used. |

## Why these changes matter

- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) recommends authenticated encryption for stored sensitive data. The existing AES-GCM vault is retained; these edits focus on data-integrity and exposure gaps around it. This vault stores *recoverable credentials for other services*, not a server's own login verifier, so one-way password hashing would not provide the required retrieval behavior.
- [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) says authentication passwords and other primary secrets should not be recorded in logs. Omitting arbitrary exception text is a deliberate tradeoff: the log identifies the failed operation but is less diagnostic.
- [Python's `secrets` documentation](https://docs.python.org/3/library/secrets.html) recommends cryptographically strong randomness for generating passwords; the default `random` generator is not for this purpose. A secure random source does not rescue an undersized or ambiguous output space, hence the settings and word-list checks.
- [MITRE CWE-362](https://cwe.mitre.org/data/definitions/362.html) describes lost integrity when shared state is read and changed without exclusive access. [MITRE CWE-367](https://cwe.mitre.org/data/definitions/367.html) describes check/use races. The lock covers cooperative same-host vault writes; the no-overwrite backup commit closes the demonstrated alias-switch overwrite path. Neither is a defense against someone who controls the Windows account or filesystem.

## Verification boundary and reviewer checklist

Run the pinned dependencies in `requirements.txt` on Windows, then run
`python -m pytest -q --override-ini addopts= --confcutdir=.`. Review the diff
against the pinned base and repeat the synthetic attack cases. Before real use,
perform a headed desktop walkthrough with made-up credentials, a clean backup
and restore on a disposable profile, interruption/power-loss checks, and a
manual review of filesystem permissions and recovery instructions. A test pass
does not establish production readiness. No real passwords or existing vaults
were opened to prepare this review.

### Disposable Windows test record

An independent reviewer tested an archive of the source commit
`33205f02614843f30127dcd5c7d0ec41900655cb` in a disposable Windows
directory with Python 3.13.7 and the pinned `requirements.txt` versions
(including pytest 9.1.1). Python bytecode writes and third-party pytest plugin
autoload were disabled. The reviewer ran the six storage/UI/adversarial/generator
modules with `-q -rs --override-ini addopts= --confcutdir=. -p no:cacheprovider`:

```text
129 passed in 31.89s
exit code: 0
```

The same options applied to `tests/test_vault_crypto.py` produced:

```text
4 passed in 0.85s
exit code: 0
```

These are two test commands, not a single `133 passed` pytest transcript.
Neither summary reported skips. The runs used synthetic data and do not prove
headed UI behavior or true power-loss durability.

A separate verbose run on the same disposable source archive selected the five
symlink/alias cases with `-k 'symlink or guard_alias_swap'`. Its recorded output
was:

```text
tests/test_storage.py::test_export_rejects_live_vault_destination_without_changing_it[symlink-False] PASSED
tests/test_storage.py::test_export_rejects_live_vault_destination_without_changing_it[symlink-True] PASSED
tests/test_storage.py::test_export_does_not_overwrite_vault_after_guard_alias_swap[False] PASSED
tests/test_storage.py::test_export_does_not_overwrite_vault_after_guard_alias_swap[True] PASSED
tests/test_vault_concurrency.py::test_sidecar_symlink_fails_closed_when_supported PASSED
5 passed, 6 deselected in 1.34s
exit code: 0
```

The six deselections were other parameter cases under the three selected test
functions, not skips. This proves execution in the tested Windows environment,
not protection against arbitrary filesystem control.

### Current review-branch verification

The earlier app-code commit is `da23351f55e6ac26a28a03860e65671db977386a`.
The subsequent `555ded63afd219c0c0ade7525415841e372abadf` commit adds tests
without changing app source. The later app-code commit
`2f8f72e8c44c95fba21d22edd1ca5b9a90c2e62d` corrects two recovery
messages in `password_manager.py` and asserts their wording in
`tests/test_ui_security.py`; it does not change vault storage behavior.
On that code, the full command
`python -m pytest -q -ra -p no:cacheprovider` returned `152 passed in 52.95s`
(exit code 0, no skips or failures) using an isolated Python 3.13.7 environment
with Tk 8.6.15. The two focused recovery UI cases returned `2 passed in 1.29s`;
the scripted real-Tk backup smoke module returned `2 passed in 9.73s`.

An independent rerun at review head `1fda4d1341a49dfb471312ce2d971ecadafb1818`
used the existing Windows Python 3.13.7 environment and disposable pytest
temporary directories. It returned `152 passed in 56.23s` (exit code 0, no
reported skips). A separate verbose selection of the five link-safety cases
returned `5 passed, 27 deselected in 1.52s` (exit code 0); each of the two
symlink-destination variants, two alias-swap variants, and the sidecar symlink
case reported `PASSED`. Pytest plugin autoload, bytecode, and the cache provider
were disabled. A Python wrapper suppressed the parent process's application
logger during import; multiprocessing children still appended generic
`storage_backend_selected` entries to the checkout-local log. This is local
test evidence, not a posted GitHub check or a manual native-dialog run.

The suite includes synthetic tests that construct real Tk windows and widgets.
They exercise startup retry/cancel, the Clear button, encrypted backup export
and refusal to replace an existing file, wrong-backup-password cancellation
without changing the destination vault, import between disposable profiles,
masked password display, and reopening the destination with both records
intact.

Some synthetic UI tests invoke the app's buttons while replacing native file,
password, and message dialogs with test doubles. Separately, the current-head
scripted real-Tk rehearsal used real Tk windows and password dialogs while
recording and scripting answers to native Windows dialogs. Neither is a
person-clicked walkthrough. The rehearsal reports five scenarios passed on Tk
8.6.12; its logs and description are included in Deep's evidence ZIP. All test
vault and backup data were synthetic and disposable.

### Current-head Windows/Tk evidence

The following records refer to app code at `2f8f72e8c44c95fba21d22edd1ca5b9a90c2e62d`.
The subsequent PR commits change documentation only; `password_manager.py`
is byte-identical. In his September 26 review, Brandon stated an **initial
intended support range** of Windows 11 with Tk 8.6.12 through 8.6.15 as
bundled with supported CPython installations. This is the owner's proposed
scope, not proof that every version in the range has been directly tested.

| Tk version | Current-head evidence | What remains unverified |
| --- | --- | --- |
| 8.6.12 | Python 3.11.15 on Windows 11 Pro 10.0.26100. Deep reports a person-clicked launch with a new empty vault, tab/list interaction, repeated Clear use, and a one-minute responsiveness observation. The ZIP includes a screenshot of the responsive empty vault. The current-head full suite is also reported as 152 passed, 0 failed, 0 skipped. | The person-clicked walkthrough is first-hand evidence, with only partial screenshot corroboration. The ZIP has no vault files or generated `verify-log.txt`; its `verify.py` is the helper source only. The reported disk-state results and all six workflow steps therefore cannot be independently reproduced from this package. The scripted rehearsal is separate corroboration, not human evidence. |
| 8.6.15 | Python 3.13.7. The current-code automated suite and scripted real-Tk checks are reported passing; the suite result is 152 passed, 0 failed, 0 skipped. Separately, a focused run reports a clean exact `542aad6` HEAD on Windows build 10.0.26200, Python 3.14.2, Tk 8.6.15, isolated venv: 23 passed, 0 failed, 0 skipped across startup retry, scripted real-Tk startup/backup, and selected link tests. On Windows 11 Pro build 26200 with Python 3.14.2/Tk 8.6.15, Bill personally created a new fake master password in a fresh disposable copy whose `password_manager.py` SHA-256 matched the current PR file (`3D868546DCB7604FD32F939D8045762862CDB3DDEC8085B903FC3CE4CA33EF58`). The empty main window opened; he clicked each tab, the empty Password Book list, and Clear, then confirmed Reminders opened normally. A contemporaneous Windows process check reported `Responding=True`, and the test folder contained a newly initialized vault; neither observation independently proves Bill's UI clicks. | This establishes a reported person-clicked current-code empty-vault startup and the specific click sequence, not a full six-step backup walkthrough on Tk 8.6.15. No continuous one-minute human observation or video was collected. The focused run mocked native file, password, and message dialogs. Nick's broader person-clicked report was on an earlier app-code commit. |

Tk 8.6.13 and 8.6.14 are included in Brandon's initial intended range but
have no separately documented person-clicked checks in this PR. The table
records direct observations on 8.6.12 and 8.6.15 only; neither the scripted
tests nor one version's human report establishes another version's behavior.

### Deep's current-head person-clicked walkthrough

Deep reports performing all six requested workflow steps by hand on Tk 8.6.12
and app code at `2f8f72e8c44c95fba21d22edd1ca5b9a90c2e62d` (later PR
commits changed documentation only): full-backup export; import into a fresh
profile with a different destination password; wrong backup password followed
by Retry and a successful import; cancellation without changing the destination; closing and
reopening the destination with its own password and finding the imported
records; and category-only import into another fresh profile with a different
destination password. He reports the order as cancel, wrong password, then the
successful full import, so the destination was not imported twice.

The attached screenshots show the source records, completed full export, real
backup-unlock prompt, and a responsive empty vault. They do not capture every
click, the cancel and wrong-password outcomes, the completed imports, the
reopened destination, or the category-only result. Although the ZIP includes a
read-only verification helper, it contains neither the referenced vault files
nor the helper's generated log. Accordingly, the six results are Deep's
first-hand report with limited attached corroboration; this package does not
independently establish the reported disk hashes or every human step.

The separate scripted rehearsal reports the same workflow passing in five
scenarios using real Tk windows and Tk password dialogs; native Windows dialogs
were recorded and their responses scripted. Its logs are attached. This
corroborates that the scripted sequence and dialog text work, but it is not a
person-clicked run.

### Current-head link-safety test evidence

In his [current-code PR report](https://github.com/theOrganizedMind/password-manager/pull/4#issuecomment-5839509925),
Deep attributes the runs to Windows 11 Pro 10.0.26100, Python 3.11.15,
Tk 8.6.12, a standard account with Developer Mode enabled (symlink privilege
active), and a fresh environment from pinned requirements. The report gives
the targeted command as `pytest -q -rs -k "symlink or alias_swap"` and reports
five passed with zero skips. This is not an independently attached pytest
transcript. Deep's comment reports the full suite as
`152 passed, 0 failed, 0 skipped`; the PR comment does not separately show the
full-suite command, process exit code, or a run-specific environment printout.
These are attributed results, not a hosted CI check. On a standard
Windows account without symlink privilege, the five targeted cases skip with
WinError 1314; they are skips, not passes. This evidence verifies the tested
defenses only, not protection against arbitrary control of the Windows account
or filesystem.

### Bill's focused recovery-message walkthrough

Bill manually launched a byte-identical disposable copy of the patched app.
The remnant warning displayed the isolated vault folder, preservation
instruction, and no-deletion statement. He then tested the missing-vault
prompt, chose No, and the app exited without creating a vault while the
quarantined fake vault and remnant remained. The test setup restored the fake
vault afterward. This walkthrough supports those specific UI outcomes; no Tk
version is attributed to this manual run. The automated tests assert the prompt
wording, displayed folder path and preservation guidance, that the warning text
states its scan scope, and that the matched entry and vault remain unchanged.
The source scans only the live-vault folder; there is no behavioral test of a
matching entry outside that folder. Brandon accepted the PostgreSQL scope
boundary on September 25, provided it remains explicit: the encrypted local
vault is the only supported backend covered here; PostgreSQL stays inactive and
unsupported and its imports are refused; cross-backend stale-write parity is
deferred; and this PR adds no database service or multi-user readiness. His
September 26 review states an initial intended Windows 11/Tk 8.6.12-8.6.15
range, while leaving acceptance of the evidence and any further validation to
his owner-level review. He requested that the PR remain Draft until that review.

### PR check availability and reproducibility limit

For the current PR head, `gh pr checks 4 --repo theOrganizedMind/password-manager`
reported `no checks reported on the 'review/brandon-single-user-pr-2026-09-23'
branch` and exited 1. This branch has no `.github` workflow directory, so no
GitHub Actions Windows/Tk run is attached to the PR. That absence is **not**
equivalent to a reproducible GitHub check or proof of failure. The local
commands, Windows/Python/Tk environments, exit codes where recorded, and
pass/skip counts above are the available local evidence. The exact invocation
and exit code for the separate 23-case focused run are not established by this
review document. Deep's reported local full-suite and symlink-enabled runs
provide commands and summary counts, but their process exit codes and the
referenced vault artifacts are not in the attached package; they must not be
presented as hosted CI results. In the documented local runs, `152 passed` and
Deep's reported `5 passed` mean zero
reported skips; on an account without symlink privilege, those five cases skip
rather than pass.

Residual limits to discuss explicitly: plaintext CSV/XLSX originals remain
after import; clipboard history and process memory can hold secrets; the app
has no idle lock or verified crash/power-loss recovery; the local lock covers
only cooperating same-host app instances; and the manual remnant walkthrough
does not establish physical crash or power-loss durability. A user or other
program with control of the Windows account can bypass these safeguards.

PostgreSQL import remains unsupported and inactive, as accepted by Brandon for
this PR's stated scope. Export dialogs suggest
timestamped names and existing files are not replaced. Startup warns if it
finds entries beside the vault whose names match the `.vault-*.tmp` pattern;
it does not verify that each matched entry is a file or encrypted. The app
leaves those entries in place for manual review. Deep's September 25 current-head
walkthrough report covers the full-backup and category-import sequence, but its
attached evidence remains partial as described above. Nick's person-clicked
report covers a retained temporary file and its warning, but does not establish
physical power-loss recovery. Bill's earlier partial walkthrough reached a
successful full-backup import into a nonempty disposable profile, but he stopped
before a close/reopen persistence check.
Earlier independent settled-code Windows test commands passed 133 cases in
total with none skipped, including the five symlink/alias cases. Two of Nick's
smaller UX notes remain: startup does not scan user-selected backup export
folders for temporary files, and the backup Save picker has no app-provided
default folder.
The picker may initially open in Documents according to Nick's earlier report.
These folder behaviors remain product choices. Neither the tester reports nor
the synthetic tests establish production readiness.

Questions for Brandon: Are these changes aligned with the intended single-user
app? Does he want the stricter backup no-overwrite behavior and the local
revision migration in his mainline? Are there existing user vaults or backup
formats we have not seen that need a separate migration test? A PR should be
reviewed on its merits; this document is not a request to merge sight unseen.
