# Communicative AI in Digital Forensics

**A Human-in-the-Loop Framework for Cybercrime Investigation**  
Authors: Prapti Shah and Aayursha Raut

A local Streamlit academic prototype for phishing-email investigation. The research objective is to examine how transparent indicators, evidence-linked explanations and controlled questions can support investigator review while preserving human responsibility for conclusions.

> This application is an academic proof of concept. Its automated findings are investigative leads and must not be treated as legal conclusions.

## Features and workflow

1. **Dashboard:** accessible cases, generated user identifier/role, encryption status, active-case status cards, safe recent events and recommended next action.
2. **New Investigation:** create a case and register one authorized evidence file together; preserve original bytes and calculate SHA-256.
3. **Evidence Analysis:** verify integrity, inspect masked text and run versioned rule-based phishing analysis with evidence-linked explanations.
4. **Ask the Evidence:** deterministic local questions, bounded masked references, supported answers and safe refusal of unsupported/legal conclusions.
5. **Human Verification:** independently approve, reject, modify or request further analysis; retain earlier decision versions.
6. **Forensic Report:** generate masked, escaped, offline HTML and JSON snapshots; hash reports and validate downloads.
7. **Audit Log:** administrator-only safe custody timeline; the dashboard exposes only scoped safe event metadata to other roles.
8. **User and Case Management:** administrator-only accounts, assignments, archival and reviewed deletion. Existing records remain preserved unless an administrator explicitly completes deletion.
9. **About the Prototype:** research objective, workflow, controls, limitations and academic disclaimer.

Dashboard case selection is available to every authenticated role. Direct page URLs do not bypass login, role checks or case assignments. A reviewer may inspect assigned evidence, record decisions and download existing reports; an investigator may also register, analyze, ask questions and generate reports. Only administrators manage users, assignments and deletion.

Progress is derived from records for each evidence item and its latest analysis/decision: Case Created, Evidence Registered, Integrity Verified, Analysis Completed, Evidence Questions Reviewed, Human Decision Recorded and Report Generated. Statuses are Not Started, In Progress, Completed and Blocked. Integrity shows the **last recorded check**, not live continuous monitoring. A supported Q&A interaction for the current analysis counts as review activity, not proof of understanding. New analysis versions require fresh Q&A and human decisions for current progress. Earlier records remain available. A request for further analysis changes the recommended next action.

## Requirements and environment

- Python **3.13 is required**. The tested environment is **Python 3.13.7**; the commands below use Windows PowerShell.
- Use `.venv`. **Do not use `.venv-python314-backup`**; it is an old environment and is retained unchanged.
- Streamlit 1.55.0 and its dependencies; SQLite comes with Python. No AI API, model download or external service is required.
- Local disk space and permissions for `data/`; a browser for local presentation. Evidence uploads are limited to 10 MiB.

For a fresh installation only, create an environment (do not overwrite an existing working environment):

```powershell
cd communicative-ai-forensics
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe --version
```

Install the required packages in the new environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

For a fully offline setup, use a trusted local Python 3.13-compatible wheel bundle containing all dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install --no-index --find-links C:\trusted-wheels -r requirements.txt
```

No packages are installed automatically by the application, helper or tests.

## Administrator and startup

Create the first administrator locally; the command prompts for a username and hidden password/confirmation. There is no default account or password. Initial setup refuses to run once an account exists. Subsequent users are created by an authenticated administrator.

```powershell
.\.venv\Scripts\python.exe -m modules.auth create-admin
```

Start using the tested environment:

```powershell
cd communicative-ai-forensics
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open `http://127.0.0.1:8501`. The server binds to loopback with CORS/XSRF protection and telemetry disabled. Do not expose this academic prototype remotely.

## Synthetic demonstration

Login as an existing administrator, then use this local helper from PowerShell:

```powershell
.\.venv\Scripts\python.exe -m modules.demo_setup
```

The CLI asks for administrator credentials and the exact confirmation `CREATE SYNTHETIC DEMONSTRATION`. It checks the bundled `samples/obvious_phishing.eml` against its reviewed checksum. It creates a new case labelled **SYNTHETIC DEMONSTRATION** using a copy with a random synthetic header. The sample itself is never modified. Each copy has its own hash, avoiding conflicts with already registered evidence without weakening duplicate detection.

The helper creates no user, password, analysis, human decision or report. Select the returned case ID on Dashboard, then complete the workflow yourself. Alternatively, upload an unchanged sample through New Investigation; registering an identical file again opens the existing case rather than creating a duplicate.

Use [the presentation script](docs/PRESENTATION.md) for a 10–15 minute demonstration. Show a supported question, a safely refused conclusion, a human decision, report verification and logout. Never alter original evidence to demonstrate a failure; use the temporary-storage integrity tests.

## Safe demonstration cleanup

```powershell
.\.venv\Scripts\python.exe -m modules.demo_setup cleanup
```

Login as an existing administrator. The command lists exact helper-created case IDs and eligibility, then requires `DELETE DEMO <CASE-ID>` separately for each eligible case. It validates receipt provenance, database records, file hashes and contained paths again under the deletion write lock. A case title alone never authorizes cleanup. No arbitrary path or non-demo case is accepted.

**Cleanup is intentionally limited to unchanged helper intake.** Opening or investigating a case can add audit records or investigator-created work; cleanup then refuses it. Analysis, decisions, reports, changed files and extra files are preserved. Retain completed demonstrations, or use the separately reviewed administrator archive/delete workflow if you later explicitly intend to remove that work. Interrupted or locked-file cleanup is reported and can require administrator review in User and Case Management. Receipt files are not cryptographic proof against a malicious machine administrator.

## Testing and final checks

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe -m compileall -q app.py modules pages tests
.\.venv\Scripts\python.exe -m unittest tests.test_final -v
```

Tests use randomly generated synthetic credentials and evidence in temporary directories. The test package rejects production SQLite connections. The end-to-end test covers administrator login, registration, hashing, integrity, masking, analysis, Q&A/refusal, a human decision, HTML/JSON generation/hashing, audit events, logout and protected pages. Existing suites cover roles, isolation, versioning, parser limits, tampering, rollback, path validation and masking. AppTest checks Streamlit rendering and interactions without browser network transport. Network entry points are blocked in workflow tests. No test fixture belongs in `data/`.

See [validation notes](docs/VALIDATION.md) for the final measured results and security review scope.

## Storage and backup

- `data/forensics.db`: users, hashed credentials, session digests, assignments, case/evidence metadata, analyses, Q&A, decisions, reports and custody events.
- `data/evidence/<case>/<evidence>/`: original read-only evidence bytes. Never edit these files.
- `data/working/<case>/<evidence>/masked.json`: masked parsed representation.
- `data/reports/<case>/<report>/`: separate HTML/JSON report versions.
- `data/demo_setup/`: helper provenance receipts for conservative cleanup.
- `data/.deletion/`: staged, explicitly authorized case deletion and pending cleanup files.

Step 8 requires no schema migration. Existing initialization is additive for earlier installations. **Back up before running any schema migration or upgrading an older database.** Stop Streamlit with Ctrl+C and close all CLI operations so that SQLite and evidence files form a consistent offline copy. Copy the entire data directory, including any SQLite journal/WAL files, to a new protected local destination:

```powershell
$backupRoot = Join-Path $env:USERPROFILE ('Documents\forensics-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $backupRoot -ErrorAction Stop
Copy-Item -LiteralPath .\data -Destination $backupRoot -Recurse -ErrorAction Stop
```

Keep backups outside source control, restrict Windows permissions, and secure them as sensitive data. Restoring requires coordinated restoration of the database and matching files with the application stopped. Never replace only originals or merge unrelated databases. Backups and downloaded reports are not removed by application cleanup.

## Privacy and security

Passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations and random salts. Login lockout follows five failures; idle sessions expire after 30 minutes on the next request. Password reset/disable revokes sessions. Logout clears the full UI state. Authorization uses stored sessions, roles and assignments, not user-supplied session-state roles.

SQL values are parameterized; dynamic table/column names come from developer-owned lists. Storage paths reject traversal and redirected directories. Evidence is rendered as text/code, never unsafe HTML. Only fixed developer CSS uses unsafe HTML. Generated reports escape dynamic values and contain no executable or external resources. Original bytes are hash-checked before analysis, human decisions and reports. Prior decision/report versions are not overwritten.

New audit events suppress entered investigator names; legacy history remains untouched. Dashboard/audit views omit free-text actors and details. Reports apply conservative masking and exclude raw evidence and credential configuration. Regex masking is best effort; synthetic-only demonstration remains necessary.

### Encryption configuration

**Encryption at rest is not configured.** SQLite, originals, working copies and reports remain unencrypted. Installing `requirements-encryption.txt` or setting an environment variable does not enable encryption in this build. No encryption key is embedded or generated by the app. Future encryption needs a separately reviewed migration with backups and secure key handling. Use Windows access controls and appropriate disk encryption outside this prototype.

## Screenshots

Screenshots are not bundled yet. Capture the Dashboard, Evidence Analysis, Ask the Evidence, Human Verification and Forensic Report using only the fictional files in `samples/` and a separate demonstration environment. Review every image for account details, local paths, identifiers and private data before adding it to the repository. Never capture production investigations.

## Publishing and academic-use disclaimer

This project is for academic research and teaching. It is not a validated forensic product, legal advice, or a substitute for qualified investigator review. Use only synthetic data for public demonstrations and follow applicable authorization and evidence-handling requirements for any other use.

Runtime data, databases, credentials, sessions, keys, local backups and test outputs must remain outside Git. Only empty `.gitkeep` markers in `data/evidence/`, `data/working/` and `data/reports/` are intended for publication. Files in `samples/` are fictional fixtures. Ignore rules cannot detect secrets embedded in source: review the complete proposed commit and rerun a secret scan before publishing. Never force-add ignored runtime files.

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 Prapti Shah and Aayursha Raut.

## Known limitations and troubleshooting

- The engine uses transparent English phrase/metadata rules, not a trained AI model. Its score is not phishing probability; false positives and negatives are possible.
- No links or attachment payloads are opened, and no sender, DNS, reputation or legal conclusion is externally verified.
- Masking can miss identifiers or remove useful context. Local administrators can access/alter unencrypted files and SQLite. Hashes are not digital signatures; custody history is not independently tamper-proof.
- Intake currently creates one case with one evidence file; CSV registration selects one row while hashing the complete original file.
- Missing case/evidence/analysis/decision/report: follow Dashboard's next action. Case access requires an administrator assignment. Archived cases permit review, not new investigation writes.
- Missing working copy: Q&A reports insufficient evidence; there is no original-content fallback. Restore a consistent approved backup rather than editing originals.
- Integrity failure: stop processing, preserve the original and investigate the discrepancy. Do not replace a hash to force a pass.
- Expired/revoked session: sign in again. Permission denied: ask the administrator to review role and case assignment.
- Database unavailable: close competing operations, confirm local storage permissions/free space and retry. UI messages omit SQL, internal paths and stack traces.
- Missing/changed synthetic sample: restore the reviewed bundled sample; the helper refuses unexpected content.
- Port already in use: stop the prior Streamlit instance, then restart. Do not switch to the old Python 3.14 environment to resolve dependency issues.
- Streamlit tests may print `missing ScriptRunContext` notices in bare mode; assess the unittest result and failures.

For safe shutdown, finish the current write, logout, then press **Ctrl+C** in the Streamlit terminal. Do not terminate during evidence/report generation or deletion. An abrupt crash can leave orphaned files because SQLite and filesystem operations do not share a crash-atomic transaction; retain them for review.

Detailed Step 1–7 rule weights, parser limits, report structure and historical implementation notes are retained in [IMPLEMENTATION.md](docs/IMPLEMENTATION.md).
