# Step 1?7 implementation reference

Historical implementation details; use README.md for current startup and presentation instructions.

﻿# Communicative AI Digital Forensics Assistant

A local Streamlit academic proof-of-concept for registering email evidence and
reviewing a masked working representation. The existing navigation, styling,
SQLite tables and localhost security configuration are retained.

## Current scope

New Investigation requires a case title, investigator, description, source,
authorization and an evidence file. Registration creates `CASE-YYYYMMDD-XXXX`
and `EVD-YYYYMMDD-XXXX` identifiers using UTC dates and random hexadecimal suffixes.
It hashes the original bytes before parsing, checks for an existing hash, preserves
original bytes read-only, saves masked JSON and records custody events in SQLite.
A duplicate shows the existing identifiers and can be cancelled or opened; it
never creates another case or copy. For CSV, choose one usable data row before
registration. The hash identifies the entire CSV file, so a different row of the
same CSV is still a duplicate in this release.

Evidence Analysis shows identifiers, filename, hash, size, UTC upload time,
integrity, masked headers/body, non-clickable URLs, attachment metadata and parser
warnings. It checks integrity on viewing; **Verify Integrity Again** also records
an explicit recheck event. The Audit Log shows the active case and unassigned
validation events (latest 500). Active identifiers are kept in Streamlit session
state. Case Management provides browsing, search and opening of assigned cases.

Local authentication is required on every page and at service entry points. Local
rule-based phishing analysis is available after an integrity check. Ask the
Evidence provides deterministic local Q&A over the selected masked representation
and analysis version. Human verification and offline HTML/JSON forensic reports
are available in Steps 5 and 6.

## Local storage and schema

- `data/forensics.db`: case/evidence metadata and custody records; no raw email body.
- `data/evidence/<case_id>/<evidence_id>/original.<extension>`: exact original bytes.
- `data/working/<case_id>/<evidence_id>/masked.json`: masked parsed representation.
- `data/reports/<case_id>/<report_id>/`: immutable masked HTML reports and JSON manifests.

The original user filename is metadata only, never a directory component. The
initializer preserves all existing tables and adds only `file_size` and
`working_path` to evidence, plus a SHA-256 index. IDs remain primary keys. Connections
enable foreign keys; writes use parameterized SQL, UTC timestamps and transactions.
An immediate transaction serializes duplicate detection and registration. Files use
atomic replacement in newly created directories, with cleanup on caught failures.
Do not modify originals. Read-only attributes provide accidental-write protection.

Analysis extends the existing `analysis_results` table with case linkage, score,
classification, level, engine version, missing information, recommendations, UTC
analysis time and per-evidence analysis version. The existing `rule_version` column
stores the ruleset version; `findings_json` holds the complete masked result envelope.
Migration is additive and idempotent. Existing rows remain unchanged. A unique index
on evidence/version and a write transaction allocate separate versions on reruns.

## File and parser limits

Only `.eml`, `.txt` and `.csv` are accepted, up to 10 MiB (10 * 1024 * 1024 bytes).
Empty/whitespace-only data, unsafe or redirected paths, unsupported extensions,
recognized executable/script content and traversal patterns are rejected. MIME
payloads are inspected locally for unsafe signatures; attachment contents are never
written, rendered or executed. Conservative validation can reject legitimate evidence
containing traversal strings, scripts or binary attachment data.

Parsing limits: headers/URLs/attachment names 2,000 characters, body 100,000
characters, 100 URLs, 50 attachment metadata entries, 200 MIME parts, 500 CSV data
rows and 50 CSV columns. CSV uses the standard library field-size limit. A CSV needs
at least one nonempty `body`, `message`, `text`, `content` or `subject` value; common
sender/recipient/date columns are also recognized. Excessive columns, malformed
rows, oversized CSV fields or MIME structures are rejected. Analysis truncation and
CSV preview row limits are explicitly recorded. Originals always remain complete.
HTML is converted to text without loading images or following links.

## Privacy and security limitations

- No external AI service, URL retrieval or evidence-related network operation.
  Evidence stays on the local server. Uploaded text is displayed as code/plain text,
  never unsafe HTML. Only the existing developer-owned styling uses HTML.
- Stable masking covers common email, phone, IPv4, card-like, Aadhaar-like and PAN-like
  formats, plus obvious personal URL query values. It is heuristic: it can miss
  unusual identifiers, names, encoded data and indirect personal information, and
  can over-mask innocent numbers. It is not anonymization. Mapping values are never
  persisted. Original filenames and investigator/case context remain metadata.
- Executable detection is conservative pattern/signature checking, not antivirus or
  proof that content is harmless. Standard-library MIME parsing happens in-process,
  with a 10 MiB upload cap and structural limits, not an OS isolation sandbox.
- Originals, SQLite and working JSON are not encrypted. Step 7 adds local authentication
  and application-level case deletion, but not a tamper-proof audit log or protection against a malicious local
  administrator. Use synthetic evidence for evaluation and OS access controls.
- Atomic file writes and a database transaction cannot form one crash-atomic unit:
  abrupt process/power failure can leave orphaned files requiring manual review.
  Caught registration failures are rolled back and their files removed.
- The existing Streamlit configuration binds to `127.0.0.1`, disables usage telemetry,
  enables CORS/XSRF protection and limits uploads. Do not expose this prototype remotely.

## Run on Windows

From the project directory, using the existing environment (no new dependency is
required for this stage):

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open `http://127.0.0.1:8501`. Stop with Ctrl+C. Streamlit is the only direct
third-party dependency. Application initialization creates the database when needed;
you can also initialize it idempotently:

```powershell
.\.venv\Scripts\python.exe -m modules.database
```

## Verification

```powershell
.\.venv\Scripts\python.exe -m compileall -q app.py modules pages tests
.\.venv\Scripts\python.exe -m unittest discover -v
```

Tests generate synthetic evidence in automatically cleaned temporary directories,
including Streamlit intake/CSV-selection/analysis interaction tests. They check
hashes, original byte preservation, masked JSON, unsafe uploads, MIME/text/CSV/HTML
parsing, parser limits, duplicate detection, database/custody records, rollback,
path containment, and both passing and failing integrity checks. Network entry points
are blocked in the evidence workflow test. No sample evidence is installed in
production data directories. The uploader is substituted with synthetic bytes in
Streamlit tests; these are not browser upload transport tests.

## Academic limitation

This system is an academic proof-of-concept. It provides AI-assisted investigative
leads and is not an operational forensic tool. Final conclusions must be verified
by a qualified human investigator.

## Transparent phishing rules (engine 1.0.0 / ruleset 1.0.0)

Every result states: **This automated result is an investigative lead and requires
human verification.** The UI labels the score: **Rule-based risk score — not a
probability of phishing.** It is neither model confidence nor a safety guarantee.

| Rule | Severity | Points |
| --- | --- | ---: |
| Urgent/threatening language | Medium | 10 |
| Credential request | High | 20 |
| Financial request | Medium | 10 |
| Raw IP URL | High | 15 |
| Shortener / punycode (each) | Medium | 8 |
| Long URL (over 200 characters) | Low | 4 |
| Excessive hostname labels (more than five) | Medium | 6 |
| HTTP / unusual port (each) | Low | 4 |
| URL authority contains @ | High | 15 |
| Suspicious URL file extension | High | 12 |
| Multiple unrelated URL domains | Low | 4 |
| From/Reply-To domain mismatch | Medium | 10 |
| Mapped organization/sender mismatch | High | 15 |
| Displayed/destination domain mismatch | High | 15 |
| Suspicious attachment metadata | High | 20 |
| Malformed or institution-claiming free-mail sender | Medium | 8 |
| Reported authentication failure (grouped SPF/DKIM/DMARC) | High | 18 |
| Impersonation language | Medium | 8 |
| Excessive capitalization/punctuation (one grouped rule) | Low | 4 |
| Secrecy/procedure-bypass request | High | 15 |
| Prompt-injection-like language | High | 20 |

Each rule scores at most once per analysis, regardless of repetitions, number of
matching URLs or attachment count. Related but distinct URL traits can coexist.
Authentication failures contribute once across mechanisms. Sender anomalies are
also grouped. The score is `min(100, sum(rule contributions))`; the result retains
the uncapped sum and the exact calculation. Individual finding contributions remain
the documented rule weights, so they can sum above the capped score.

| Score | Classification | Risk level |
| --- | --- | --- |
| 0–24 | No Significant Indicators Detected | Low |
| 25–49 | Uncertain | Medium |
| 50–100 | Suspicious | High |

Missing sender/Reply-To/authentication/attachments, incomplete CSV or text metadata,
missing link pairs and truncation are disclosed without increasing the score.
A present but malformed sender is a distinct, explicitly weighted rule. Each finding
contains source, severity, contribution, a masked snippet of at most 260 characters,
plain-language explanation and independent manual-verification advice.

Analysis reads at most 10 MiB plus one sentinel byte and hashes that same buffer
before parsing; changed, missing or redirected originals block analysis and generate
a refusal audit event. It reparses verified original bytes in transient memory to
check domains and IPs hidden by preview masking; raw content is never persisted in
analysis records. CSV uses the registered working representation's selected row.
The analysis never interprets evidence instructions or modifies original/working
files. Existing working copies do not need regeneration to obtain new MIME metadata.

Additional bounded parser metadata includes up to 100 displayed/destination HTML
link pairs (2,000 characters per field) and 20 authentication headers (2,000
characters each). The engine independently bounds body, header, URL, attachment and
link inputs. It inspects attachment metadata only; original upload rejection rules
remain unchanged, so executable attachments normally cannot reach analysis through
intake. Masking uses bounded mailbox matching to prevent slow scans of long strings.

Use **Run Phishing Analysis**, then **Run New Analysis Version**. Each successful
run creates an append-only analysis record. The history selector shows the latest
100 versions; older records remain in SQLite. Viewing, requests, reruns, integrity
checks/refusals, completion, versions, scores/classifications and rule-processing
errors are audited with safe metadata. Historic results remain visible if current
integrity fails, with a warning; no new result is generated on failure.

### Rule limitations

- Phrases can appear in legitimate, quoted or training material. Keyword matching
  lacks semantic understanding and can miss paraphrases or non-English messages.
- Authentication headers are reported, potentially forged values. No DNS, redirect,
  reputation, ownership, SPF signature or DKIM cryptographic checks are performed.
  Reported passes do not lower the score or establish a verified sender.
- Organization matching is intentionally limited to explicit fictional mappings
  (`Example Bank` → `bank.example.test`; `Example Research Group` → `example.org`).
  Other organization ownership is unavailable. A mention can be quotation rather
  than a claim. Free-mail and shortener lists are static examples, not exhaustive.
  `mail.test` and `short.test` are reserved-domain demonstration fixtures.
- Domain comparisons use exact hostnames and direct parent/subdomain relationships,
  not a public-suffix or domain-ownership database. Unrelated-host scoring is weak
  and can flag legitimate multi-service emails. Displayed-link comparisons only
  apply when the visible text itself resembles a domain or HTTP(S) URL.
- “Unusual port” means other than 80/443; heavy capitalization means over 75% uppercase
  among at least 20 alphabetic characters; excessive punctuation means four or more
  consecutive exclamation/question marks. Thresholds are heuristics.
- Existing masking, storage, in-process parsing and local-administrator limitations
  above still apply. CSV row-selection metadata and audit storage are not tamper-proof.

### Fictional sample results

All fixtures under `samples/` use reserved domains or documentation-only addresses.
These files contain no actual people, companies or credentials and are safe to commit.
They are not installed in production evidence storage.

| Sample | Classification | Score |
| --- | --- | ---: |
| legitimate_meeting.eml | No Significant Indicators Detected | 0 |
| obvious_phishing.eml | Suspicious | 100 |
| uncertain_invoice.eml | Uncertain | 32 |
| prompt_injection_phishing.eml | Suspicious | 54 |
| missing_headers.txt | No Significant Indicators Detected | 0 |

The automated suite runs all samples in temporary storage while blocking network,
DNS, URL-opening and subprocess entry points. It verifies unchanged read-only
originals, masked result persistence, prior-version retention, integrity refusal,
custody events, scoring thresholds, all rule families and the existing workflow.

## Ask the Evidence: controlled local Q&A

This component is a deterministic intent matcher and template-based answer builder,
not a generative language model. It uses no external AI API, cloud service, search,
DNS lookup, URL request or command execution. `modules/qa_engine.py` documents the
normalized phrase/regex groups; `modules/qa_service.py` controls retrieval and storage.

Supported topics include sender, recipient, subject, date, Reply-To, concise summary,
classification, score/level, explanations and supporting findings, suspicious words,
URLs/counts, attachments/names, password/OTP/login wording, payment, urgency,
sender/Reply-To mismatch, authentication and missing metadata, prompt-injection
wording, masking categories, manual checks, limitations, recorded integrity, hash,
case/evidence identifiers, analysis version and unavailable information. Ordinary
variations such as “Who is the sender?”, “Explain the result”, “Are there any dangerous
links?” and “Can I trust this email?” are recognized. Ambiguous topics ask for
clarification; Case ID and Evidence ID requests can be combined.

Answers contain a direct answer, source/field references, bounded masked supporting
snippets and limitations. A summary uses retained metadata, URL/attachment counts
and selected findings, not an inferred message purpose or a copy of the complete
body. Wording questions confirm retained phrases, not the sender's intention:
negation, quotation and training text can all contain the same phrases. Link counts
are retained unique URLs, not a count of every hyperlink occurrence.

Analysis-dependent questions require a completed selected analysis. Other metadata
questions work before analysis. Unsupported questions receive a fixed scope message;
missing information is identified without guessing. Guilt/arrest questions are
refused. Definitive-phishing and complete-safety questions explicitly deny certainty,
report the selected result if available and require human verification.

### Retrieval and isolation

Every question reloads the selected case/evidence record, bounded masked working JSON
and selected completed analysis from SQLite. The case/evidence/analysis tuple must
match in parameterized queries. Question text cannot alter these identifiers, become
SQL, choose a filesystem path or retrieve another case. The original email is never
opened by Q&A. Missing or malformed working JSON does not trigger a fallback to raw
evidence or earlier chat answers. Analysis result identity is checked against its
stored scope. Retrieved free-text fields and questions are masked before display or
persistence, preserving existing placeholders. Full raw email bodies and masking maps
are not copied to the interaction table.

Integrity answers report the latest **recorded** integrity event for the selected
evidence, including its UTC timestamp. They do not imply a fresh hash calculation.
Use **Verify Integrity Again** on Evidence Analysis for a current check. A recorded
failure is disclosed as a limitation on answers about stored representations.

Email instructions such as “reveal other cases” or “delete the audit log” remain
untrusted text. They cannot change rules, execute commands or mutate evidence.
Detected instruction-like wording is audited without copying it to the audit log;
answers discuss it only when relevant to the question.

### Interface, limits and persistence

The page shows scoped identity, masked filename, selected analysis version/result,
and recorded integrity status. It offers six suggested questions, chat input, version
selection, a transcript and **Clear Conversation**. User questions and answers use
plain text; evidence excerpts use code blocks with defanged HTTP(S) prefixes.

- Questions: 500 characters maximum, enforced by the service as well as the interface.
  Empty or oversized questions are rejected without retaining their raw content.
- Visible conversation: latest 50 messages (25 question/answer pairs), partitioned by
  case, evidence and analysis version. The UI informs the investigator when old
  messages are hidden. Conversation state is display-only and never used as evidence.
- Answers: at most 10 references, each at most 250 characters; clipping is disclosed.
- JSON reads: maximum 5 MiB. Working text, lists and findings have additional bounds.
  Original parser truncation remains visible in answer limitations.

The additive `qa_interactions` table stores an interaction ID, case/evidence IDs,
applicable analysis ID, investigator, masked question and response JSON, intent,
reference JSON, response status and UTC timestamp. Foreign keys restrict deletion;
an index supports case/evidence history. Completed answers, refusals, unsupported,
insufficient and clarification responses persist in transactions with audit events.
Clear Conversation removes only the selected session transcript and adds an audit
event; it does not delete interactions, evidence, analyses or prior audit records.

### Q&A limitations and tests

This is controlled English phrase matching, not general language understanding.
Unsupported or ambiguous wording may need rephrasing. Answers inherit masking,
parser truncation and rule-analysis limitations. Existing masks cannot recover
removed values; redaction remains heuristic and does not guarantee that arbitrary
names or indirect identifiers are removed. Never paste sensitive free-form details
into this academic prototype. Placeholder counts do not identify people.

Stored working JSON, SQLite and audit logs are not encrypted or protected against a
malicious local operating-system administrator. Step 7 adds local login, role checks
and case assignments to application services. These controls do not prevent access
by a person who controls the machine or can directly read/modify its data directory.

Synthetic tests cover all 37 requested question types, wording variations, source
references, analysis-version selection, missing data, high-risk refusals, prompt
injection, SQL injection, arbitrary-file requests, cross-case isolation, masking,
interaction/audit persistence, limits and Streamlit conversation clearing. The six
suggested questions run against `obvious_phishing.eml` in temporary storage with
original-file reads, network/DNS/URL entry points and subprocess execution blocked.
No Q&A fixture is installed into production data directories.

## Step 5: Human Verification

Open **Human Verification**, select an active case, evidence and a completed analysis
version, review the fresh integrity result, automated findings, masked supporting
excerpts and limitations, then record a decision. Approve accepts the automated
classification; reject records no final classification; modify requires a different
classification and explanation; request further analysis records a pending status
and selected manual actions. No requested action is automatically executed.

The name, at least 20 characters of notes, and review confirmation are required.
Submission repeats the integrity check and validates the case/evidence/analysis
relationship in the service. Closed cases cannot receive decisions. A failed hash
check blocks recording. Previous decisions appear before the form; creating another
version requires a reason and links the new row to the previous decision. A stale
review must reload the latest decision before submitting. Automated results are
never updated by this workflow.

The existing `investigator_decisions` table is extended additively with scope IDs,
decision version/type, automated classification/score snapshots, human classification,
masked notes/reasons, JSON requests, integrity/hash, UTC ISO 8601 timestamp and
supersession link. Existing columns and rows remain intact. A unique analysis/version
index and SQLite UPDATE/DELETE rejection triggers protect append-only history.
Legacy decisions remain visible and can be superseded without alteration.

Step 5 applies the existing identifier masker, followed by a conservative review-word
allowlist to free text. Unrecognized words/numbers become `[PRIVATE]`; this removes
useful context as well as names. Investigator names are required as input but are
stored as generated masked identifiers, without a reversible mapping. The workflow
does not authenticate the investigator or provide identity attribution across
decisions. Displayed excerpts are restricted to masked analysis snippets, never the
original message body. Notes and excerpts are rendered as plain text. Local files
and the database remain subject to the earlier access-control and encryption limits;
masking is not a substitute for using authorized, minimized input.

Audit events contain only identifiers and status information, with a masked actor:
`HUMAN_VERIFICATION_OPENED`, `DECISION_RECORDED`, `DECISION_APPROVED`,
`DECISION_REJECTED`, `CONCLUSION_MODIFIED`, `FURTHER_ANALYSIS_REQUESTED`,
`DECISION_VERSION_CREATED`, `DECISION_SUBMISSION_BLOCKED` and
`INTEGRITY_CHECK_BEFORE_DECISION`. Opening/rerunning the review records a fresh check;
invalid service submissions are audited without saving entered text.

The Forensic Report page implements Step 6 as described below. No new packages, models,
external APIs, or network requests are needed. Tests use only synthetic records in
temporary directories, including Streamlit interaction tests and migration tests.

Run from the project directory in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe -m compileall -q app.py modules pages tests
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## Step 6: Local Forensic Reports

Select an active case, evidence, completed analysis and a recorded human-decision
version on **Forensic Report**. The page verifies the original evidence hash and
shows a masked structured preview with separate Automated Result, Human-Verified
Result, Supporting Evidence and Limitations. Generation revalidates the complete
selection and freshly hashes the original evidence immediately before producing
the report. Missing decisions and failed integrity checks block generation.
Legacy decisions without Step 5 integrity/version metadata must be verified again.
A recorded request for further analysis is reportable, but the report states that
the final conclusion is pending. No requested action is automatically performed.

Reports contain ten sections: report information, case information, evidence
information, chain of custody, automated analysis, Ask-the-Evidence summary, human
verification, limitations, final conclusion and report integrity. Conclusions come
only from the selected human decision. Selecting an older decision or analysis
intentionally produces a snapshot of that version, not a claim it is the latest.
Q&A includes only the selected case and evidence; interactions from other analysis
versions of that evidence retain their analysis IDs. Q&A and relevant custody events
are each limited to the latest 1,000 entries, with explicit truncation indicators.

Each report gets a new `RPT-XXXXXXXXXXXX` identifier and files named
`RPT-XXXXXXXXXXXX-vN.html` and `.json`. Files live under
`data/reports/<CASE-ID>/<RPT-ID>/`. The additive `reports` table stores scope IDs,
selected analysis/decision IDs, version, relative artifact paths, HTML and JSON
SHA-256 hashes, source evidence hash, status, UTC ISO 8601 creation time, prior report
link and masked version reason. A unique decision/version constraint and UPDATE /
DELETE rejection triggers preserve report records. New versions require a reason,
link to the preceding report for that decision, and never overwrite earlier files.
Stale concurrent generation requests must first review the latest report version.

HTML is self-contained, black-and-white, printable, and uses escaped values with no
scripts, links, external fonts/images/stylesheets or executable evidence. The preview
uses Streamlit plain text and structured JSON, never unsafe HTML. Download HTML and
open it locally to print as PDF through the browser; no PDF package is installed.
No absolute local paths, raw evidence copies, audit actors/details, credentials or
configuration are exported. Free text uses the existing conservative masking rules;
case title, purpose and original filename are also masked. This can remove useful
context and is not a guarantee of identifying every personal detail.

The SHA-256 of the final HTML bytes is authoritative in the database and JSON
manifest. The HTML explains where that hash is recorded instead of embedding a
self-referential hash. **Verify Report Integrity** recalculates the HTML hash and
reports Pass or Fail. Downloads validate both HTML and JSON hashes; modified or
missing files block downloads. A JSON-only change therefore blocks downloading
even when the HTML integrity check passes. Hashes are not digital signatures and
do not protect against an administrator changing files and database records together.

Files are written atomically inside a newly and exclusively created report directory.
Normal generation failures roll back the database transaction and remove only that
attempt's files; no earlier report or source record is touched. A process crash can
still leave an unregistered report directory because SQLite and the filesystem do
not share a transaction. Unregistered files are never offered as report downloads.

Audit events are `REPORT_PAGE_OPENED`, `REPORT_PREVIEWED`, `REPORT_GENERATED`,
`REPORT_DOWNLOADED`, `REPORT_VERSION_CREATED`, `REPORT_INTEGRITY_CHECKED` and
`REPORT_GENERATION_BLOCKED`. They contain identifiers/status only. Download events
record the user's download-button request, not proof the browser saved the file.
Each report's custody snapshot includes its own generation event; subsequent
downloads and checks remain in the application audit trail without changing the report.

Tests use synthetic evidence and temporary databases/directories for generation,
versioning, masking, escaping, hashes, failure cleanup, isolation and Streamlit UI.
No production report is created by tests. No new packages, external services or
network calls are needed. Step 7 authentication and encryption status are described below.

## Step 7: Local Authentication and Case Management

Create the first administrator from a local PowerShell terminal in the project
directory. There is no default account or password and no registration bypass in
the application. The setup command refuses to run once any account exists.

```powershell
.\.venv\Scripts\python.exe -m modules.auth create-admin
.\.venv\Scripts\python.exe -m streamlit run app.py
```

The command prompts for a username, a hidden password and hidden confirmation.
Usernames use 3–64 letters, numbers, dots, underscores or hyphens and are
case-insensitive. Passwords require 12–1024 characters with uppercase, lowercase,
a number and a non-whitespace special character. Passwords use standard-library
PBKDF2-HMAC-SHA256 with 600,000 iterations, independent 32-byte random salts and
constant-time comparison. Neither hashes nor salts are returned by account-listing
or session helpers. Successful logins issue a new random bearer token; only its
SHA-256 digest is stored as the database session ID. No password or session token
is logged.

Five failed attempts lock an account for 15 minutes. Unknown, disabled, locked and
incorrect-password attempts receive the same failure message and perform a password
hash and constant-time comparison. Sessions expire after 30 minutes without an
application request; each protected service call checks the live session and account.
Logout clears the entire Streamlit session state, including case/evidence selection,
previews, Q&A and report receipts. Password reset and account disabling revoke all
active sessions for that account. The last enabled administrator cannot be disabled.
There is no email recovery service or hidden recovery password: retain a second
administrator account and secure local backups according to your own procedures.

| Role | Allowed operations |
| --- | --- |
| Administrator | All cases and investigation features; users, passwords, assignments, archival, audit review and eligible case deletion |
| Investigator | Assigned cases; registration, analysis, Q&A, human decisions, report generation and downloads |
| Reviewer | Assigned cases; masked evidence/analysis review, human decisions, report viewing and downloads; no upload, analysis execution, Q&A execution, generation or deletion |

Administrators use **User Management** to create users, choose their roles, enable
or disable accounts, reset passwords and activate/deactivate case assignments.
Investigation accounts see only assigned cases. Registration assigns the new case
to its creator. Existing cases initially remain accessible only to administrators
until assigned. Permissions are checked by backend service decorators using stored
sessions and assignments, not UI visibility or a role in Streamlit session state.
The UI also rejects forged/revoked active case and evidence selections before
showing evidence. Duplicate evidence from an inaccessible case does not disclose its
identifiers. Every page has the login gate; navigation appears only after login.

**Case Management** searches accessible case IDs/titles, displays masked titles,
evidence counts and analysis/verification/report availability, and opens a case.
The new `workflow_status` field uses Open, Under Analysis, Awaiting Human
Verification, Verified, Report Generated and Archived. Status derives from the
latest completed analysis and latest decision for each evidence item; the least
complete item determines the case stage. A request for more analysis returns the
case to Under Analysis. A newer analysis invalidates the *current stage*, not earlier
stored decisions or reports. Legacy `status` values remain for schema compatibility.
Administrators archive cases; archival blocks new investigation writes while
preserving existing files and records. Assigned users can still review archived
evidence, and existing report read/download services remain available.

### Deleting an archived case

Only administrators can delete. First archive the case, review the counts of
originals, working copies, analysis, Q&A, decisions, report files and audit records,
then **Mark case for deletion**. The same administrator must enter exactly
`DELETE <CASE-ID>` before the second action is accepted. The application displays:

> Deletion removes the application’s files and database records, but guaranteed physical erasure cannot be assured on modern storage devices.

All database file paths and recursive targets are validated against the application
data root; symlinks, junctions and mismatched case/report locations are rejected.
Only the selected case directories are staged in `data/.deletion/<DEL-ID>/`.
Database deletion respects report/decision version dependencies. Normal connections
retain append-only protections; only the validated deletion connection can enable
the case-specific DELETE exception. No UPDATE exception is provided. SQLite secure
delete is enabled for that transaction, but this is not a physical-erasure guarantee.

If the database transaction fails, staged directories are restored. After commit,
files are removed; a Windows file-lock failure remains as a pending deletion job,
which an administrator can retry in Case Management. Associated case audit records
are removed. A final unassigned `CASE_DELETED` event and minimal deletion job retain
only identifiers/status/timestamps, never evidence contents. Files downloaded or
backed up outside the data root are not removed. A process/power failure during
staging still requires local recovery because SQLite and filesystem renames do not
share an atomic transaction. Retain secured backups before production deletion.

### Database and audit additions

Additive tables: `users`, `sessions`, `case_assignments`, and `deletion_jobs`.
Case columns add workflow status, archive time/actor and deletion-request time/actor.
Unique indexes constrain usernames, sessions and user/case assignments. No existing
analysis, decision or report is rewritten during migration. All application SQL
values are parameterized.

Security events include LOGIN_SUCCESS, LOGIN_FAILURE, ACCOUNT_LOCKED, LOGOUT,
SESSION_EXPIRED, USER_CREATED, USER_DISABLED, USER_ENABLED, PASSWORD_RESET,
CASE_ASSIGNED, CASE_OPENED, CASE_ARCHIVED, CASE_DELETION_REQUESTED, CASE_DELETED,
ACCESS_DENIED and ENCRYPTION_STATUS_CHECKED. New security events contain generated
user/case identifiers and status information only. The administrator audit page omits
legacy free-text actors/details. Authentication secrets, encryption keys, evidence
bodies and verification notes never enter security audit metadata.

### Encryption preparation — disabled in this installation

Inspection found that `cryptography` is **not installed**. No package was installed
automatically. The application displays **Encryption at rest is not configured.**
No custom encryption, persisted encryption key, or automatic migration is present.
Existing evidence and working files remain unchanged. The optional dependency is
listed separately in `requirements-encryption.txt`.

If you later authorize dependency installation, the exact command is:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-encryption.txt
```

For an offline installation, obtain a trusted compatible wheel bundle separately
and use a local wheel directory instead of contacting a package index:

```powershell
.\.venv\Scripts\python.exe -m pip install --no-index --find-links C:\trusted-wheels -r requirements-encryption.txt
```

Key preparation for a future reviewed Fernet implementation can be done entirely
in process memory after that installation:

```powershell
$env:FORENSICS_ENCRYPTION_KEY = & .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode('ascii'))"
```

This captures the key in the current PowerShell environment without printing it or
writing a project file. Protect and back up the key outside the project through an
appropriate local secret store; do not regenerate it after encrypting data. Installing
the dependency or setting this variable alone **does not enable encryption in this
build**. Authenticated encrypted-file support and a reviewed migration command must
be added before encryption is enabled. Originals must continue to be verified by
their original plaintext evidence hashes, independently of encrypted working files.

### Limits and validation

These are local application controls, not an operating-system security boundary.
Use file permissions and trusted local users. There is no TLS/cloud identity,
multi-factor authentication, automatic account recovery, or cryptographic report
signature. Inactivity is checked on the next page/service request, not by a background
timer that blanks an idle browser. Previously downloaded files cannot be revoked.
Step 8 presentation and validation are documented in README.md.

Tests create random synthetic credentials, real authenticated sessions and synthetic
evidence only in temporary databases/directories. Earlier regression tests now enter
those sessions instead of bypassing security. New checks cover lockout, timeout,
role/assignment isolation, unauthenticated pages, archive preservation, deletion
confirmation/containment/rollback/retry, credential secrecy and blocked network
entry points. Run the existing unittest and compileall commands shown above.
