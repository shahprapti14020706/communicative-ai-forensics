"""SQLite schema foundation. No evidence or sample data is inserted."""

import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "forensics.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 user_id TEXT PRIMARY KEY, username TEXT NOT NULL COLLATE NOCASE UNIQUE,
 password_hash BLOB NOT NULL, password_salt BLOB NOT NULL, password_iterations INTEGER NOT NULL CHECK(password_iterations>=600000),
 role TEXT NOT NULL CHECK(role IN ('Administrator','Investigator','Reviewer')),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)), failed_attempts INTEGER NOT NULL DEFAULT 0,
 locked_until_utc TEXT, created_at_utc TEXT NOT NULL, updated_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id),
 login_time_utc TEXT NOT NULL, last_activity_utc TEXT NOT NULL, logout_time_utc TEXT,
 status TEXT NOT NULL CHECK(status IN ('active','logged_out','expired','revoked'))
);
CREATE TABLE IF NOT EXISTS case_assignments (
 assignment_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(case_id),
 user_id TEXT NOT NULL REFERENCES users(user_id), assigned_by TEXT NOT NULL REFERENCES users(user_id),
 assigned_at_utc TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 UNIQUE(case_id,user_id)
);
CREATE TABLE IF NOT EXISTS deletion_jobs (
 job_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, requested_by TEXT NOT NULL REFERENCES users(user_id),
 status TEXT NOT NULL CHECK(status IN ('pending','completed')), created_at_utc TEXT NOT NULL, completed_at_utc TEXT
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY NOT NULL,
    title TEXT NOT NULL,
    investigator_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    evidence_source TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'open', 'under_review', 'closed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    original_filename TEXT NOT NULL,
    storage_path TEXT,
    sha256 TEXT CHECK (sha256 IS NULL OR
        (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*')),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'stored', 'analysed', 'reviewed', 'failed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS analysis_results (
    analysis_id TEXT PRIMARY KEY NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    rule_version TEXT,
    findings_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'completed', 'failed', 'superseded')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS investigator_decisions (
    decision_id TEXT PRIMARY KEY NOT NULL,
    analysis_id TEXT NOT NULL REFERENCES analysis_results(analysis_id) ON DELETE RESTRICT,
    investigator_name TEXT NOT NULL,
    decision TEXT NOT NULL
        CHECK (decision IN ('approve', 'reject', 'modify', 'reanalyse')),
    rationale TEXT NOT NULL DEFAULT '',
    revised_finding TEXT,
    status TEXT NOT NULL DEFAULT 'recorded'
        CHECK (status IN ('recorded', 'superseded')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id INTEGER PRIMARY KEY,
    case_id TEXT REFERENCES cases(case_id) ON DELETE RESTRICT,
    evidence_id TEXT REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'success'
        CHECK (status IN ('success', 'failure', 'pending')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence ON analysis_results(evidence_id);
CREATE INDEX IF NOT EXISTS idx_decisions_analysis ON investigator_decisions(analysis_id);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_logs(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_evidence ON audit_logs(evidence_id);
CREATE TABLE IF NOT EXISTS qa_interactions (
    interaction_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    analysis_id TEXT REFERENCES analysis_results(analysis_id) ON DELETE RESTRICT,
    investigator_name TEXT NOT NULL,
    masked_question TEXT NOT NULL,
    intent TEXT NOT NULL,
    masked_response TEXT NOT NULL,
    evidence_references_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL CHECK(status IN ('completed','unsupported','insufficient','refused','clarification')),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_qa_scope ON qa_interactions(case_id,evidence_id,created_at);
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    analysis_id TEXT NOT NULL REFERENCES analysis_results(analysis_id) ON DELETE RESTRICT,
    decision_id TEXT NOT NULL REFERENCES investigator_decisions(decision_id) ON DELETE RESTRICT,
    report_version INTEGER NOT NULL CHECK(report_version > 0),
    html_path TEXT NOT NULL,
    json_path TEXT NOT NULL,
    report_sha256 TEXT NOT NULL,
    json_sha256 TEXT NOT NULL,
    source_evidence_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status = 'generated'),
    created_at_utc TEXT NOT NULL,
    supersedes_report_id TEXT REFERENCES reports(report_id) ON DELETE RESTRICT,
    masked_version_reason TEXT NOT NULL DEFAULT '',
    UNIQUE(decision_id, report_version)
);
CREATE INDEX IF NOT EXISTS idx_reports_scope ON reports(case_id,evidence_id,analysis_id,decision_id);
CREATE TRIGGER IF NOT EXISTS reports_no_update BEFORE UPDATE ON reports
BEGIN SELECT RAISE(ABORT, 'Reports are append-only'); END;
CREATE TRIGGER IF NOT EXISTS reports_no_delete BEFORE DELETE ON reports
BEGIN SELECT RAISE(ABORT, 'Reports are append-only'); END;
"""


def connect_database(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a connection with foreign keys enabled; caller must close it."""
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.execute("PRAGMA foreign_keys = ON")
    connection.create_function('case_deletion_allowed', 1, lambda case_id: 0)
    return connection


def initialize_database(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """Create empty tables idempotently. Existing records are left unchanged."""
    connection = connect_database(db_path)
    try:
        with connection:
            connection.executescript(SCHEMA)
            # Serialize additive migrations across simultaneous first page loads.
            connection.execute('BEGIN IMMEDIATE')
            user_columns = {row[1] for row in connection.execute('PRAGMA table_info(users)')}
            if 'display_name' not in user_columns:
                connection.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
            case_columns = {row[1] for row in connection.execute('PRAGMA table_info(cases)')}
            for name, kind in [
                ('workflow_status', "TEXT NOT NULL DEFAULT 'Open'"), ('archived_at_utc', 'TEXT'),
                ('archived_by', 'TEXT REFERENCES users(user_id)'), ('deletion_requested_at_utc', 'TEXT'),
                ('deletion_requested_by', 'TEXT REFERENCES users(user_id)')]:
                if name not in case_columns:
                    connection.execute(f'ALTER TABLE cases ADD COLUMN {name} {kind}')
            columns = {row[1] for row in connection.execute('PRAGMA table_info(evidence)')}
            for name, kind in [('file_size', 'INTEGER'), ('working_path', 'TEXT')]:
                if name not in columns:
                    connection.execute(f'ALTER TABLE evidence ADD COLUMN {name} {kind}')
            connection.execute('CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256)')
            analysis_columns = {row[1] for row in connection.execute('PRAGMA table_info(analysis_results)')}
            additions = [
                ('case_id', 'TEXT REFERENCES cases(case_id) ON DELETE RESTRICT'),
                ('classification', 'TEXT'), ('risk_score', 'INTEGER CHECK(risk_score BETWEEN 0 AND 100)'),
                ('risk_level', 'TEXT'), ('engine_version', 'TEXT'),
                ('missing_information_json', 'TEXT'), ('recommended_verification_json', 'TEXT'),
                ('analysis_timestamp', 'TEXT'), ('analysis_version', 'INTEGER'),
            ]
            for name, kind in additions:
                if name not in analysis_columns:
                    connection.execute(f'ALTER TABLE analysis_results ADD COLUMN {name} {kind}')
            connection.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_analysis_version '
                               'ON analysis_results(evidence_id, analysis_version)')
            decision_columns = {row[1] for row in connection.execute('PRAGMA table_info(investigator_decisions)')}
            for name, kind in [
                ('case_id', 'TEXT REFERENCES cases(case_id)'),
                ('evidence_id', 'TEXT REFERENCES evidence(evidence_id)'),
                ('decision_version', 'INTEGER'), ('decision_type', 'TEXT'),
                ('automated_classification', 'TEXT'), ('automated_risk_score', 'INTEGER'),
                ('final_classification', 'TEXT'), ('masked_verification_notes', 'TEXT'),
                ('requested_actions', 'TEXT'), ('integrity_status', 'TEXT'),
                ('evidence_sha256', 'TEXT'), ('created_at_utc', 'TEXT'),
                ('supersedes_decision_id', 'TEXT REFERENCES investigator_decisions(decision_id)'),
                ('masked_version_reason', 'TEXT'), ('masked_change_reason', 'TEXT'),
                ('masked_decision_reason', "TEXT NOT NULL DEFAULT ''"),
            ]:
                if name not in decision_columns:
                    connection.execute(f'ALTER TABLE investigator_decisions ADD COLUMN {name} {kind}')
            connection.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_decision_version '
                               'ON investigator_decisions(analysis_id,decision_version)')
            connection.execute('''CREATE TRIGGER IF NOT EXISTS decisions_no_update
                BEFORE UPDATE ON investigator_decisions
                BEGIN SELECT RAISE(ABORT, 'Human decisions are append-only'); END''')
            connection.execute('''CREATE TRIGGER IF NOT EXISTS decisions_no_delete
                BEFORE DELETE ON investigator_decisions
                BEGIN SELECT RAISE(ABORT, 'Human decisions are append-only'); END''')
            # Only a validated deletion service connection can enable this narrowly
            # scoped exception. Ordinary connections always return 0.
            for name, table, scope in [
                ('decisions_no_delete', 'investigator_decisions',
                 '(SELECT e.case_id FROM analysis_results a JOIN evidence e USING(evidence_id) WHERE a.analysis_id=OLD.analysis_id)'),
                ('reports_no_delete', 'reports', 'OLD.case_id')]:
                sql = connection.execute('SELECT sql FROM sqlite_master WHERE name=?', (name,)).fetchone()[0]
                if 'case_deletion_allowed' not in sql:
                    connection.execute(f'DROP TRIGGER {name}')
                    connection.execute(f'''CREATE TRIGGER {name} BEFORE DELETE ON {table}
                        WHEN case_deletion_allowed({scope}) != 1
                        BEGIN SELECT RAISE(ABORT, 'Records are append-only'); END''')
    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()
    print(f"Database schema initialized: {DEFAULT_DB_PATH}")
