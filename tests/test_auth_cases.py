"""Synthetic credentials only; all databases and files are temporary."""
from contextlib import ExitStack
from datetime import timedelta
from functools import partial
import hashlib
import json
from pathlib import Path
import secrets
import unittest
from unittest.mock import patch
from streamlit.testing.v1 import AppTest

from tests import test_evidence
from modules import auth, case_service, encryption, ui
from modules.database import initialize_database, connect_database
from modules.evidence_handler import get_evidence, register_evidence, ValidationError
from modules.analysis_service import run_analysis, analysis_history
from modules.qa_service import ask, load_context
from modules.verification_service import record_decision, selections, decision_history
from modules.report_generator import generate_report, download_bytes


class AuthenticationTests(unittest.TestCase):
    setUp = test_evidence.StorageTests.setUp
    tearDown = test_evidence.StorageTests.tearDown
    query = test_evidence.StorageTests.query

    def account(self, role='Reviewer'):
        password = secrets.token_urlsafe(18) + 'Aa1!'
        username = 'synthetic_' + secrets.token_hex(4)
        uid = auth.create_user(username, password, role, self.db)
        token = auth.login(username, password, self.db)
        return uid, username, password, token

    def test_password_storage_and_unique_salt(self):
        uid, username, password, token = self.account()
        row = self.query('SELECT password_hash,password_salt,password_iterations FROM users WHERE user_id=?', (uid,))[0]
        self.assertNotEqual(row[0], password.encode())
        self.assertGreaterEqual(row[2], 600000)
        self.assertGreaterEqual(len(row[1]), 16)
        self.assertEqual(row[0], hashlib.pbkdf2_hmac('sha256', password.encode(), row[1], row[2]))
        self.assertEqual(len({r[0] for r in self.query('SELECT password_salt FROM users')}), 2)
        self.assertNotIn(password.encode(), self.db.read_bytes())
        public = auth.list_users(self.db)
        self.assertFalse(any('password' in key or 'salt' in key for row in public for key in row))

    def test_correct_password_and_session_regeneration(self):
        token = auth.login('synthetic_admin', self.synthetic_password, self.db)
        self.assertTrue(token)
        self.assertNotEqual(token, self.token)
        self.assertEqual(auth.current_user(self.db, token)['role'], 'Administrator')
        self.assertNotIn(token, str(self.query('SELECT * FROM sessions')))

    def test_wrong_unknown_and_constant_time_comparison(self):
        original = auth.hmac.compare_digest
        with patch.object(auth.hmac, 'compare_digest', wraps=original) as compare:
            self.assertIsNone(auth.login('synthetic_admin', secrets.token_urlsafe(20), self.db))
            self.assertIsNone(auth.login('unknown_synthetic', secrets.token_urlsafe(20), self.db))
            self.assertEqual(compare.call_count, 2)

    def test_disabled_user_and_revocation(self):
        uid, username, password, token = self.account()
        auth.set_enabled(uid, False, self.db)
        self.assertIsNone(auth.login(username, password, self.db))
        with self.assertRaises(auth.AccessDenied):
            auth.current_user(self.db, token)

    def test_five_failures_and_lock_expiry(self):
        uid, username, password, token = self.account()
        timestamp = auth.now()
        with patch.object(auth, 'now', return_value=timestamp):
            for attempt in range(5):
                self.assertIsNone(auth.login(username, 'incorrect', self.db))
            self.assertIsNone(auth.login(username, password, self.db))
        self.assertEqual(self.query('SELECT failed_attempts FROM users WHERE user_id=?', (uid,))[0][0], 5)
        self.assertTrue(self.query("SELECT 1 FROM audit_logs WHERE action='ACCOUNT_LOCKED'"))
        with patch.object(auth, 'now', return_value=timestamp + timedelta(minutes=16)):
            self.assertTrue(auth.login(username, password, self.db))

    def test_session_timeout(self):
        with patch.object(auth, 'now', return_value=auth.now() + timedelta(minutes=31)):
            with self.assertRaises(auth.AccessDenied):
                auth.current_user(self.db, self.token)
        self.assertTrue(self.query("SELECT 1 FROM audit_logs WHERE action='SESSION_EXPIRED'"))

    def test_logout_clears_all_investigation_state(self):
        state = dict(auth_token=self.token, active_case_id='synthetic', active_evidence_id='synthetic', qa_conversation=['private'])
        auth.logout(self.token, state, self.db)
        self.assertEqual(state, {})
        with self.assertRaises(auth.AccessDenied):
            auth.current_user(self.db, self.token)

    def test_non_admin_cannot_manage_users(self):
        uid, username, password, token = self.account('Investigator')
        with auth.as_session(token):
            for call in (lambda: auth.list_users(self.db), lambda: auth.create_user('another', password, 'Reviewer', self.db),
                         lambda: auth.set_enabled(self.admin_id, False, self.db), lambda: auth.reset_password(self.admin_id, password, self.db)):
                with self.assertRaises(auth.AccessDenied):
                    call()

    def test_reset_password_revokes_sessions(self):
        uid, username, password, token = self.account()
        replacement = secrets.token_urlsafe(18) + 'Bb2!'
        auth.reset_password(uid, replacement, self.db)
        self.assertIsNone(auth.login(username, password, self.db))
        self.assertTrue(auth.login(username, replacement, self.db))
        with self.assertRaises(auth.AccessDenied):
            auth.current_user(self.db, token)

    def test_last_admin_and_password_requirements(self):
        with self.assertRaises(ValueError):
            auth.set_enabled(self.admin_id, False, self.db)
        for password in ('short', 'a'*20, 'A'*20, '1'*20, 'Abcdefgh123456'):
            with self.assertRaises(ValueError):
                auth.create_user('synthetic_invalid', password, 'Reviewer', self.db)

    def test_audit_contains_no_credentials(self):
        uid, username, password, token = self.account()
        auth.set_enabled(uid, False, self.db)
        auth.reset_password(uid, password, self.db)
        rows = str(self.query('SELECT actor,action,details FROM audit_logs'))
        for secret in (password, token, username):
            self.assertNotIn(secret, rows)
        for digest, salt in self.query('SELECT password_hash,password_salt FROM users'):
            self.assertNotIn(digest.hex(), rows)
            self.assertNotIn(salt.hex(), rows)

    def test_first_admin_cli_empty_database(self):
        first_db = self.root / 'first.db'
        initialize_database(first_db)
        password = secrets.token_urlsafe(20) + 'Cc3!'
        with patch('sys.argv', ['auth', 'create-admin']), patch('builtins.input', return_value='synthetic_first'), \
             patch('getpass.getpass', side_effect=[password, password]), \
             patch.object(auth, 'create_first_admin', partial(auth.create_first_admin, db_path=first_db)):
            auth.main()
        self.assertTrue(auth.login('synthetic_first', password, first_db))
        with self.assertRaises(auth.AccessDenied):
            auth.create_first_admin('second_synthetic', password, first_db)

    def test_all_pages_unauthenticated(self):
        for path in [Path('app.py'), *Path('pages').glob('*.py')]:
            with self.subTest(path=path), auth.as_session(None):
                app = AppTest.from_file(str(path)).run()
                self.assertFalse(app.exception)
                self.assertEqual([t.label for t in app.text_input], ['Username','Password'])
                self.assertEqual([b.label for b in app.button], ['Login'])
                self.assertFalse(app.sidebar.button)

    def test_login_page_generic_failure(self):
        with auth.as_session(None):
            app = AppTest.from_file('app.py').run()
            app.text_input[0].set_value('unknown_synthetic')
            app.text_input[1].set_value('incorrect')
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertTrue(any(x.value == auth.FAILURE for x in app.error))

    def test_no_network_and_encryption_disabled(self):
        with ExitStack() as stack:
            for name in ('socket.socket.connect','socket.create_connection','socket.getaddrinfo','urllib.request.urlopen'):
                stack.enter_context(patch(name, side_effect=AssertionError('Network forbidden')))
            token = auth.login('synthetic_admin', self.synthetic_password, self.db)
            self.assertTrue(token)
            self.assertFalse(encryption.encryption_status(self.db)['configured'])

    def test_administrator_management_page_renders(self):
        with ExitStack() as stack:
            for name in ('list_users','create_user','set_enabled','reset_password'):
                stack.enter_context(patch.object(auth, name, partial(getattr(auth, name), db_path=self.db)))
            for name in ('list_cases','assign_case'):
                stack.enter_context(patch.object(case_service, name, partial(getattr(case_service, name), db_path=self.db)))
            app = test_evidence.authenticated_app(self, 'pages/8_User_Management.py').run()
            self.assertFalse(app.exception)
            self.assertTrue(app.dataframe)
            for frame in app.dataframe:
                self.assertNotIn('password_hash', str(frame.value))
                self.assertNotIn('password_salt', str(frame.value))


class CaseAccessTests(unittest.TestCase):
    tearDown = test_evidence.StorageTests.tearDown
    query = test_evidence.StorageTests.query
    register = test_evidence.StorageTests.register
    account = AuthenticationTests.account

    def setUp(self):
        test_evidence.StorageTests.setUp(self)
        self.case, self.evidence = self.register()
        self.analysis = run_analysis(self.evidence, self.db, self.root)
        self.decision = record_decision(self.case, self.evidence, self.analysis['analysis_id'], 'Synthetic Reviewer',
            'Approve Analysis', 'I reviewed the evidence and the automated findings.', True, db_path=self.db, data_root=self.root)

    def report(self):
        return generate_report(self.case, self.evidence, self.analysis['analysis_id'], self.decision['decision_id'], db_path=self.db, data_root=self.root)

    def test_assignments_isolation_and_revocation(self):
        uid, username, password, token = self.account('Investigator')
        with auth.as_session(token):
            self.assertEqual(case_service.list_cases(db_path=self.db), [])
            with self.assertRaises(auth.AccessDenied):
                get_evidence(self.evidence, self.db)
            with self.assertRaises(auth.AccessDenied):
                load_context(self.case, self.evidence, self.analysis['analysis_id'], self.db, self.root)
        case_service.assign_case(self.case, uid, db_path=self.db)
        with auth.as_session(token):
            self.assertEqual(selections(db_path=self.db)[0], [self.case])
            self.assertTrue(get_evidence(self.evidence, self.db))
            self.assertEqual(case_service.open_case(self.case, self.db), [self.evidence])
        case_service.assign_case(self.case, uid, False, self.db)
        with auth.as_session(token), self.assertRaises(auth.AccessDenied):
            analysis_history(self.evidence, self.db)

    def test_reviewer_permissions_enforced_by_services(self):
        report = self.report()
        uid, username, password, token = self.account()
        case_service.assign_case(self.case, uid, db_path=self.db)
        with auth.as_session(token):
            self.assertTrue(analysis_history(self.evidence, self.db))
            self.assertTrue(download_bytes(self.case, self.evidence, report['report_id'], 'html', db_path=self.db, data_root=self.root))
            for call in (lambda: self.register(data=test_evidence.SAMPLE+b'new'),
                         lambda: run_analysis(self.evidence, self.db, self.root),
                         lambda: ask(self.case, self.evidence, 'Who sent this email?', db_path=self.db, data_root=self.root),
                         self.report, lambda: case_service.archive_case(self.case, self.db)):
                with self.assertRaises(auth.AccessDenied):
                    call()
            result = record_decision(self.case, self.evidence, self.analysis['analysis_id'], 'Synthetic Reviewer',
                'Reject Analysis', 'Additional context needs further review.', True, expected_previous_id=self.decision['decision_id'],
                version_reason='Further context reviewed.', db_path=self.db, data_root=self.root)
            self.assertEqual(result['decision_version'], 2)

    def test_investigator_upload_auto_assignment(self):
        uid, username, password, token = self.account('Investigator')
        with auth.as_session(token):
            case, evidence = self.register(data=test_evidence.SAMPLE+b'Synthetic new case')
            self.assertEqual(selections(db_path=self.db)[0], [case])
            self.assertTrue(get_evidence(evidence, self.db))
            with self.assertRaises(auth.AccessDenied):
                case_service.assign_case(self.case, uid, db_path=self.db)

    def test_duplicate_cannot_disclose_unassigned_case(self):
        uid, username, password, token = self.account('Investigator')
        with auth.as_session(token), self.assertRaises(ValidationError) as caught:
            self.register()
        self.assertNotIn(self.case, str(caught.exception))
        self.assertNotIn(self.evidence, str(caught.exception))

    def test_session_state_tampering_does_not_leak_case(self):
        uid, username, password, token = self.account('Investigator')
        app = AppTest.from_file('pages/2_Evidence_Analysis.py')
        app.session_state['auth_token'] = token
        app.session_state['active_case_id'] = self.case
        app.session_state['active_evidence_id'] = self.evidence
        app.run()
        self.assertFalse(app.exception)
        self.assertTrue(any(x.value == auth.DENIED for x in app.error))
        self.assertFalse(app.code)

    def test_archiving_preserves_records_and_blocks_writes(self):
        report = self.report()
        before = {t:self.query('SELECT * FROM '+t) for t in ('evidence','analysis_results','investigator_decisions','reports')}
        files = {p:p.read_bytes() for p in self.root.rglob('*') if p.is_file() and p.suffix != '.db'}
        case_service.archive_case(self.case, self.db)
        self.assertEqual(case_service.list_cases(db_path=self.db)[0]['status'], 'Archived')
        for table in before:
            self.assertEqual(before[table], self.query('SELECT * FROM '+table))
        for path, contents in files.items():
            self.assertEqual(contents, path.read_bytes())
        with self.assertRaises(auth.AccessDenied):
            run_analysis(self.evidence, self.db, self.root)
        self.assertTrue(get_evidence(self.evidence, self.db))

    def test_workflow_status_tracks_latest_versions(self):
        self.assertEqual(case_service.list_cases(db_path=self.db)[0]['status'], 'Verified')
        self.report()
        self.assertEqual(case_service.list_cases(db_path=self.db)[0]['status'], 'Report Generated')
        run_analysis(self.evidence, self.db, self.root)
        self.assertEqual(case_service.list_cases(db_path=self.db)[0]['status'], 'Awaiting Human Verification')

    def mark(self):
        case_service.archive_case(self.case, self.db)
        return case_service.request_deletion(self.case, self.db, self.root)

    def test_deletion_requires_archival_mark_and_exact_confirmation(self):
        for confirmation in ('DELETE '+self.case, self.case, 'DELETE '+self.case+' '):
            with self.assertRaises(ValidationError):
                case_service.delete_case(self.case, confirmation, self.db, self.root)
        self.mark()
        with self.assertRaises(ValidationError):
            case_service.delete_case(self.case, 'DELETE '+self.case.lower(), self.db, self.root)
        self.assertTrue(self.query('SELECT * FROM cases'))

    def test_nonadministrator_cannot_delete(self):
        uid, username, password, token = self.account('Investigator')
        case_service.assign_case(self.case, uid, db_path=self.db)
        with auth.as_session(token):
            for call in (lambda: case_service.request_deletion(self.case, self.db, self.root),
                         lambda: case_service.delete_case(self.case, 'DELETE '+self.case, self.db, self.root)):
                with self.assertRaises(auth.AccessDenied):
                    call()

    def test_deletion_removes_files_records_preserves_other_case(self):
        self.report()
        other, other_evidence = self.register(data=test_evidence.SAMPLE+b'Other retained synthetic case')
        inventory = self.mark()
        self.assertEqual(inventory['Evidence originals'], 1)
        self.assertEqual(inventory['Reports'], 1)
        result = case_service.delete_case(self.case, 'DELETE '+self.case, self.db, self.root)
        self.assertEqual(result['status'], 'completed')
        for area in ('evidence','working','reports'):
            self.assertFalse((self.root / area / self.case).exists())
        for table in ('cases','evidence','analysis_results','investigator_decisions','reports','qa_interactions','case_assignments','audit_logs'):
            self.assertFalse(self.query('SELECT * FROM '+table+' WHERE case_id=?', (self.case,)))
        self.assertTrue(get_evidence(other_evidence, self.db))
        tombstone = self.query("SELECT details FROM audit_logs WHERE action='CASE_DELETED'")[0][0]
        self.assertEqual(set(json.loads(tombstone)), {'deleted_case_id','deletion_id'})

    def test_deletion_path_escape_rejected(self):
        self.mark()
        c = connect_database(self.db)
        with c:
            c.execute('UPDATE evidence SET storage_path=? WHERE evidence_id=?', (str(self.root.parent / 'outside.eml'), self.evidence))
        c.close()
        with self.assertRaises(ValueError):
            case_service.delete_case(self.case, 'DELETE '+self.case, self.db, self.root)
        self.assertTrue(self.query('SELECT * FROM cases WHERE case_id=?', (self.case,)))
        self.assertTrue((self.root / 'evidence' / self.case).exists())

    def test_deletion_failure_rolls_back_staging(self):
        self.mark()
        with patch('modules.case_service.secrets.token_hex', return_value='A'*24):
            c = connect_database(self.db)
            with c:
                c.execute("INSERT INTO deletion_jobs VALUES(?,?,?,'completed',?,?)", ('DEL-'+'A'*24,'synthetic',self.admin_id,auth.utc_now(),auth.utc_now()))
            c.close()
            with self.assertRaises(Exception):
                case_service.delete_case(self.case, 'DELETE '+self.case, self.db, self.root)
        self.assertTrue(get_evidence(self.evidence, self.db))
        self.assertTrue((self.root / 'evidence' / self.case).exists())

    def test_pending_cleanup_can_be_retried(self):
        self.mark()
        with patch.object(case_service, '_purge', side_effect=PermissionError('Synthetic locked file')):
            result = case_service.delete_case(self.case, 'DELETE '+self.case, self.db, self.root)
        self.assertEqual(result['status'], 'pending')
        self.assertTrue(case_service.pending_deletions(self.db))
        case_service.finish_deletion(result['job_id'], self.db, self.root)
        self.assertFalse(case_service.pending_deletions(self.db))

    def test_case_management_page_renders(self):
        with ExitStack() as stack:
            for name in ('list_cases','open_case','archive_case','pending_deletions'):
                stack.enter_context(patch.object(case_service, name, partial(getattr(case_service, name), db_path=self.db)))
            app = test_evidence.authenticated_app(self, 'pages/7_Case_Management.py').run()
            self.assertFalse(app.exception)
            self.assertTrue(app.dataframe)
            self.assertIn(self.case, app.selectbox[0].options)

    def test_deleted_versions_can_be_removed_only_via_admin_service(self):
        first = self.report()
        generate_report(self.case, self.evidence, self.analysis['analysis_id'], self.decision['decision_id'],
                        expected_previous_id=first['report_id'], version_reason='Additional review.', db_path=self.db, data_root=self.root)
        record_decision(self.case, self.evidence, self.analysis['analysis_id'], 'Synthetic Reviewer', 'Reject Analysis',
            'Further review changed the conclusion.', True, expected_previous_id=self.decision['decision_id'], version_reason='Additional review.',
            db_path=self.db, data_root=self.root)
        c = connect_database(self.db)
        try:
            with self.assertRaises(Exception):
                c.execute('DELETE FROM reports')
            c.rollback()
        finally:
            c.close()
        self.mark()
        self.assertEqual(case_service.delete_case(self.case, 'DELETE '+self.case, self.db, self.root)['status'], 'completed')
