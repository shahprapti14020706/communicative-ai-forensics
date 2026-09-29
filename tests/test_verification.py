"""Synthetic Step 5 tests; all writes are confined to temporary storage."""
from contextlib import ExitStack
from functools import partial
import json
from pathlib import Path
import socket
import sqlite3
import stat
import unittest
from unittest.mock import patch
from streamlit.testing.v1 import AppTest

from tests import test_evidence
from modules import verification_service as service, qa_service
from modules.analysis_service import run_analysis
from modules.database import connect_database, initialize_database, SCHEMA
from modules.evidence_handler import get_evidence, ValidationError


class VerificationTests(unittest.TestCase):
    tearDown = test_evidence.StorageTests.tearDown
    register = test_evidence.StorageTests.register
    query = test_evidence.StorageTests.query

    def setUp(self):
        test_evidence.StorageTests.setUp(self)
        self.case, self.evidence = self.register()
        self.analysis = run_analysis(self.evidence, self.db, self.root)
        self.aid = self.analysis['analysis_id']

    def submit(self, **changes):
        values = dict(case_id=self.case, evidence_id=self.evidence, analysis_id=self.aid,
                      investigator_name='Fictional Reviewer', decision_type='Approve Analysis',
                      notes='I reviewed the evidence and verified the findings.', confirmed=True,
                      db_path=self.db, data_root=self.root)
        values.update(changes)
        return service.record_decision(**values)

    def test_readable_prose_keeps_identifiers_private(self):
        prose = 'Why ask what information should be checked through links? The email creates urgency.'
        self.assertEqual(service.private_text(prose), prose)
        for secret in ('Name: Zorvian Quell', 'alice@example.test', '+1 202 555 0100',
                       '192.0.2.15', 'ABCDE1234F', '1234 5678 9012'):
            masked = service.private_text(prose + ' ' + secret)
            self.assertNotIn(secret, masked)
            self.assertTrue(masked.startswith(prose))
            self.assertEqual(service.private_text(masked), masked)

    def test_explicit_decision_reason_validation(self):
        for reason in ('', '   ', 'x' * 5001, 23):
            with self.subTest(reason=repr(reason)[:30]), self.assertRaises(ValidationError):
                self.submit(decision_reason=reason)

    def test_approve(self):
        result = self.submit()
        self.assertEqual(result['final_classification'], self.analysis['classification'])
        self.assertEqual(result['decision_version'], 1)
        self.assertRegex(result['decision_id'], r'^DEC-[A-F0-9]{12}$')
        self.assertTrue(result['created_at_utc'].endswith('+00:00'))

    def test_reject(self):
        result = self.submit(decision_type='Reject Analysis')
        self.assertIsNone(result['final_classification'])
        self.assertEqual(result['decision'], 'reject')

    def test_modify(self):
        result = self.submit(decision_type='Modify Conclusion', final_classification='Suspicious',
                             change_reason='Additional context supports suspicious classification.')
        self.assertEqual(result['final_classification'], 'Suspicious')
        self.assertNotEqual(result['automated_classification'], result['final_classification'])
        for fields in ({'final_classification': None}, {'change_reason': ''},
                       {'final_classification': self.analysis['classification']}):
            values = dict(decision_type='Modify Conclusion', final_classification='Suspicious',
                          change_reason='Additional context.', expected_previous_id=result['decision_id'],
                          version_reason='More evidence reviewed.')
            values.update(fields)
            with self.assertRaises(ValidationError):
                self.submit(**values)

    def test_further_analysis_and_json(self):
        result = self.submit(decision_type='Request Further Analysis',
                             requested_actions=['Inspect email headers', 'Other'],
                             other_description='Compare with synthetic@example.test evidence.')
        actions = json.loads(result['requested_actions'])
        self.assertEqual(actions['actions'], ['Inspect email headers', 'Other'])
        self.assertNotIn('synthetic@example.test', actions['other_description'])
        self.assertIsNone(result['final_classification'])

    def test_further_analysis_requires_actions_and_other_description(self):
        for actions in (None, [], ['invalid'], ['Other']):
            with self.subTest(actions=actions), self.assertRaises(ValidationError):
                self.submit(decision_type='Request Further Analysis', requested_actions=actions)

    def test_required_name(self):
        for value in ('', '   ', None):
            with self.assertRaises(ValidationError):
                self.submit(investigator_name=value)

    def test_notes_length(self):
        for value in ('', 'short', 'x' * 19, None, ' ' * 25):
            with self.assertRaises(ValidationError):
                self.submit(notes=value)
        self.submit(notes='x' * 20)

    def test_confirmation(self):
        for value in (False, None, 1, 'yes'):
            with self.assertRaises(ValidationError):
                self.submit(confirmed=value)

    def tamper(self):
        path = Path(get_evidence(self.evidence, self.db)['storage_path'])
        path.chmod(stat.S_IREAD | stat.S_IWRITE)
        path.write_bytes(b'Synthetic altered evidence')

    def test_integrity_failure_and_recheck_after_open(self):
        review = service.open_review(self.case, self.evidence, self.aid, self.db, self.root)
        self.assertTrue(review['integrity_valid'])
        self.tamper()
        with self.assertRaisesRegex(ValidationError, service.BLOCKED):
            self.submit()
        self.assertFalse(self.query('SELECT * FROM investigator_decisions'))
        self.assertTrue(self.query("SELECT * FROM audit_logs WHERE action='INTEGRITY_CHECK_BEFORE_DECISION' AND status='failure'"))
        self.assertTrue(self.query("SELECT * FROM audit_logs WHERE action='DECISION_SUBMISSION_BLOCKED'"))

    def test_original_analysis_and_evidence_unchanged(self):
        before = self.query('SELECT * FROM analysis_results')
        original = Path(get_evidence(self.evidence, self.db)['storage_path'])
        contents = original.read_bytes()
        self.submit(decision_type='Modify Conclusion', final_classification='Suspicious', change_reason='More context reviewed.')
        self.assertEqual(before, self.query('SELECT * FROM analysis_results'))
        self.assertEqual(contents, original.read_bytes())

    def test_notes_names_and_reasons_masked(self):
        text = 'Reviewed Zorvian Quell synthetic@example.test +1 202 555 0100 <script>private</script>.'
        result = self.submit(notes=text, investigator_name='Zorvian Quell')
        stored = str(self.query('SELECT * FROM investigator_decisions'))
        for secret in ('Zorvian', 'Quell', 'synthetic@example.test', '202 555 0100', '<script>'):
            self.assertNotIn(secret, stored)
        self.assertIn('[EMAIL-', result['masked_verification_notes'])
        self.assertEqual(service.private_text(result['masked_verification_notes']), result['masked_verification_notes'])

    def test_append_only_link_and_reason(self):
        first = self.submit()
        before = self.query('SELECT * FROM investigator_decisions WHERE decision_id=?', (first['decision_id'],))
        with self.assertRaises(ValidationError):
            self.submit(expected_previous_id=first['decision_id'])
        second = self.submit(expected_previous_id=first['decision_id'], version_reason='Additional evidence reviewed.', decision_type='Reject Analysis')
        self.assertEqual(second['decision_version'], 2)
        self.assertEqual(second['supersedes_decision_id'], first['decision_id'])
        self.assertEqual(before, self.query('SELECT * FROM investigator_decisions WHERE decision_id=?', (first['decision_id'],)))
        connection = connect_database(self.db)
        try:
            for sql in ('UPDATE investigator_decisions SET rationale=?', 'DELETE FROM investigator_decisions WHERE decision_id=?'):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(sql, (first['decision_id'],))
                connection.rollback()
        finally:
            connection.close()

    def test_stale_review(self):
        self.submit()
        with self.assertRaisesRegex(ValidationError, 'history changed'):
            self.submit(version_reason='A stale concurrent review.')
        self.assertEqual(len(self.query('SELECT * FROM investigator_decisions')), 1)

    def test_cross_case_and_missing_scope(self):
        case, evidence = self.register(data=test_evidence.SAMPLE + b'Other synthetic evidence')
        analysis = run_analysis(evidence, self.db, self.root)
        for fields in ({'case_id': case}, {'evidence_id': evidence}, {'analysis_id': analysis['analysis_id']},
                       {'case_id': None}, {'evidence_id': None}, {'analysis_id': None}):
            with self.subTest(fields=fields), self.assertRaises(ValidationError):
                self.submit(**fields)
        self.assertFalse(self.query('SELECT * FROM investigator_decisions'))

    def test_closed_case(self):
        connection = connect_database(self.db)
        with connection:
            connection.execute("UPDATE cases SET status='closed' WHERE case_id=?", (self.case,))
        connection.close()
        with self.assertRaises(ValidationError):
            self.submit()

    def test_audit_all_events_without_private_text(self):
        service.open_review(self.case, self.evidence, self.aid, self.db, self.root)
        previous = None
        for decision in service.DECISIONS:
            result = self.submit(decision_type=decision, final_classification='Suspicious',
                change_reason='Synthetic reason for change.', requested_actions=['Verify sender identity'],
                expected_previous_id=previous, version_reason='Additional context reviewed.',
                notes='Private sentinel SECRETXYZ synthetic@example.test was reviewed.')
            previous = result['decision_id']
        with self.assertRaises(ValidationError):
            self.submit(confirmed=False)
        events = self.query("SELECT actor,action,details FROM audit_logs WHERE action GLOB '*_*' AND action NOT IN ('USER_CREATED','LOGIN_SUCCESS','CASE_ASSIGNED')")
        self.assertEqual({r[1] for r in events}, {'HUMAN_VERIFICATION_OPENED', 'DECISION_RECORDED',
            'DECISION_APPROVED', 'DECISION_REJECTED', 'CONCLUSION_MODIFIED', 'FURTHER_ANALYSIS_REQUESTED',
            'DECISION_VERSION_CREATED', 'DECISION_SUBMISSION_BLOCKED', 'INTEGRITY_CHECK_BEFORE_DECISION'})
        for actor, action, details in events:
            json.loads(details)
            self.assertEqual(actor, '[INVESTIGATOR]')
            for private in ('SECRETXYZ', 'synthetic@example.test', 'Fictional Reviewer', 'Private sentinel'):
                self.assertNotIn(private, details)

    def test_no_network(self):
        with patch.object(socket.socket, 'connect', side_effect=AssertionError('Network forbidden')), \
             patch('socket.create_connection', side_effect=AssertionError('Network forbidden')), \
             patch('urllib.request.urlopen', side_effect=AssertionError('Network forbidden')):
            service.open_review(self.case, self.evidence, self.aid, self.db, self.root)
            self.submit()

    def isolated_page(self, empty=False):
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name in ('selections', 'decision_history'):
            stack.enter_context(patch.object(service, name, partial(getattr(service, name), db_path=self.db)))
        for name in ('open_review', 'record_decision'):
            stack.enter_context(patch.object(service, name, partial(getattr(service, name), db_path=self.db, data_root=self.root)))
        stack.enter_context(patch.object(qa_service, 'available_analyses', partial(qa_service.available_analyses, db_path=self.db)))
        app = test_evidence.authenticated_app(self, 'pages/4_Human_Verification.py')
        if not empty:
            app.session_state['active_case_id'] = self.case
            app.session_state['active_evidence_id'] = self.evidence
        return app.run()

    def test_page_renders_and_submits(self):
        app = self.isolated_page()
        self.assertFalse(app.exception)
        self.assertTrue(app.button[0].disabled)
        app.text_input[0].set_value('Fictional Reviewer')
        app.text_area[0].set_value('I reviewed the evidence and the analysis limitations.')
        app.text_area[1].set_value('I reviewed the evidence and the analysis limitations.')
        app.checkbox[0].check().run()
        self.assertFalse(app.button[0].disabled)
        app.button[0].click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any(x.value == 'Your decision has been recorded.' for x in app.success))
        self.assertEqual(len(self.query('SELECT * FROM investigator_decisions')), 1)
        self.assertTrue(any('preserve the previous decision' in x.value for x in app.info))
        saved = service.decision_history(self.case, self.evidence, self.aid, db_path=self.db)[0]
        self.assertEqual(saved['masked_decision_reason'], 'I reviewed the evidence and the analysis limitations.')
        self.assertEqual(saved['masked_verification_notes'], 'I reviewed the evidence and the analysis limitations.')
        self.assertNotIn('Reason:', saved['masked_verification_notes'])

    def test_page_conditional_fields(self):
        app = self.isolated_page()
        app.selectbox[3].select('Update the Conclusion').run()
        self.assertFalse(app.exception)
        self.assertEqual(app.selectbox[4].options, ['Suspicious', 'Needs Review', 'No Warning Signs Found'])
        self.assertTrue(app.button[0].disabled)
        app.selectbox[3].select('Needs More Investigation').run()
        self.assertFalse(app.exception)
        next(x for x in app.checkbox if x.label == 'Other').check().run()
        self.assertTrue(any(x.label == 'Other request description' for x in app.text_area))

    def test_page_integrity_failure(self):
        self.tamper()
        app = self.isolated_page()
        self.assertFalse(app.exception)
        self.assertTrue(app.button[0].disabled)
        self.assertTrue(any(x.value == 'The email integrity check failed. A decision cannot be recorded.' for x in app.error))

    def test_empty_database(self):
        self.db = self.root / 'empty.db'
        app = self.isolated_page(empty=True)
        self.assertFalse(app.exception)
        self.assertTrue(any('No active cases' in x.value for x in app.info))

    def test_legacy_migration_preserves_rows(self):
        legacy = self.root / 'legacy.db'
        connection = sqlite3.connect(legacy)
        connection.executescript(SCHEMA)
        connection.execute("INSERT INTO cases(case_id,title,investigator_name) VALUES('C','Synthetic','Fictional')")
        connection.execute("INSERT INTO evidence(evidence_id,case_id,original_filename) VALUES('E','C','synthetic.txt')")
        connection.execute("INSERT INTO analysis_results(analysis_id,evidence_id) VALUES('A','E')")
        connection.execute("INSERT INTO investigator_decisions(decision_id,analysis_id,investigator_name,decision,rationale) VALUES('D','A','Fictional','approve','Synthetic prior notes')")
        before = connection.execute('SELECT * FROM investigator_decisions').fetchone()
        connection.commit()
        connection.close()
        initialize_database(legacy)
        initialize_database(legacy)
        connection = sqlite3.connect(legacy)
        after = connection.execute('SELECT * FROM investigator_decisions').fetchone()
        connection.close()
        self.assertEqual(before, after[:len(before)])
