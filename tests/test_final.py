"""Final synthetic workflow, UI, privacy and demonstration-safety regression tests."""
from contextlib import ExitStack
import hashlib
import inspect
import io
from functools import partial
import json
from pathlib import Path
import secrets
import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from streamlit.testing.v1 import AppTest

from tests import test_evidence
from tests.test_evidence import authenticated_app
from modules import (auth, workflow, demo_setup, case_service, evidence_handler, analysis_service,
                     qa_service, verification_service, report_generator, ui)


class FinalTests(unittest.TestCase):
    setUp = test_evidence.StorageTests.setUp
    tearDown = test_evidence.StorageTests.tearDown
    query = test_evidence.StorageTests.query
    register = test_evidence.StorageTests.register

    def analyze(self):
        case, evidence = self.register(data=demo_setup.sample_bytes())
        result = analysis_service.run_analysis(evidence, self.db, self.root)
        return case, evidence, result['analysis_id']

    def test_end_to_end_local_workflow_and_logout(self):
        with ExitStack() as stack:
            for target in ('socket.socket.connect', 'socket.socket.connect_ex', 'socket.create_connection',
                           'socket.getaddrinfo', 'urllib.request.urlopen'):
                stack.enter_context(patch(target, side_effect=AssertionError('External connections forbidden')))
            token = auth.login('synthetic_admin', self.synthetic_password, self.db)
            with auth.as_session(token):
                source = demo_setup.sample_bytes()
                case, evidence = self.register(data=source)
                row = evidence_handler.get_evidence(evidence, self.db)
                original = evidence_handler.evidence_path(row, data_root=self.root)
                self.assertEqual(row['sha256'], hashlib.sha256(source).hexdigest())
                self.assertTrue(evidence_handler.verify_integrity(evidence, self.db, self.root))
                analysis = analysis_service.run_analysis(evidence, self.db, self.root)
                aid = analysis['analysis_id']
                self.assertEqual(analysis['classification'], 'Suspicious')
                context = qa_service.load_context(case, evidence, aid, self.db, self.root)
                self.assertIn('[EMAIL-', context['working']['sender'])
                for question in ('Why is this email suspicious?', 'What evidence supports the result?'):
                    result = qa_service.ask(case, evidence, question, aid, self.db, self.root)
                    self.assertEqual(result['status'], 'completed')
                    self.assertTrue(result['evidence_references'])
                self.assertEqual(qa_service.ask(case, evidence, 'Predict tomorrow weather', aid, self.db, self.root)['status'], 'unsupported')
                decision = verification_service.record_decision(case, evidence, aid, 'Synthetic Investigator',
                    'Approve Analysis', 'I reviewed the evidence and the automated findings.', True, db_path=self.db, data_root=self.root)
                report = report_generator.generate_report(case, evidence, aid, decision['decision_id'], db_path=self.db, data_root=self.root)
                html = report_generator.download_bytes(case, evidence, report['report_id'], 'html', db_path=self.db, data_root=self.root)
                manifest = report_generator.download_bytes(case, evidence, report['report_id'], 'json', db_path=self.db, data_root=self.root)
                self.assertEqual(hashlib.sha256(html).hexdigest(), report['report_sha256'])
                self.assertEqual(hashlib.sha256(manifest).hexdigest(), report['json_sha256'])
                self.assertTrue(report_generator.verify_report_integrity(case, evidence, report['report_id'], self.db, self.root))
                self.assertEqual(set(workflow.case_progress(case, self.db)['stages'].values()), {'Completed'})
                self.assertEqual(original.read_bytes(), source)
                actions = {row[0] for row in self.query('SELECT action FROM audit_logs')}
                self.assertTrue({'LOGIN_SUCCESS', 'Evidence uploaded', 'DECISION_RECORDED', 'REPORT_GENERATED', 'REPORT_INTEGRITY_CHECKED'} <= actions)
                auth.logout(token, db_path=self.db)
                with self.assertRaises(auth.AccessDenied):
                    workflow.case_progress(case, self.db)
            for path in [Path('app.py'), *Path('pages').glob('*.py')]:
                app = AppTest.from_file(str(path))
                app.session_state['auth_token'] = token
                app.run()
                self.assertFalse(app.exception)
                self.assertEqual([b.label for b in app.button], ['Login'])

    def test_progress_empty_states_and_failed_integrity(self):
        self.assertEqual(set(workflow.case_progress(db_path=self.db)['stages'].values()), {'Not Started'})
        case, evidence = self.register()
        progress = workflow.case_progress(case, self.db)
        self.assertEqual(progress['stages']['Evidence Registered'], 'Completed')
        self.assertEqual(progress['stages']['Integrity Verified'], 'Not Started')
        evidence_handler.log_event('Synthetic Investigator', 'Integrity rechecked', 'failure', case, evidence, db_path=self.db)
        self.assertEqual(workflow.case_progress(case, self.db)['stages']['Report Generated'], 'Blocked')

    def test_new_analysis_requires_new_review_and_decision(self):
        case, evidence, aid = self.analyze()
        qa_service.ask(case, evidence, 'Why is this email suspicious?', aid, self.db, self.root)
        verification_service.record_decision(case, evidence, aid, 'Synthetic Reviewer', 'Approve Analysis',
            'I reviewed the evidence and findings.', True, db_path=self.db, data_root=self.root)
        analysis_service.run_analysis(evidence, self.db, self.root)
        qa_service.ask(case, evidence, 'Why is this email suspicious?', aid, self.db, self.root)
        stages = workflow.case_progress(case, self.db)['stages']
        self.assertEqual(stages['Evidence Questions Reviewed'], 'Not Started')
        self.assertEqual(stages['Human Decision Recorded'], 'Not Started')
        self.assertEqual(len(self.query('SELECT * FROM investigator_decisions')), 1)

    def test_dashboard_and_progress_cross_user_isolation(self):
        case, evidence = self.register()
        password = secrets.token_urlsafe(20) + 'Aa1!'
        uid = auth.create_user('synthetic_reader', password, 'Reviewer', self.db)
        token = auth.login('synthetic_reader', password, self.db)
        with auth.as_session(token):
            for function in (workflow.case_progress, workflow.recent_events):
                with self.assertRaises(auth.AccessDenied):
                    function(case, self.db)
            app = AppTest.from_file('app.py')
            app.session_state['auth_token'] = token
            app.run()
            self.assertFalse(app.exception)
            self.assertNotIn('User and Case Management', [b.label for b in app.sidebar.button])
            for path in ('pages/7_Case_Management.py', 'pages/8_User_Management.py'):
                page = AppTest.from_file(path)
                page.session_state['auth_token'] = token
                page.run()
                self.assertFalse(page.exception)
                self.assertTrue(page.error)

    def test_new_audit_actors_do_not_store_entered_names(self):
        case, evidence = self.register(investigator='Synthetic Private Name')
        analysis_service.run_analysis(evidence, self.db, self.root)
        self.assertNotIn('Synthetic Private Name', str(self.query('SELECT actor,details FROM audit_logs')))
        self.assertTrue(all(set(event) == {'timestamp_utc','event','status'} for event in workflow.recent_events(case, self.db)))

    def test_demo_isolated_unique_and_no_automatic_decision(self):
        retained, eid = self.register()
        before = evidence_handler.get_evidence(eid, self.db)
        one = demo_setup.create_demo(self.db, self.root)
        two = demo_setup.create_demo(self.db, self.root)
        self.assertNotEqual(one, two)
        self.assertEqual(len(demo_setup.list_demos(self.db, self.root)), 2)
        self.assertEqual(before, evidence_handler.get_evidence(eid, self.db))
        for table in ('analysis_results','investigator_decisions','reports'):
            self.assertEqual(self.query('SELECT COUNT(*) FROM '+table)[0][0], 0)
        self.assertEqual(self.query('SELECT COUNT(*) FROM users')[0][0], 1)

    def test_demo_cleanup_exact_scope_and_confirmation(self):
        retained, eid = self.register()
        case, evidence = demo_setup.create_demo(self.db, self.root)
        with self.assertRaises(ValueError):
            demo_setup.cleanup_demo(case, 'yes', self.db, self.root)
        result = demo_setup.cleanup_demo(case, 'DELETE DEMO '+case, self.db, self.root)
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(evidence_handler.get_evidence(eid, self.db))
        for area in ('evidence','working','reports'):
            self.assertFalse((self.root / area / case).exists())
        self.assertFalse(demo_setup.list_demos(self.db, self.root))
        self.assertTrue(self.query("SELECT 1 FROM audit_logs WHERE action='DEMO_CLEANED'"))

    def test_demo_cleanup_refuses_regular_case_even_with_label(self):
        case, _ = self.register(title=demo_setup.LABEL)
        with self.assertRaises(ValueError):
            demo_setup.cleanup_demo(case, 'DELETE DEMO '+case, self.db, self.root)
        self.assertEqual(self.query('SELECT COUNT(*) FROM cases')[0][0], 1)

    def test_demo_cleanup_preserves_added_investigator_work(self):
        case, evidence = demo_setup.create_demo(self.db, self.root)
        analysis_service.run_analysis(evidence, self.db, self.root)
        with self.assertRaises(ValueError):
            demo_setup.cleanup_demo(case, 'DELETE DEMO '+case, self.db, self.root)
        self.assertEqual(len(self.query('SELECT * FROM analysis_results')), 1)

    def test_demo_cleanup_refuses_extra_files_and_traversal(self):
        case, evidence = demo_setup.create_demo(self.db, self.root)
        extra = self.root / 'working' / case / 'investigator-notes.txt'
        extra.write_text('Synthetic investigator-created notes')
        with self.assertRaises(ValueError):
            demo_setup.cleanup_demo(case, 'DELETE DEMO '+case, self.db, self.root)
        self.assertTrue(extra.exists())
        with self.assertRaises(ValueError):
            demo_setup.cleanup_demo('../outside', 'DELETE DEMO ../outside', self.db, self.root)

    def test_missing_and_malformed_sample_no_records(self):
        sample = self.root / 'missing.eml'
        with patch.object(demo_setup, 'SAMPLE_PATH', sample):
            with self.assertRaises(ValueError):
                demo_setup.create_demo(self.db, self.root)
            sample.write_bytes(b'Malformed synthetic fixture')
            with self.assertRaises(ValueError):
                demo_setup.create_demo(self.db, self.root)
        self.assertFalse(self.query('SELECT * FROM cases'))

    def test_demo_requires_authentication_and_administrator(self):
        with auth.as_session(None), self.assertRaises(auth.AccessDenied):
            demo_setup.create_demo(self.db, self.root)
        password = secrets.token_urlsafe(20) + 'Aa1!'
        auth.create_user('synthetic_investigator', password, 'Investigator', self.db)
        token = auth.login('synthetic_investigator', password, self.db)
        with auth.as_session(token), self.assertRaises(auth.AccessDenied):
            demo_setup.create_demo(self.db, self.root)

    def test_storage_errors_safe_on_every_page(self):
        for path in [Path('app.py'), *Path('pages').glob('*.py')]:
            with patch.object(ui, 'initialize_database', side_effect=sqlite3.OperationalError('PRIVATE SQL PATH')):
                app = authenticated_app(self, str(path)).run()
                self.assertFalse(app.exception)
                self.assertTrue(app.error)
                self.assertNotIn('PRIVATE SQL PATH', str(app.error))

    def test_every_page_renders_authenticated_empty_storage(self):
        modules = (auth, case_service, evidence_handler, analysis_service, qa_service, verification_service, report_generator)
        with ExitStack() as stack:
            for module in modules:
                for name, function in inspect.getmembers(module, inspect.isfunction):
                    if function.__module__ != module.__name__:
                        continue
                    signature = inspect.signature(function)
                    if 'db_path' not in signature.parameters:
                        continue
                    def isolated(*args, _function=function, _signature=signature, **kwargs):
                        bound = _signature.bind_partial(*args, **kwargs)
                        if 'db_path' not in bound.arguments:
                            kwargs['db_path'] = self.db
                        if 'data_root' in _signature.parameters and 'data_root' not in bound.arguments:
                            kwargs['data_root'] = self.root
                        return _function(*args, **kwargs)
                    stack.enter_context(patch.object(module, name, isolated))
            for path in [Path('app.py'), *Path('pages').glob('*.py')]:
                with self.subTest(page=path.name):
                    app = authenticated_app(self, str(path)).run()
                    self.assertFalse(app.exception)
                    self.assertTrue(app.title)

    def test_tests_refuse_production_database(self):
        with self.assertRaises(AssertionError):
            sqlite3.connect(Path('data') / 'forensics.db')

    def test_active_dashboard_contains_no_evidence_or_private_context(self):
        case, evidence = self.register(title='Synthetic Private Context', investigator='Synthetic Private Name')
        app = authenticated_app(self, 'app.py')
        app.session_state['active_case_id'] = case
        app.session_state['active_evidence_id'] = evidence
        app.run()
        self.assertFalse(app.exception)
        display = str([v.value for v in app.text]) + str([v.value for v in app.dataframe])
        for private in ('Synthetic Private Context','Synthetic Private Name','sender@example.test'):
            self.assertNotIn(private, display)
        self.assertTrue(any(case in item.value for item in app.text))

    def test_demo_cleanup_refuses_redirected_database_path(self):
        case, evidence = demo_setup.create_demo(self.db, self.root)
        c = sqlite3.connect(self.db)
        with c:
            c.execute('UPDATE evidence SET storage_path=? WHERE evidence_id=?', (str(self.root.parent / 'outside.eml'), evidence))
        c.close()
        with self.assertRaises(ValueError):
            demo_setup.cleanup_demo(case, 'DELETE DEMO '+case, self.db, self.root)
        self.assertEqual(len(self.query('SELECT * FROM cases')), 1)

    def test_demo_cli_confirmation_and_exact_cleanup_listing(self):
        local_auth = SimpleNamespace(login=partial(auth.login, db_path=self.db),
            logout=partial(auth.logout, db_path=self.db), as_session=auth.as_session,
            require_permission=partial(auth.require_permission, db_path=self.db),
            current_user=auth.current_user, event=auth.event)
        output = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(demo_setup, 'auth', local_auth))
            for name in ('create_demo','list_demos','cleanup_demo'):
                stack.enter_context(patch.object(demo_setup, name, partial(getattr(demo_setup, name), db_path=self.db, data_root=self.root)))
            stack.enter_context(patch('getpass.getpass', return_value=self.synthetic_password))
            stack.enter_context(patch('sys.stdout', output))
            with patch('sys.argv', ['demo_setup']), patch('builtins.input', side_effect=['synthetic_admin', 'cancel']):
                demo_setup.main()
            self.assertFalse(self.query('SELECT * FROM cases'))
            with patch('sys.argv', ['demo_setup']), patch('builtins.input', side_effect=['synthetic_admin', 'CREATE SYNTHETIC DEMONSTRATION']):
                demo_setup.main()
            case = self.query('SELECT case_id FROM cases')[0][0]
            with patch('sys.argv', ['demo_setup', 'cleanup']), patch('builtins.input', side_effect=['synthetic_admin', 'DELETE DEMO '+case]):
                demo_setup.main()
            self.assertFalse(self.query('SELECT * FROM cases'))
        self.assertIn(case + ' | Eligible', output.getvalue())
        self.assertNotIn(self.synthetic_password, output.getvalue())
