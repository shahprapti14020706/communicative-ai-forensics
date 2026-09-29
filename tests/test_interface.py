"""Streamlit interaction checks with synthetic evidence in temporary storage."""
from contextlib import ExitStack
from functools import partial
import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
from tests import test_evidence
from modules import evidence_handler as handler
from modules import analysis_service


SAMPLE = test_evidence.SAMPLE


class InterfaceTests(unittest.TestCase):
    setUp = test_evidence.StorageTests.setUp
    tearDown = test_evidence.StorageTests.tearDown
    query = test_evidence.StorageTests.query

    def test_intake_and_analysis(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(analysis_service, 'run_analysis', partial(analysis_service.run_analysis, db_path=self.db, data_root=self.root)))
            for name in ('analysis_history', 'view_analysis'):
                stack.enter_context(patch.object(analysis_service, name, partial(getattr(analysis_service, name), db_path=self.db)))
            stack.enter_context(patch.object(handler, 'register_evidence', partial(handler.register_evidence, data_root=self.root, db_path=self.db)))
            for name in ('log_event', 'get_evidence'):
                def isolate(function):
                    def call(*args, **kwargs):
                        bound = inspect.signature(function).bind_partial(*args, **kwargs)
                        if 'db_path' not in bound.arguments:
                            kwargs['db_path'] = self.db
                        return function(*args, **kwargs)
                    return call
                stack.enter_context(patch.object(handler, name, isolate(getattr(handler, name))))
            stack.enter_context(patch.object(handler, 'verify_integrity', partial(handler.verify_integrity, db_path=self.db, data_root=self.root)))
            stack.enter_context(patch.object(handler, 'evidence_path', partial(handler.evidence_path, data_root=self.root)))
            stack.enter_context(patch('streamlit.file_uploader', return_value=SimpleNamespace(name='sample.eml', getvalue=lambda: SAMPLE)))
            app = test_evidence.authenticated_app(self, 'pages/1_New_Investigation.py').run()
            self.assertFalse(app.exception)
            app.text_input[0].set_value('Synthetic case')
            app.text_input[1].set_value('Test Investigator')
            app.text_area[0].set_value('Synthetic description')
            app.text_input[2].set_value('Synthetic mailbox')
            app.checkbox[0].check()
            app.button[0].click().run()
            self.assertFalse(app.exception)
            evidence = app.session_state['active_evidence_id']
            analysis = test_evidence.authenticated_app(self, 'pages/2_Evidence_Analysis.py')
            analysis.session_state['active_evidence_id'] = evidence
            analysis.run()
            self.assertFalse(analysis.exception)
            self.assertEqual(analysis.success[0].value, 'Email integrity checked')
            self.assertTrue(any('[EMAIL-1]' in code.value for code in analysis.code))
            analysis.button[0].click().run()
            self.assertFalse(analysis.exception)
            self.assertEqual(len(self.query("SELECT * FROM audit_logs WHERE action='Integrity rechecked'")), 1)
            next(button for button in analysis.button if button.label == 'Analyze Email').click().run()
            self.assertFalse(analysis.exception)
            self.assertEqual(len(self.query('SELECT * FROM analysis_results')), 1)
            self.assertTrue(any('The investigator makes the final decision.' in item.value for item in analysis.caption))
            self.assertTrue(any('Result: No Warning Signs Found' == item.value for item in analysis.success))
            next(button for button in analysis.button if button.label == 'Run Analysis Again').click().run()
            self.assertFalse(analysis.exception)
            self.assertEqual(len(self.query('SELECT * FROM analysis_results')), 2)
            self.assertEqual(len(analysis.selectbox[0].options), 2)
            analysis.selectbox[0].set_value(self.query('SELECT analysis_id FROM analysis_results WHERE analysis_version=1')[0][0]).run()
            self.assertFalse(analysis.exception)
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertTrue(any('Duplicate' in warning.value for warning in app.warning))
            next(button for button in app.button if button.label == 'Cancel duplicate upload').click().run()
            self.assertFalse(app.exception)
            self.assertFalse(any('Duplicate' in warning.value for warning in app.warning))

    def test_csv_selection(self):
        data = b'from,body\nsender@example.test,First synthetic row\nsender@example.test,Second synthetic row\n'
        with patch('streamlit.file_uploader', return_value=SimpleNamespace(name='sample.csv', getvalue=lambda: data)):
            app = test_evidence.authenticated_app(self, 'pages/1_New_Investigation.py').run()
            app.checkbox[0].check().run()
            self.assertFalse(app.exception)
            self.assertEqual(len(app.selectbox[0].options), 2)
            app.selectbox[0].set_value(2).run()
            self.assertIn('Second synthetic row', app.code[0].value)
