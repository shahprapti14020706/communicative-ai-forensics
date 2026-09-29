"""Activity authorization tests use real sessions and temporary databases only."""
import unittest
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
from tests import test_evidence, test_auth_cases
from modules import auth, case_service, activity_service, workflow
from modules.audit import record
from modules.database import connect_database


class ActivityTests(unittest.TestCase):
    tearDown = test_evidence.StorageTests.tearDown
    register = test_evidence.StorageTests.register
    query = test_evidence.StorageTests.query
    account = test_auth_cases.AuthenticationTests.account

    def setUp(self):
        test_evidence.StorageTests.setUp(self)
        self.case, self.evidence = self.register()
        self.other, _ = self.register(data=test_evidence.SAMPLE + b'Other case')
        self.uid, _, _, self.investigator_token = self.account('Investigator')
        case_service.assign_case(self.case, self.uid, db_path=self.db)
        c = connect_database(self.db)
        with c:
            for event in activity_service.ACTIVITIES:
                record(c, self.admin_id, event, case_id=self.case, details='PRIVATE PAYLOAD')
            record(c, self.admin_id, 'USER_DISABLED', case_id=self.case, details='SECURITY SECRET')
            record(c, self.admin_id, 'REPORT_GENERATED', case_id=self.other, details='OTHER CASE')
            record(c, self.admin_id, 'LOGIN_SUCCESS', details='GLOBAL SECRET')
        c.close()

    def test_investigator_service_scope_and_projection(self):
        with auth.as_session(self.investigator_token):
            rows = activity_service.activity_history(self.case, self.db)
            self.assertEqual({row['activity'] for row in rows}, set(activity_service.ACTIVITIES.values()))
            self.assertTrue(all(set(row) == {'timestamp_utc', 'activity', 'status'} for row in rows))
            for secret in (self.admin_id, self.case, self.other, 'PRIVATE', 'SECURITY', 'GLOBAL', 'USER_DISABLED'):
                self.assertNotIn(secret, str(rows))
            self.assertEqual(activity_service.activity_history(db_path=self.db), [])
            with self.assertRaises(auth.AccessDenied):
                activity_service.activity_history(self.other, self.db)
            with self.assertRaises(auth.AccessDenied):
                activity_service.record_activity_view(self.other, self.db)
            with self.assertRaises(auth.AccessDenied):
                case_service.audit_history(self.case, self.db)

    def test_admin_history_and_filters(self):
        rows = case_service.audit_history(db_path=self.db)
        self.assertTrue({self.case, self.other, None}.issubset({row['case_id'] for row in rows}))
        self.assertIn('SECURITY SECRET', str(rows))
        filtered = case_service.audit_history(self.other, self.db, event_filter='REPORT_GENERATED', status_filter='success')
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['details'], 'OTHER CASE')
        self.assertEqual(case_service.audit_history(db_path=self.db, offset=1)[0], rows[1])
        with self.assertRaises(ValueError):
            case_service.audit_history(db_path=self.db, offset=-1)


    def test_anonymous_denied(self):
        with auth.as_session(None):
            for function in (activity_service.activity_history, activity_service.record_activity_view, case_service.audit_history):
                with self.assertRaises(auth.AccessDenied):
                    function(self.case, self.db)
            app = AppTest.from_file('pages/6_Audit_Log.py').run()
            self.assertFalse(app.exception)
            self.assertFalse(app.dataframe)
            self.assertTrue(any(item.value == 'Investigator Login' for item in app.title))

    def page(self, case_id, token=None):
        app = AppTest.from_file('pages/6_Audit_Log.py')
        app.session_state['auth_token'] = token or self.investigator_token
        if case_id:
            app.session_state['active_case_id'] = case_id
        return app.run()

    def test_investigator_page_and_progress(self):
        with auth.as_session(self.investigator_token):
            self.assertFalse(workflow.case_progress(self.case, self.db)['activity_history_viewed'])
        app = self.page(self.case)
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        self.assertTrue(app.dataframe)
        self.assertFalse(app.json)
        self.assertFalse(app.selectbox)
        self.assertFalse(any(item.label == 'Technical Details' for item in app.expander))
        self.assertEqual(list(app.dataframe[0].value.columns), ['Date', 'Activity', 'Status'])
        with auth.as_session(self.investigator_token):
            steps = workflow.visible_steps(workflow.case_progress(self.case, self.db))
            self.assertEqual(len(steps), 6)
            self.assertEqual(list(steps)[-1], 'Activity History')
            self.assertTrue(steps['Activity History'])
        self.assertFalse(workflow.case_progress(self.case, self.db)['activity_history_viewed'])
        complete = dict(stages=dict.fromkeys(workflow.STAGES, 'Completed'), activity_history_viewed=True)
        self.assertEqual(sum(workflow.visible_steps(complete).values()), 6)

    def test_missing_case_and_other_case_page(self):
        app = self.page(None)
        self.assertFalse(app.exception)
        self.assertTrue(any(item.value == 'Select an investigation to view its activity history.' for item in app.info))
        self.assertFalse(app.dataframe)
        denied = self.page(self.other)
        self.assertFalse(denied.exception)
        self.assertFalse(denied.dataframe)
        self.assertTrue(denied.error)
        self.assertFalse(self.query("SELECT 1 FROM audit_logs WHERE case_id=? AND actor=? AND action='ACTIVITY_HISTORY_VIEWED'", (self.other, self.uid)))

    def test_admin_page(self):
        app = self.page(None, self.token)
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        self.assertEqual(len(app.selectbox), 3)
        self.assertTrue(app.json)
        self.assertIn('details', app.dataframe[0].value.columns)
