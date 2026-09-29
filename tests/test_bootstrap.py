"""Cloud startup tests use generated credentials and temporary databases only."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from streamlit.errors import StreamlitSecretNotFoundError
from streamlit.testing.v1 import AppTest

from modules import auth, bootstrap, ui
from modules.database import connect_database, SCHEMA


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db = Path(self.temporary.name) / 'nested' / 'demo.db'
        self.config = {
            'bootstrap_admin': {'username': 'synthetic_admin', 'password': secrets.token_urlsafe(24) + 'Aa1!',
                                'display_name': 'Fictional Administrator'},
            'bootstrap_investigator': {'username': 'synthetic_investigator', 'password': secrets.token_urlsafe(24) + 'Bb2!',
                                       'display_name': 'Fictional Investigator'},
        }

    def start(self, config=None):
        with patch.object(bootstrap.st, 'secrets', self.config if config is None else config):
            bootstrap.initialize_demo_accounts(self.db)

    def query(self, sql, values=()):
        connection = connect_database(self.db)
        try:
            return connection.execute(sql, values).fetchall()
        finally:
            connection.close()

    def test_first_startup_creates_schema_roles_and_secure_passwords(self):
        self.assertFalse(self.db.exists())
        self.start()
        rows = self.query('SELECT username,password_hash,password_salt,password_iterations,role,display_name FROM users ORDER BY username')
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0][2], rows[1][2])
        for row, section, role in zip(rows, self.config.values(), ('Administrator', 'Investigator')):
            self.assertEqual(row[0], section['username'])
            self.assertEqual(row[3], auth.ITERATIONS)
            self.assertEqual(row[4:], (role, section['display_name']))
            self.assertEqual(row[1], hashlib.pbkdf2_hmac('sha256', section['password'].encode(), row[2], row[3]))
            self.assertTrue(auth.login(section['username'], section['password'], self.db))

    def test_repeated_startup_does_not_reset_password_or_duplicate_events(self):
        self.start()
        before = self.query('SELECT * FROM users ORDER BY username')
        events = self.query('SELECT * FROM audit_logs')
        for section in self.config.values():
            section['username'] = section['username'].upper()
            section['password'] = secrets.token_urlsafe(24) + 'Cc3!'
            section['display_name'] = 'Changed fictional label'
        self.start()
        self.start()
        self.assertEqual(before, self.query('SELECT * FROM users ORDER BY username'))
        self.assertEqual(events, self.query('SELECT * FROM audit_logs'))

    def test_missing_sections_initialize_empty_schema(self):
        self.start({})
        self.assertEqual(self.query('SELECT COUNT(*) FROM users'), [(0,)])
        self.assertEqual(self.query('SELECT COUNT(*) FROM cases'), [(0,)])

    def test_missing_local_secrets_file_is_optional(self):
        missing = MagicMock()
        missing.__getitem__.side_effect = StreamlitSecretNotFoundError('No synthetic secret file')
        self.start(missing)
        self.assertEqual(self.query('SELECT COUNT(*) FROM users'), [(0,)])

    def test_recreated_database_bootstraps_again_without_cache(self):
        self.start()
        ids = self.query('SELECT user_id FROM users ORDER BY username')
        self.db.unlink()  # Only the temporary test database; all connections closed.
        self.start()
        self.assertNotEqual(ids, self.query('SELECT user_id FROM users ORDER BY username'))
        for section in self.config.values():
            self.assertTrue(auth.login(section['username'], section['password'], self.db))

    def test_only_missing_account_is_created(self):
        self.start({'bootstrap_admin': self.config['bootstrap_admin']})
        original = self.query('SELECT * FROM users')[0]
        self.start()
        self.assertEqual(self.query('SELECT * FROM users WHERE username=?', ('synthetic_admin',))[0], original)
        self.assertEqual(self.query('SELECT COUNT(*) FROM users'), [(2,)])

    def test_investigator_section_can_be_used_independently(self):
        self.start({'bootstrap_investigator': self.config['bootstrap_investigator']})
        self.assertEqual(self.query('SELECT role FROM users'), [('Investigator',)])

    def test_disabled_and_locked_accounts_are_not_reenabled(self):
        self.start()
        connection = connect_database(self.db)
        with connection:
            connection.execute("UPDATE users SET enabled=0,failed_attempts=5,locked_until_utc='2099-01-01T00:00:00+00:00'")
        connection.close()
        before = self.query('SELECT * FROM users ORDER BY username')
        self.start()
        self.assertEqual(before, self.query('SELECT * FROM users ORDER BY username'))

    def test_existing_role_conflict_never_promotes_an_account(self):
        self.start({'bootstrap_investigator': self.config['bootstrap_investigator']})
        self.config['bootstrap_admin']['username'] = 'synthetic_investigator'
        del self.config['bootstrap_investigator']
        with self.assertRaisesRegex(bootstrap.BootstrapError, '^Demo account configuration is invalid'):
            self.start()
        self.assertEqual(self.query('SELECT role FROM users'), [('Investigator',)])

    def test_invalid_second_password_rolls_back_both_accounts(self):
        self.config['bootstrap_investigator']['password'] = secrets.token_hex(3)
        with self.assertRaises(bootstrap.BootstrapError):
            self.start()
        self.assertEqual(self.query('SELECT COUNT(*) FROM users'), [(0,)])
        self.assertEqual(self.query('SELECT COUNT(*) FROM audit_logs'), [(0,)])

    def test_incomplete_duplicate_or_malformed_sections_fail_safely(self):
        for config in (
            {'bootstrap_admin': {'username': 'synthetic_admin'}},
            {'bootstrap_admin': 'not a section'},
            {'bootstrap_admin': dict(self.config['bootstrap_admin'], display_name=['invalid'])},
            dict(self.config, bootstrap_investigator=self.config['bootstrap_admin']),
        ):
            with self.subTest(kind=type(config['bootstrap_admin']).__name__):
                with self.assertRaises(bootstrap.BootstrapError):
                    self.start(config)
                self.assertEqual(self.query('SELECT COUNT(*) FROM users'), [(0,)])

    def test_parse_error_is_sanitized(self):
        error = StreamlitSecretNotFoundError(self.config['bootstrap_admin']['password'])
        error.__cause__ = ValueError(self.config['bootstrap_admin']['password'])
        malformed = MagicMock()
        malformed.__getitem__.side_effect = error
        with self.assertRaises(bootstrap.BootstrapError) as caught:
            self.start(malformed)
        self.assertEqual(str(caught.exception), bootstrap.MESSAGE)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_credentials_are_absent_from_output_and_audit(self):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output), self.assertNoLogs(level='WARNING'):
            self.start()
        public = output.getvalue() + str(self.query('SELECT actor,action,details FROM audit_logs'))
        for section in self.config.values():
            for value in section.values():
                self.assertNotIn(value, public)
            self.assertNotIn(section['password'].encode(), self.db.read_bytes())

    def test_concurrent_first_startups_create_only_one_of_each(self):
        with patch.object(bootstrap.st, 'secrets', self.config):
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(lambda _: bootstrap.initialize_demo_accounts(self.db), range(2)))
        self.assertEqual(self.query('SELECT COUNT(*) FROM users'), [(2,)])
        self.assertEqual(self.query("SELECT COUNT(*) FROM audit_logs WHERE action='USER_CREATED'"), [(2,)])

    def test_legacy_schema_gets_optional_display_name_column(self):
        connection = connect_database(self.db)
        connection.executescript(SCHEMA)
        connection.close()
        self.start()
        self.assertEqual(self.query('SELECT display_name FROM users ORDER BY username'),
                         [('Fictional Administrator',), ('Fictional Investigator',)])

    def test_page_startup_and_login_work_for_both_roles(self):
        with patch.object(ui, 'AUTH_DB_PATH', self.db):
            for section in self.config.values():
                app = AppTest.from_file('app.py')
                app.secrets.update(self.config)
                app.run()
                self.assertFalse(app.exception)
                app.text_input[0].set_value(section['username'])
                app.text_input[1].set_value(section['password'])
                app.button[0].click().run()
                self.assertFalse(app.exception)
                self.assertTrue(any(title.value == 'Communicative AI Digital Forensics Assistant' for title in app.title))

    def test_direct_page_initializes_before_login(self):
        with patch.object(ui, 'AUTH_DB_PATH', self.db):
            app = AppTest.from_file('pages/1_New_Investigation.py')
            app.secrets.update(self.config)
            app.run()
        self.assertFalse(app.exception)
        self.assertEqual([button.label for button in app.button], ['Login'])
        self.assertEqual(self.query('SELECT COUNT(*) FROM users'), [(2,)])

    def test_invalid_configuration_displays_only_safe_error(self):
        self.config['bootstrap_admin']['display_name'] = ['invalid']
        with patch.object(ui, 'AUTH_DB_PATH', self.db):
            app = AppTest.from_file('app.py')
            app.secrets.update(self.config)
            app.run()
        self.assertFalse(app.exception)
        self.assertEqual([error.value for error in app.error], [bootstrap.MESSAGE])
        self.assertFalse(app.text_input)


if __name__ == '__main__':
    unittest.main()
