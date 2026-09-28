"""Synthetic evidence only; every artifact lives in a temporary directory."""
import hashlib
import json
from pathlib import Path
import socket
import stat
import tempfile
import secrets
from contextlib import ExitStack
import unittest
from unittest.mock import patch
from email.message import EmailMessage

from modules.database import initialize_database, connect_database
from modules import auth
from modules.email_parser import (parse_email, csv_rows, html_to_text, ParseError, MAX_BODY,
                                  MAX_HEADER, MAX_CSV_ROWS, MAX_CSV_COLUMNS, MAX_ATTACHMENTS)
from modules.privacy import mask_evidence
from modules.evidence_handler import (register_evidence, validate_upload, sanitize_filename,
    sha256_bytes, DuplicateEvidence, ValidationError, MAX_FILE_SIZE, get_evidence,
    verify_integrity, confined, evidence_path, log_event)

SAMPLE = (b'From: sender@example.test\r\nTo: recipient@example.test\r\n'
          b'Subject: Synthetic evidence\r\nDate: Sat, 26 Sep 2026 12:00:00 +0000\r\n'
          b'Message-ID: <synthetic@example.test>\r\n\r\n'
          b'Contact sender@example.test. Visit https://example.test/?email=sender%40example.test\r\n')


def authorize_database(test):
    """Real credentials and sessions, scoped exclusively to each temporary DB."""
    test.synthetic_password = secrets.token_urlsafe(20) + 'Aa1!'
    test.admin_id = auth.create_first_admin('synthetic_admin', test.synthetic_password, test.db)
    test.token = auth.login('synthetic_admin', test.synthetic_password, test.db)
    test.auth_stack.enter_context(auth.as_session(test.token))
    test.auth_stack.enter_context(patch('modules.ui.AUTH_DB_PATH', test.db))
    test.auth_db = test.db


def authenticated_app(test, path):
    from streamlit.testing.v1 import AppTest
    if test.auth_db != test.db:
        authorize_database(test)
    app = AppTest.from_file(path)
    app.session_state['auth_token'] = test.token
    return app


class ParsingTests(unittest.TestCase):
    def test_sha256(self):
        self.assertEqual(sha256_bytes(b'abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_filename_sanitization(self):
        self.assertEqual(sanitize_filename('synthetic (1).TXT'), 'synthetic _1_.TXT')
        for name in ('../a.eml', '..\\a.eml', '/a.txt', 'C:\\a.txt', 'CON.txt', 'a.txt:evil',
                     'a.exe', 'a\x00.txt', '%2e%2e%2fa.txt', 'a..txt', 'a.txt ', '\\\\host\\a.txt'):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                sanitize_filename(name)

    def test_size_and_empty(self):
        for data in (b'', b'  \r\n', b'x' * (MAX_FILE_SIZE + 1)):
            with self.assertRaises(ValidationError):
                validate_upload('a.txt', data)
        self.assertEqual(validate_upload('a.txt', b'x' * MAX_FILE_SIZE), 'a.txt')

    def test_malicious_content(self):
        for data in (b'MZfake', b'\x7fELF', b'#!/bin/sh', b'../secret', b'%2e%2e%2fsecret',
                     b'<script>alert(1)</script>', b'<img onerror="evil()">', b'hello\x00world'):
            with self.subTest(data=data), self.assertRaises(ValidationError):
                validate_upload('a.txt', data)
        message = EmailMessage()
        message.set_content('Synthetic attachment test')
        message.add_attachment(b'MZsynthetic', maintype='application', subtype='octet-stream', filename='sample.exe')
        with self.assertRaises(ValidationError):
            validate_upload('a.eml', message.as_bytes())

    def test_eml(self):
        result = parse_email(SAMPLE, '.eml')
        self.assertEqual(result['sender'], 'sender@example.test')
        self.assertEqual(result['recipient'], 'recipient@example.test')
        self.assertIn('Contact', result['body'])
        self.assertEqual(len(result['urls']), 1)

    def test_txt(self):
        result = parse_email(b'From: sender@example.test\nSubject: Test\n\nbody\nTo: stays in body', '.txt')
        self.assertEqual(result['subject'], 'Test')
        self.assertIn('To: stays in body', result['body'])
        self.assertEqual(parse_email(b'Complete plain text', '.txt')['body'], 'Complete plain text')

    def test_csv(self):
        data = b'from,to,subject,body\nsender@example.test,recipient@example.test,One,First\nsender@example.test,recipient@example.test,Two,Second\n'
        self.assertEqual(len(csv_rows(data)[0]), 2)
        with self.assertRaises(ParseError):
            parse_email(data, '.csv')
        self.assertEqual(parse_email(data, '.csv', 2)['body'], 'Second')
        for invalid in (b'a,b\n1,2', b'body\n\n', b'body,body\na,b', b'body,subject\none,two,three'):
            with self.assertRaises(ParseError):
                csv_rows(invalid)

    def test_html_and_no_network_urls(self):
        self.assertEqual(html_to_text('<p>Hello &amp; goodbye</p><script>secret()</script><style>x</style>'), '\nHello & goodbye')
        message = EmailMessage()
        message['From'] = 'sender@example.test'
        message.set_content('<p>Hello</p><a href="https://example.test/path">Link</a><img src="https://example.test/image">', subtype='html')
        with patch.object(socket.socket, 'connect', side_effect=AssertionError('Network forbidden')):
            result = parse_email(message.as_bytes(), '.eml')
        self.assertIn('Hello', result['body'])
        self.assertEqual(len(result['urls']), 2)
        self.assertNotIn('<img', result['body'])

    def test_attachment_metadata(self):
        message = EmailMessage()
        message.set_content('Synthetic body')
        message.add_attachment(b'synthetic attachment', maintype='text', subtype='plain', filename='note.txt')
        result = parse_email(message.as_bytes(), '.eml')
        self.assertEqual(result['attachments'], [{'name': 'note.txt', 'type': 'text/plain', 'size': 20}])
        self.assertNotIn('synthetic attachment', result['body'])

    def test_masking_and_stability(self):
        value = {'sender': 'sender@example.test', 'body': 'sender@example.test +1 202 555 0100 192.0.2.1 4111 1111 1111 1111 1234 5678 9012 ABCDE1234F',
                 'urls': ['https://example.test/?name=SyntheticPerson&email=sender%40example.test']}
        masked = mask_evidence(value)
        self.assertEqual(masked['sender'], '[EMAIL-1]')
        for kind in ('EMAIL', 'PHONE', 'IP', 'CARD', 'AADHAAR', 'PAN'):
            self.assertIn(f'[{kind}-1]', masked['body'])
        self.assertNotIn('SyntheticPerson', str(masked))
        self.assertNotIn('sender', str(masked['urls']))
        self.assertEqual(mask_evidence({'a': '+1 202 555 0100', 'b': '+12025550100'})['a'], '[PHONE-1]')
        repeated = mask_evidence({'a': '+1 202 555 0100', 'b': '+12025550100'})
        self.assertEqual(repeated['a'], repeated['b'])

    def test_limits(self):
        parsed = parse_email(('Subject: ' + 'x' * (MAX_HEADER + 1) + '\n\n' + 'y' * (MAX_BODY + 1)).encode(), '.txt')
        self.assertTrue(parsed['truncated'])
        self.assertEqual(len(parsed['body']), MAX_BODY)
        self.assertEqual(len(parsed['subject']), MAX_HEADER)
        parsed = parse_email(' '.join(f'https://example.test/{i}' for i in range(110)).encode(), '.txt')
        self.assertEqual(len(parsed['urls']), 100)
        self.assertTrue(parsed['truncated'])
        rows, warnings = csv_rows(('body\n' + 'synthetic\n' * (MAX_CSV_ROWS + 1)).encode())
        self.assertEqual(len(rows), MAX_CSV_ROWS)
        self.assertTrue(warnings)
        with self.assertRaises(ParseError):
            csv_rows((','.join(['body'] + [f'c{i}' for i in range(MAX_CSV_COLUMNS)]) + '\n').encode())
        message = EmailMessage()
        message.set_content('Synthetic body')
        for i in range(MAX_ATTACHMENTS + 1):
            message.add_attachment(b'synthetic', maintype='text', subtype='plain', filename=f'note{i}.txt')
        result = parse_email(message.as_bytes(), '.eml')
        self.assertEqual(len(result['attachments']), MAX_ATTACHMENTS)
        self.assertTrue(result['truncated'])


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.db = self.root / 'forensics.db'
        initialize_database(self.db)
        self.auth_stack = ExitStack()
        authorize_database(self)

    def tearDown(self):
        self.auth_stack.close()
        for path in self.root.rglob('*'):
            if path.is_file():
                path.chmod(stat.S_IREAD | stat.S_IWRITE)
        self.temporary.cleanup()

    def register(self, data=SAMPLE, **changes):
        args = dict(title='Synthetic case', investigator='Test Investigator', description='Synthetic description',
                    source='Synthetic mailbox', authorized=True, filename='sample.eml', data=data,
                    data_root=self.root, db_path=self.db)
        args.update(changes)
        return register_evidence(**args)

    def query(self, sql, parameters=()):
        connection = connect_database(self.db)
        try:
            return connection.execute(sql, parameters).fetchall()
        finally:
            connection.close()

    def test_registration_original_masked_json_and_database(self):
        with patch.object(socket.socket, 'connect', side_effect=AssertionError('Network forbidden')), patch('urllib.request.urlopen', side_effect=AssertionError('Network forbidden')):
            case, evidence = self.register()
        self.assertRegex(case, r'^CASE-\d{8}-[A-F0-9]{4}$')
        self.assertRegex(evidence, r'^EVD-\d{8}-[A-F0-9]{4}$')
        row = get_evidence(evidence, self.db)
        original = evidence_path(row, data_root=self.root)
        self.assertEqual(original.read_bytes(), SAMPLE)
        self.assertFalse(original.stat().st_mode & stat.S_IWUSR)
        self.assertEqual(row['sha256'], hashlib.sha256(SAMPLE).hexdigest())
        self.assertEqual(row['file_size'], len(SAMPLE))
        working = evidence_path(row, working=True, data_root=self.root)
        parsed = json.loads(working.read_text())
        self.assertEqual(parsed['sender'], '[EMAIL-1]')
        self.assertNotIn('sender@example.test', working.read_text())
        self.assertNotIn(SAMPLE, self.db.read_bytes())
        for path in (original, working):
            self.assertTrue(path.resolve().is_relative_to(self.root))
        self.assertEqual(len(self.query('SELECT * FROM cases')), 1)
        self.assertEqual(len(self.query('SELECT * FROM evidence')), 1)
        events = self.query("SELECT action,status,created_at FROM audit_logs WHERE action NOT IN ('USER_CREATED','LOGIN_SUCCESS','CASE_ASSIGNED')")
        self.assertEqual(len(events), 8)
        self.assertTrue(all(event[2].endswith('+00:00') for event in events))
        initialize_database(self.db)
        self.assertEqual(len(self.query('SELECT * FROM evidence')), 1)

    def test_duplicate_hash(self):
        case, evidence = self.register()
        with self.assertRaises(DuplicateEvidence) as caught:
            self.register(filename='renamed.eml')
        self.assertEqual((caught.exception.case_id, caught.exception.evidence_id), (case, evidence))
        self.assertEqual(len(self.query('SELECT * FROM evidence')), 1)
        self.assertEqual(self.query('SELECT action FROM audit_logs ORDER BY audit_id DESC LIMIT 1')[0][0], 'Duplicate upload detected')

    def test_validation_audit(self):
        for changes in ({'authorized': False}, {'title': ''}, {'filename': '../evil.eml'}, {'data': b''}, {'filename': 'a.csv', 'data': b'body\n'}):
            with self.assertRaises(ValueError):
                self.register(**changes)
        self.assertEqual(len(self.query("SELECT * FROM audit_logs WHERE action='Validation failure'")), 5)
        self.assertFalse(self.query('SELECT * FROM cases'))

    def test_integrity(self):
        case, evidence = self.register()
        self.assertTrue(verify_integrity(evidence, self.db, self.root))
        original = Path(get_evidence(evidence, self.db)['storage_path'])
        original.chmod(stat.S_IWRITE | stat.S_IREAD)
        original.write_bytes(b'Tampered synthetic evidence')
        self.assertFalse(verify_integrity(evidence, self.db, self.root))
        self.assertEqual(self.query("SELECT status FROM audit_logs WHERE action='Integrity rechecked'"), [('success',), ('failure',)])

    def test_containment_and_forged_path(self):
        with self.assertRaises(ValidationError):
            confined(self.root, '..', 'escape')
        case, evidence = self.register()
        row = get_evidence(evidence, self.db)
        row['storage_path'] = str(self.root / 'forensics.db')
        with self.assertRaises(ValidationError):
            evidence_path(row, data_root=self.root)

    def test_transaction_failure_cleans_files(self):
        from modules.evidence_handler import atomic_write

        def fail_working_write(path, data):
            if path.name == 'masked.json':
                raise OSError('synthetic disk failure after original stored')
            return atomic_write(path, data)

        with patch('modules.evidence_handler.atomic_write', side_effect=fail_working_write):
            with self.assertRaises(OSError):
                self.register()
        self.assertFalse(self.query('SELECT * FROM cases'))
        self.assertFalse(list(self.root.glob('evidence/*/*/*')))
        self.assertFalse(list(self.root.glob('working/*/*/*')))

    def test_foreign_keys(self):
        connection = connect_database(self.db)
        try:
            self.assertEqual(connection.execute('PRAGMA foreign_keys').fetchone()[0], 1)
        finally:
            connection.close()

    def test_view_audit(self):
        case, evidence = self.register()
        log_event('Test Investigator', 'Evidence viewed', case_id=case, evidence_id=evidence, db_path=self.db)
        self.assertEqual(self.query('SELECT action FROM audit_logs ORDER BY audit_id DESC LIMIT 1')[0][0], 'Evidence viewed')


if __name__ == '__main__':
    unittest.main()
