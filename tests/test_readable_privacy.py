"""Readable prose and targeted identifier redaction regression tests."""
import unittest
from modules.verification_service import private_text
from modules.qa_engine import redact
from modules.presentation import plain_answer


class ReadablePrivacyTests(unittest.TestCase):
    def test_ordinary_prose_is_preserved(self):
        values = [
            'Are there any suspicious links?',
            'Why ask for personal information through an unverified link?',
            'The email creates urgency. Contact the sender independently.',
            'The conclusion should reflect verification findings detected in the suspicious email.',
            'Initial Investigation Report: Account Verification',
            'No safe conclusion can be drawn from the available evidence.',
        ]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(private_text(value), value)
                self.assertEqual(redact(value), value)

    def test_structured_identifiers_and_confident_names(self):
        values = ['Name: Alice', 'Dr. Alice', 'Name: Alice Example', 'Dr. Alice Example', 'Alice Example <alice@example.test>',
                  'alice@example.test', '+1 202 555 0100', '9876543210', '192.0.2.15',
                  '2001:db8::1', 'ABCDE1234F', '1234 5678 9012', '4111 1111 1111 1111',
                  'SSN: 123-45-6789', 'Passport: A1234567', 'account number: 12345678']
        for value in values:
            with self.subTest(value=value):
                result = private_text(value)
                self.assertNotEqual(result, value)
                self.assertEqual(private_text(result), result)
                self.assertNotIn('Alice Example', result)
                self.assertNotIn('alice@example.test', result)

    def test_empty_and_legacy_answers_have_readable_fallback(self):
        for answer in ('', '   ', 'Detected indicators: [PRIVATE].'):
            self.assertTrue(plain_answer(answer).strip())
            self.assertNotIn('[PRIVATE]', plain_answer(answer))
