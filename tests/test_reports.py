"""Local synthetic reporting tests. No production records or artifacts are used."""
from contextlib import ExitStack
from functools import partial
from html.parser import HTMLParser
import json
from pathlib import Path
import socket
import sqlite3
import stat
import unittest
from unittest.mock import patch
from streamlit.testing.v1 import AppTest

from tests import test_evidence, test_verification
from modules import report_generator as reports, qa_service, verification_service
from modules.analysis_service import run_analysis
from modules.database import connect_database, initialize_database
from modules.evidence_handler import get_evidence, ValidationError, sha256_bytes


class ReportTests(unittest.TestCase):
    tearDown = test_evidence.StorageTests.tearDown
    register = test_evidence.StorageTests.register
    query = test_evidence.StorageTests.query
    submit = test_verification.VerificationTests.submit
    tamper = test_verification.VerificationTests.tamper

    def setUp(self):
        test_verification.VerificationTests.setUp(self)
        self.decision = self.submit()
        self.did = self.decision['decision_id']

    def generate(self, **changes):
        args = dict(case_id=self.case, evidence_id=self.evidence, analysis_id=self.aid,
                    decision_id=self.did, db_path=self.db, data_root=self.root)
        args.update(changes)
        return reports.generate_report(**args)

    def manifest(self, report):
        return json.loads((self.root / report['json_path']).read_bytes())

    def verify(self, report):
        return reports.verify_report_integrity(self.case, self.evidence, report['report_id'], self.db, self.root)

    def download(self, report, kind='html', audit=False):
        return reports.download_bytes(self.case, self.evidence, report['report_id'], kind,
                                       audit=audit, db_path=self.db, data_root=self.root)

    def test_separate_reason_notes_and_version_details(self):
        from modules.presentation import report_sections
        reason = ('The email creates urgency, threatens account suspension and requests '
                  'confidential login information through an unverified link.')
        notes = ('The sender and verification link should be independently checked. '
                 'The recipient should not click the link or provide credentials.')
        version_reason = ('Initial investigation report created after completing email '
                          'analysis and investigator verification.')
        actions = ['Inspect email headers', 'Examine suspicious links', 'Examine attachments']
        current = self.submit(decision_type='Request Further Analysis', decision_reason=reason,
            notes=notes, requested_actions=actions, expected_previous_id=self.did,
            version_reason='Additional context reviewed.')
        self.did = current['decision_id']
        self.assertEqual(current['masked_decision_reason'], reason)
        self.assertEqual(current['masked_verification_notes'], notes)
        first = self.generate(version_reason=version_reason)
        second = self.generate(version_reason=version_reason, expected_previous_id=first['report_id'])
        preview = reports.preview_report(self.case, self.evidence, self.aid, self.did,
            self.db, self.root, version_reason=version_reason)
        third = self.generate(version_reason=version_reason, expected_previous_id=second['report_id'])
        for document in (preview, self.manifest(third)):
            sections = report_sections(document)
            decision = next(v for k, v in sections.items() if k.endswith('final decision'))
            self.assertEqual(decision, {'Decision': 'Needs More Investigation',
                'Reason': reason, 'Requested checks': actions})
            self.assertEqual(next(v for k, v in sections.items() if k.endswith('notes')), notes)
            self.assertEqual(sections['Report version details'],
                {'Version': 3, 'Reason for this version': version_reason})
        html = self.download(third).decode().split('<details>')[0]
        for value in (reason, notes, version_reason, 'REPORT VERSION DETAILS', *actions):
            self.assertIn(value, html)
        self.assertNotIn('Reason: ', self.manifest(third)['human_verification']['masked_verification_notes'])
        self.assertTrue(self.verify(first))
        self.assertTrue(self.verify(third))

    def test_legacy_embedded_reason_is_presented_without_mutating_record(self):
        notes = 'The sender should be independently checked.'
        reason = 'The email creates urgency through an unverified link.'
        current = self.submit(notes=notes + '\nReason: ' + reason,
            expected_previous_id=self.did, version_reason='Additional context reviewed.')
        self.did = current['decision_id']
        human = self.manifest(self.generate())['human_verification']
        self.assertEqual(human['masked_decision_reason'], reason)
        self.assertEqual(human['masked_verification_notes'], notes)
        saved = verification_service.decision_history(self.case, self.evidence, self.aid, self.db)[0]
        self.assertIn('\nReason: ', saved['masked_verification_notes'])

    def test_readable_questions_survive_preview_and_html(self):
        from modules.presentation import report_sections
        data = (b'From: Alice Example <alice@example.test>\nTo: recipient@example.test\n'
                b'Subject: Urgent account verification\n\n'
                b'Verify your account immediately or your account will be suspended. '
                b'Provide login details at https://example.test/account-verification')
        title = 'Account verification investigation'
        purpose = 'Contact the sender and examine any suspicious findings.'
        self.case, self.evidence = self.register(data=data, title=title, description=purpose)
        self.aid = run_analysis(self.evidence, self.db, self.root)['analysis_id']
        reason = 'The email creates urgency and asks for login credentials.'
        notes = 'The sender and verification link should be independently checked.'
        self.did = self.submit(decision_reason=reason, notes=notes)['decision_id']
        questions = ['Why is this email suspicious?', 'Are there any suspicious links?']
        responses = [qa_service.ask(self.case, self.evidence, question, self.aid, self.db, self.root) for question in questions]
        self.assertIn('urgency', responses[0]['display_answer'])
        self.assertIn('account suspension', responses[0]['display_answer'])
        self.assertIn('login details', responses[0]['display_answer'])
        link_answer = ('The email contains an account-verification link. Do not open it until '
                       'the sender and destination have been independently verified.')
        self.assertEqual(responses[1]['display_answer'], link_answer)
        version_reason = 'Initial report created after completing investigator verification.'
        preview = reports.preview_report(self.case, self.evidence, self.aid, self.did, self.db, self.root,
                                         version_reason=version_reason)
        report = self.generate(version_reason=version_reason)
        for document in (preview, self.manifest(report)):
            sections = report_sections(document)
            self.assertEqual(sections['Case details'], {'Title': title, 'Purpose': purpose})
            self.assertEqual([item['Question'] for item in sections['Questions and answers']], questions)
            self.assertEqual(sections['Questions and answers'][1]['Answer'], link_answer)
            self.assertNotIn('[PRIVATE]', str(sections))
            self.assertNotIn('alice@example.test', str(document))
            self.assertNotIn('Alice Example', str(document))
            self.assertEqual(document['human_verification']['masked_decision_reason'], reason)
            self.assertEqual(document['human_verification']['masked_verification_notes'], notes)
            self.assertEqual(sections['Report version details']['Reason for this version'], version_reason)
        html = self.download(report).decode().split('<details>')[0]
        for text in (*questions, link_answer, reason, notes, version_reason):
            self.assertIn(text, html)

    def test_completed_report_and_identifiers(self):
        report = self.generate()
        self.assertRegex(report['report_id'], r'^RPT-[A-F0-9]{12}$')
        self.assertEqual(report['status'], 'generated')
        self.assertEqual(report['report_version'], 1)
        self.assertTrue(report['created_at_utc'].endswith('+00:00'))
        data = self.manifest(report)
        self.assertEqual(len(data), 10)
        self.assertEqual(data['case_information']['case_id'], self.case)
        self.assertEqual(data['evidence_information']['evidence_id'], self.evidence)
        self.assertEqual(data['automated_analysis']['analysis_id'], self.aid)
        self.assertEqual(data['human_verification']['decision_id'], self.did)
        self.assertEqual(data['report_integrity']['analysis_version'], 1)
        self.assertEqual(data['report_integrity']['decision_version'], 1)
        self.assertTrue(any(e['event'] == 'REPORT_GENERATED' for e in data['chain_of_custody']['events']))
        folder = self.root / 'reports' / self.case / report['report_id']
        self.assertEqual({p.suffix for p in folder.iterdir()}, {'.html', '.json'})

    def test_blocked_without_decision(self):
        analysis = run_analysis(self.evidence, self.db, self.root)
        with self.assertRaisesRegex(ValidationError, reports.NO_DECISION):
            self.generate(analysis_id=analysis['analysis_id'], decision_id=None)
        self.assertFalse(self.query('SELECT * FROM reports'))

    def test_integrity_fails_after_preview(self):
        preview = reports.preview_report(self.case, self.evidence, self.aid, self.did, self.db, self.root)
        self.assertEqual(preview['evidence_information']['current_integrity_status'], 'Pass')
        self.tamper()
        with self.assertRaisesRegex(ValidationError, reports.BLOCKED):
            self.generate()
        self.assertFalse(self.query('SELECT * FROM reports'))
        self.assertFalse(list((self.root / 'reports').rglob('*.html')))

    def test_automated_and_human_conclusions_separate(self):
        modified = self.submit(decision_type='Modify Conclusion', final_classification='Suspicious',
            change_reason='Additional context reviewed.', version_reason='More evidence reviewed.', expected_previous_id=self.did)
        report = self.generate(decision_id=modified['decision_id'])
        data = self.manifest(report)
        self.assertEqual(data['automated_analysis']['automated_classification'], self.analysis['classification'])
        self.assertEqual(data['human_verification']['human_verified_classification_or_status'], 'Suspicious')
        self.assertEqual(data['final_conclusion'], reports.CONCLUSIONS['modify'])

    def test_conclusions_follow_all_recorded_decisions(self):
        previous = self.did
        for decision in ('Reject Analysis', 'Request Further Analysis'):
            current = self.submit(decision_type=decision, requested_actions=['Inspect email headers'],
                expected_previous_id=previous, version_reason='Additional context reviewed.')
            report = self.generate(decision_id=current['decision_id'])
            data = self.manifest(report)
            self.assertEqual(data['final_conclusion'], reports.CONCLUSIONS[current['decision']])
            previous = current['decision_id']
        self.assertEqual(data['human_verification']['human_verified_classification_or_status'], 'Further analysis required')

    def test_privacy_and_no_absolute_paths(self):
        c = connect_database(self.db)
        with c:
            c.execute('UPDATE cases SET title=?,description=? WHERE case_id=?',
                ('Zorvian Quell synthetic@example.test', 'Review +1 202 555 0100 at C:\\Private\\Zorvian\\secret', self.case))
        c.close()
        qa_service.ask(self.case, self.evidence, 'Who sent this email? Zorvian Quell synthetic@example.test', self.aid, self.db, self.root)
        report = self.generate()
        for kind in ('html', 'json'):
            text = self.download(report, kind).decode('utf-8')
            for private in ('Zorvian', 'Quell', 'synthetic@example.test', 'sender@example.test', 'recipient@example.test',
                            '202 555 0100', 'C:\\Private', str(self.root), 'Test Investigator', 'Fictional Reviewer'):
                self.assertNotIn(private, text)
        self.assertTrue(self.manifest(report)['case_information']['masked_investigator_identifier'].startswith('[INVESTIGATOR-'))

    def test_html_escaping_no_executable_resources(self):
        hostile = '<script>alert("secret")</script><img src="https://example.test/x" onerror="alert(1)"><iframe src="file:///secret">'
        rendered = reports.render_html({'section': {'"<key>': hostile}}).decode()
        self.assertIn('&lt;script&gt;', rendered)
        self.assertIn('&quot;', rendered)
        self.assertNotIn('<script>', rendered)
        class Inspector(HTMLParser):
            def handle_starttag(parser, tag, attrs):
                self.assertNotIn(tag, {'script', 'img', 'iframe', 'link', 'object', 'embed', 'a', 'form'})
                self.assertFalse(any(k.startswith('on') or k in {'src', 'href', 'srcdoc'} for k, v in attrs))
        Inspector().feed(rendered)
        report = self.generate()
        html = self.download(report).decode()
        Inspector().feed(html)
        self.assertNotIn('@import', html)
        self.assertNotIn('url(', html)

    def test_html_hash_and_json_manifest(self):
        report = self.generate()
        html = self.download(report)
        self.assertEqual(sha256_bytes(html), report['report_sha256'])
        data = self.manifest(report)
        self.assertEqual(data['report_integrity']['report_sha256'], report['report_sha256'])
        self.assertIn(reports.HASH_NOTICE.encode(), html)
        self.assertNotIn(report['report_sha256'].encode(), html)
        self.assertEqual(sha256_bytes(self.download(report, 'json')), report['json_sha256'])

    def test_integrity_pass(self):
        self.assertTrue(self.verify(self.generate()))

    def test_integrity_fail_and_download_blocked(self):
        report = self.generate()
        (self.root / report['html_path']).write_bytes(b'<html>Synthetic changed report</html>')
        self.assertFalse(self.verify(report))
        with self.assertRaises(ValidationError):
            self.download(report)
        self.assertTrue(self.query("SELECT * FROM audit_logs WHERE action='REPORT_INTEGRITY_CHECKED' AND status='failure'"))

    def test_manifest_modification_blocks_download(self):
        report = self.generate()
        (self.root / report['json_path']).write_text('{}', encoding='utf-8')
        self.assertTrue(self.verify(report))  # Requested button verifies the HTML hash.
        with self.assertRaises(ValidationError):
            self.download(report, 'json')

    def test_report_versions_preserve_files_and_rows(self):
        first = self.generate()
        before = self.query('SELECT * FROM reports WHERE report_id=?', (first['report_id'],))
        html, manifest = self.download(first), self.download(first, 'json')
        with self.assertRaises(ValidationError):
            self.generate(expected_previous_id=first['report_id'])
        second = self.generate(expected_previous_id=first['report_id'], version_reason='Additional review completed.')
        self.assertEqual(second['report_version'], 2)
        self.assertEqual(second['supersedes_report_id'], first['report_id'])
        self.assertNotEqual(first['html_path'], second['html_path'])
        self.assertEqual(html, self.download(first))
        self.assertEqual(manifest, self.download(first, 'json'))
        self.assertEqual(before, self.query('SELECT * FROM reports WHERE report_id=?', (first['report_id'],)))
        c = connect_database(self.db)
        try:
            for sql in ('UPDATE reports SET status=?', 'DELETE FROM reports WHERE report_id=?'):
                with self.assertRaises(sqlite3.IntegrityError):
                    c.execute(sql, (first['report_id'],))
                c.rollback()
        finally:
            c.close()

    def test_stale_report_version_rejected(self):
        self.generate()
        with self.assertRaisesRegex(ValidationError, 'history changed'):
            self.generate(version_reason='Stale preview.')
        self.assertEqual(len(self.query('SELECT * FROM reports')), 1)

    def test_cross_case_and_cross_analysis_rejected(self):
        other_case, other_evidence = self.register(data=test_evidence.SAMPLE + b'Other synthetic evidence')
        other_analysis = run_analysis(other_evidence, self.db, self.root)
        other_decision = self.submit(case_id=other_case, evidence_id=other_evidence, analysis_id=other_analysis['analysis_id'])
        for changed in ({'case_id': other_case}, {'evidence_id': other_evidence},
                        {'analysis_id': other_analysis['analysis_id']}, {'decision_id': other_decision['decision_id']},
                        {'case_id': '../outside'}, {'decision_id': "' OR 1=1 --"}):
            with self.subTest(changed=changed), self.assertRaises(ValidationError):
                self.generate(**changed)
        self.assertFalse(self.query('SELECT * FROM reports'))
        report = self.generate()
        with self.assertRaises(ValidationError):
            reports.download_bytes(other_case, other_evidence, report['report_id'], 'html', db_path=self.db, data_root=self.root)

    def test_path_traversal_rejected(self):
        report = self.generate()
        for path in ('../outside.html', str(self.root / 'outside.html'), 'reports/other/report.html'):
            forged = dict(report, html_path=path)
            with self.assertRaises(ValidationError):
                reports._read_artifact(forged, 'html', self.root)
        with self.assertRaises(ValidationError):
            reports._report_directory(self.root, '../outside', report['report_id'])

    def test_qa_isolation_and_empty_history(self):
        empty = self.manifest(self.generate())
        self.assertEqual(empty['ask_the_evidence_summary']['message'], reports.EMPTY_QA)
        own = qa_service.ask(self.case, self.evidence, 'Who sent this email?', self.aid, self.db, self.root)
        other_case, other_evidence = self.register(data=test_evidence.SAMPLE + b'Other synthetic evidence')
        other = qa_service.ask(other_case, other_evidence, 'Who sent this email?', db_path=self.db, data_root=self.root)
        # Also test a second evidence row inside the selected case (no copied files needed for Q&A).
        c = connect_database(self.db)
        with c:
            c.execute('UPDATE evidence SET case_id=? WHERE evidence_id=?', (self.case, other_evidence))
            c.execute('UPDATE qa_interactions SET case_id=? WHERE interaction_id=?', (self.case, other['interaction_id']))
        c.close()
        data = reports.preview_report(self.case, self.evidence, self.aid, self.did, self.db, self.root)
        qa = data['ask_the_evidence_summary']['interactions']
        self.assertEqual([r['interaction_id'] for r in qa], [own['interaction_id']])
        self.assertNotIn(other['interaction_id'], json.dumps(data))

    def test_audit_metadata_is_safe(self):
        reports.page_opened(self.case, self.evidence, self.db)
        reports.preview_report(self.case, self.evidence, self.aid, self.did, self.db, self.root)
        first = self.generate()
        self.download(first, audit=True)
        self.verify(first)
        self.generate(expected_previous_id=first['report_id'], version_reason='SECRETXYZ synthetic@example.test')
        with self.assertRaises(ValidationError):
            self.generate(decision_id='secret@example.test')
        rows = self.query("SELECT actor,action,details FROM audit_logs WHERE action LIKE 'REPORT_%'")
        self.assertEqual({r[1] for r in rows}, reports.EVENTS)
        for actor, action, details in rows:
            json.loads(details)
            self.assertEqual(actor, '[INVESTIGATOR]')
            for secret in ('SECRETXYZ', 'synthetic@example.test', 'secret@example.test', 'Fictional Reviewer'):
                self.assertNotIn(secret, details)

    def test_no_network_calls(self):
        with ExitStack() as stack:
            for target in ('socket.socket.connect', 'socket.create_connection', 'socket.getaddrinfo', 'urllib.request.urlopen'):
                stack.enter_context(patch(target, side_effect=AssertionError('Network forbidden')))
            reports.preview_report(self.case, self.evidence, self.aid, self.did, self.db, self.root)
            report = self.generate()
            self.verify(report)
            self.download(report, audit=True)

    def test_original_sources_unchanged(self):
        tables = ('cases', 'evidence', 'analysis_results', 'investigator_decisions', 'qa_interactions')
        before = {t: self.query('SELECT * FROM ' + t) for t in tables}
        files = {p: p.read_bytes() for area in ('evidence', 'working') for p in (self.root / area).rglob('*') if p.is_file()}
        self.generate()
        for t in tables:
            after = self.query('SELECT * FROM ' + t)
            if t == 'cases':
                # Step 7 advances the new workflow_status column only.
                self.assertEqual([r[:8]+r[9:] for r in before[t]], [r[:8]+r[9:] for r in after])
                self.assertEqual(after[0][8], 'Report Generated')
            else:
                self.assertEqual(before[t], after)
        for path, value in files.items():
            self.assertEqual(value, path.read_bytes())

    def test_atomic_write_failure_cleans_new_artifacts(self):
        real_write = reports.atomic_write
        calls = []
        def fail_second(path, data):
            calls.append(path)
            if len(calls) == 2:
                raise OSError('Synthetic disk failure')
            real_write(path, data)
        with patch.object(reports, 'atomic_write', side_effect=fail_second), self.assertRaises(OSError):
            self.generate()
        self.assertFalse(self.query('SELECT * FROM reports'))
        self.assertFalse(list((self.root / 'reports').rglob('*.html')))
        self.assertFalse(self.query("SELECT * FROM audit_logs WHERE action='REPORT_GENERATED'"))

    def test_database_initialization_is_additive(self):
        report = self.generate()
        before = self.query('SELECT * FROM reports')
        initialize_database(self.db)
        initialize_database(self.db)
        self.assertEqual(before, self.query('SELECT * FROM reports'))
        self.assertTrue(self.verify(report))

    def isolated_page(self, active=True):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(verification_service, 'selections', partial(verification_service.selections, db_path=self.db)))
        stack.enter_context(patch.object(qa_service, 'available_analyses', partial(qa_service.available_analyses, db_path=self.db)))
        for name in ('available_decisions', 'page_opened', 'report_history'):
            stack.enter_context(patch.object(reports, name, partial(getattr(reports, name), db_path=self.db)))
        for name in ('preview_report', 'generate_report', 'verify_report_integrity', 'download_bytes'):
            stack.enter_context(patch.object(reports, name, partial(getattr(reports, name), db_path=self.db, data_root=self.root)))
        app = test_evidence.authenticated_app(self, 'pages/5_Forensic_Report.py')
        if active:
            app.session_state['active_case_id'] = self.case
            app.session_state['active_evidence_id'] = self.evidence
        return app.run()

    def test_page_renders_generates_and_versions(self):
        app = self.isolated_page()
        self.assertFalse(app.exception)
        next(b for b in app.button if b.label == 'Generate report').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any(x.value == 'Investigation report generated.' for x in app.success))
        self.assertEqual(len(app.get('download_button')), 2)
        self.assertEqual(len(self.query('SELECT * FROM reports')), 1)
        self.assertTrue(next(b for b in app.button if b.label == 'Generate report').disabled)
        self.assertTrue(any('preserve the previous report' in x.value for x in app.info))
        app.text_area[0].set_value('Additional review completed.').run()
        next(b for b in app.button if b.label == 'Generate report').click().run()
        self.assertFalse(app.exception)
        self.assertEqual(len(self.query('SELECT * FROM reports')), 2)
        self.assertEqual(len(app.get('download_button')), 4)
        next(b for b in app.button if b.label == 'Verify Report Integrity').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any('report integrity verified' in x.value for x in app.success))

    def test_page_no_human_decision(self):
        run_analysis(self.evidence, self.db, self.root)
        app = self.isolated_page()
        self.assertFalse(app.exception)
        self.assertTrue(any(x.value == reports.NO_DECISION for x in app.info))

    def test_page_integrity_failure(self):
        self.tamper()
        app = self.isolated_page()
        self.assertFalse(app.exception)
        self.assertTrue(any(x.value == reports.BLOCKED for x in app.error))
        self.assertTrue(next(b for b in app.button if b.label == 'Generate report').disabled)

    def test_archived_reports_remain_downloadable_read_only(self):
        from modules.case_service import archive_case
        self.generate()
        archive_case(self.case, self.db)
        app = self.isolated_page()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.get('download_button')), 2)
        self.assertTrue(next(b for b in app.button if b.label == 'Generate report').disabled)

    def test_empty_database(self):
        self.db = self.root / 'empty.db'
        app = self.isolated_page(active=False)
        self.assertFalse(app.exception)
        self.assertTrue(any('No active cases' in x.value for x in app.info))
