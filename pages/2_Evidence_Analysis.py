from modules.ui import page_errors

with page_errors():
    """Safe text-only preview of the active evidence."""
    import json
    import streamlit as st
    from modules.ui import setup_page, may
    from modules.auth import AccessDenied, DENIED
    from modules.evidence_handler import get_evidence, evidence_path, verify_integrity, log_event

    setup_page('Evidence Analysis')
    st.title('Evidence Analysis')
    evidence_id = st.session_state.get('active_evidence_id')
    if not evidence_id:
        st.info('Create a case and register evidence on New Investigation first.')
        st.stop()
    try:
        row = get_evidence(evidence_id)
    except AccessDenied:
        st.error(DENIED)
        st.stop()
    if not row:
        st.error('The active evidence record is unavailable.')
        st.stop()

    # One view event per page execution, including refreshes and integrity rechecks.
    log_event(row['investigator_name'], 'Evidence viewed', case_id=row['case_id'], evidence_id=evidence_id,
              details='Masked working representation requested.')
    for label, value in [('Case ID', row['case_id']), ('Evidence ID', evidence_id),
                         ('Original filename', row['original_filename']), ('SHA-256', row['sha256']),
                         ('File size (bytes)', row['file_size']), ('Upload timestamp (UTC)', row['created_at'])]:
        st.caption(label)
        st.code(str(value), language=None)
    recheck = st.button('Verify Integrity Again')
    valid = verify_integrity(evidence_id, audit=recheck)
    if valid:
        st.success('Integrity verified')
    else:
        st.error('Integrity check failed')
    try:
        path = evidence_path(row, working=True)
        if path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError('Working representation exceeds limits.')
        parsed = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        st.error('The masked working representation is unavailable or invalid.')
        st.stop()
    for label, key in [('Masked sender', 'sender'), ('Masked recipient', 'recipient'), ('Cc', 'cc'),
                       ('Reply-To', 'reply_to'), ('Subject', 'subject'), ('Date', 'date'), ('Message-ID', 'message_id')]:
        st.caption(label)
        st.code(parsed.get(key) or '(not present)', language=None)
    st.subheader('Masked plain-text body preview')
    st.code(parsed.get('body') or '(no text body)', language=None)
    st.subheader('Extracted URLs (non-clickable)')
    for url in parsed.get('urls', []):
        st.code(url.replace('https://', 'hxxps://').replace('http://', 'hxxp://').replace('.', '[.]'), language=None)
    st.subheader('Attachments (metadata only)')
    for attachment in parsed.get('attachments', []):
        st.code(f"Name: {attachment['name']}\nType: {attachment['type']}\nSize: {attachment['size']} bytes", language=None)
    if parsed.get('selected_csv_row'):
        st.caption(f"Registered CSV data row: {parsed['selected_csv_row']}")
    for warning in parsed.get('warnings', []):
        st.warning(warning)
    if parsed.get('truncated'):
        st.warning('Analysis content was truncated. The original evidence remains complete and unchanged.')

    # Analysis uses hash-verified original bytes in memory, never the preview text as
    # instructions. Only masked results are returned and persisted.
    from modules.analysis_service import run_analysis, analysis_history, view_analysis, IntegrityFailure
    from modules.phishing_analyzer import DISCLAIMER, SCORE_LABEL

    st.subheader('Local rule-based phishing analysis')
    st.info(DISCLAIMER)
    st.caption(SCORE_LABEL)
    history = analysis_history(evidence_id)
    button_label = 'Run New Analysis Version' if history else 'Run Phishing Analysis'
    if st.button(button_label, type='primary', disabled=not may('analyze', row['case_id'])):
        try:
            new_result = run_analysis(evidence_id)
            st.session_state['selected_analysis_' + evidence_id] = new_result['analysis_id']
            history = analysis_history(evidence_id)
            st.rerun()
        except IntegrityFailure:
            st.error('Integrity check failed. Analysis refused and recorded in the audit log.')
        except Exception:
            st.error('Analysis could not be completed. A rule-processing error was recorded; previous results are preserved.')

    if history:
        choices = {item[0]: f'Version {item[1]} | {item[2]} | {item[3]} | {item[4]}/100' for item in history}
        selected = st.selectbox('Analysis history (latest 100 versions)', list(choices),
                                format_func=choices.get, key='selected_analysis_' + evidence_id)
        result = view_analysis(selected, evidence_id)
        if not valid:
            st.warning('Historical result only: current evidence integrity has failed. This result is not a new analysis.')
        if result['risk_level'] == 'High':
            st.error(result['classification'])
        elif result['risk_level'] == 'Medium':
            st.warning(result['classification'])
        else:
            st.info(result['classification'])
        st.metric('Rule-based risk score', f"{result['risk_score']}/100")
        st.caption(SCORE_LABEL)
        st.text(f"Risk level: {result['risk_level']} | {result['score_calculation']}")
        st.info(DISCLAIMER)
        st.text(f"Engine: {result['engine_version']} | Ruleset: {result['ruleset_version']}\n"
                f"Analysis time (UTC): {result['analysis_timestamp']}\n"
                f"Analysis ID: {result['analysis_id']} | Version: {result['analysis_version']}")
        st.subheader('Evidence-linked findings')
        if not result['findings']:
            st.text('No configured indicators were detected. Absence of indicators does not establish safety.')
        for finding in result['findings']:
            with st.expander(f"{finding['indicator']} | {finding['severity']} | +{finding['score_contribution']} points"):
                st.text('Evidence source: ' + finding['evidence_source'])
                snippet = finding['masked_evidence'].replace('https://', 'hxxps://').replace('http://', 'hxxp://')
                st.code(snippet, language=None)
                st.text('Explanation: ' + finding['explanation'])
                st.text('Manual verification: ' + finding['manual_verification'])
        st.subheader('Reported authentication')
        st.text(result['authentication_note'])
        for mechanism, values in result['authentication'].items():
            st.text(mechanism.upper() + ': ' + (', '.join(values) if values else 'Unavailable'))
        st.subheader('Missing or unavailable information')
        for item in result['missing_information']:
            st.text('- ' + item)
        st.subheader('Manual verification checklist')
        st.caption('Suggested checks. Record your decision on Human Verification after reviewing the evidence.')
        for item in result['recommended_verification']:
            st.text('\u2610 ' + item)
