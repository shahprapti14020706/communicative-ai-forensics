from modules.ui import page_errors

with page_errors():
    import json
    import streamlit as st
    from modules.ui import setup_page, may, technical_details
    from modules.evidence_handler import get_evidence, evidence_path, verify_integrity, log_event
    from modules.analysis_service import run_analysis, analysis_history, view_analysis, IntegrityFailure
    from modules.presentation import classification, finding_text, DISCLAIMER, NEXT_STEPS

    setup_page('Email Analysis')
    st.title('Email Analysis')
    evidence_id = st.session_state.get('active_evidence_id')
    if not evidence_id:
        st.info('Create a case and upload an email on New Investigation first.')
        st.stop()
    row = get_evidence(evidence_id)
    if not row:
        st.error('The selected email is unavailable.')
        st.stop()
    log_event(row['investigator_name'], 'Evidence viewed', case_id=row['case_id'], evidence_id=evidence_id,
              details='Masked working representation requested.')
    st.text('Selected email: ' + row['original_filename'])
    recheck = st.button('Check Email Integrity')
    valid = verify_integrity(evidence_id, audit=recheck)
    if valid:
        st.success('Email integrity checked')
    else:
        st.error('The stored email has changed or is unavailable. Investigation actions are blocked.')
    try:
        path = evidence_path(row, working=True)
        if path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError('Working representation exceeds limits.')
        parsed = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        st.error('The email preview is unavailable.')
        st.stop()
    with st.expander('Email preview'):
        for label, field in [('Sender', 'sender'), ('Recipient', 'recipient'), ('Subject', 'subject'), ('Message', 'body')]:
            st.caption(label)
            st.code(parsed.get(field) or 'Not available', language=None)
        st.caption('Links')
        for url in parsed.get('urls', []):
            st.code(url.replace('https://', 'hxxps://').replace('http://', 'hxxp://').replace('.', '[.]'), language=None)
        st.caption('Attachments')
        for item in parsed.get('attachments', []):
            st.text(item['name'])
    if parsed.get('truncated'):
        st.warning('Only part of this email could be reviewed.')
    st.subheader('Email Safety Analysis')
    history = analysis_history(evidence_id)
    if st.button('Run Analysis Again' if history else 'Analyze Email', type='primary', disabled=not may('analyze', row['case_id'])):
        try:
            result = run_analysis(evidence_id)
            st.session_state['selected_analysis_' + evidence_id] = result['analysis_id']
            st.rerun()
        except IntegrityFailure:
            st.error('The email integrity check failed. Analysis was blocked.')
        except Exception:
            st.error('Analysis could not be completed. Please try again.')
    if history:
        choices = {r[0]: ('Latest analysis' if i == 0 else f'Earlier analysis {len(history)-i}') for i, r in enumerate(history)}
        selected = st.selectbox('Analysis to review', list(choices), format_func=choices.get, key='selected_analysis_' + evidence_id)
        result = view_analysis(selected, evidence_id)
        if not valid:
            st.warning('This is a previous result. The current email could not be verified.')
        with st.container(border=True):
            display = {'High': st.error, 'Medium': st.warning, 'Low': st.success}[result['risk_level']]
            display('Result: ' + classification(result['classification']))
            st.metric('Risk Score', f"{result['risk_score']}/100")
            st.text('Risk Level: ' + result['risk_level'])
        st.subheader('Why This Email May Be Suspicious')
        for message in dict.fromkeys(finding_text(f) for f in result['findings']):
            st.text('- ' + message)
        if not result['findings']:
            st.text('No warning signs were found in the available information.')
        st.subheader('What Could Not Be Confirmed')
        st.text('The sender identity, linked websites and attachment contents have not been independently confirmed.')
        if result['missing_information']:
            st.text('Some email information is missing or could not be checked.')
        st.subheader('What You Should Do')
        for message in NEXT_STEPS:
            st.text('- ' + message)
        technical_details(result)
    st.caption(DISCLAIMER)
    technical_details({'evidence': {key: row[key] for key in ('case_id', 'evidence_id', 'sha256', 'file_size', 'created_at')}, 'preview_warnings': parsed.get('warnings', [])})
