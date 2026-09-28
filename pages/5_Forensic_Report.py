from modules.ui import page_errors

with page_errors():
    """Local, versioned HTML and JSON reports; no embedded report HTML is executed."""
    import streamlit as st
    from modules.ui import setup_page, may
    from modules.verification_service import selections
    from modules.qa_service import available_analyses
    from modules.report_generator import (available_decisions, page_opened, preview_report, generate_report,
        report_history, verify_report_integrity, download_bytes, NO_DECISION, BLOCKED)

    setup_page('Forensic Report')
    st.title('Forensic Report')
    st.write('Generate an offline academic report from selected evidence, automated findings and a recorded human decision.')
    st.caption('HTML reports use a black-and-white print layout. Open the downloaded HTML locally and use your browser’s Print to PDF option. No PDF-generation service is used.')


    def log_download(case, evidence, report, kind):
        try:
            download_bytes(case, evidence, report, kind, audit=True)
        except Exception:
            st.error('Download integrity validation failed. Reload the report history.')


    def show_report(row):
        for label, value in [('Report ID', row['report_id']), ('Report version', row['report_version']),
                             ('UTC timestamp', row['created_at_utc']), ('Report SHA-256', row['report_sha256'])]:
            st.caption(label)
            st.code(str(value), language=None) if label == 'Report SHA-256' else st.text(str(value))
        if row['supersedes_report_id']:
            st.text('Supersedes report: ' + row['supersedes_report_id'])
        if row['masked_version_reason']:
            st.text('Version reason: ' + row['masked_version_reason'])
        if st.button('Verify Report Integrity', key='verify_' + row['report_id']):
            try:
                valid = verify_report_integrity(case_id, evidence_id, row['report_id'])
                if valid:
                    st.success('Pass — report integrity verified.')
                else:
                    st.error('Fail — report integrity verification failed.')
            except Exception:
                st.error('Fail — report integrity verification could not be completed.')
        try:
            html = download_bytes(case_id, evidence_id, row['report_id'], 'html')
            manifest = download_bytes(case_id, evidence_id, row['report_id'], 'json')
        except Exception:
            st.error('Report files are unavailable or changed. Downloads are blocked.')
            return
        filename = row['report_id'] + '-v' + str(row['report_version'])
        st.download_button('Download HTML report', html, file_name=filename + '.html', mime='text/html',
            key='html_' + row['report_id'], on_click=log_download, args=(case_id, evidence_id, row['report_id'], 'html'))
        st.download_button('Download JSON report', manifest, file_name=filename + '.json', mime='application/json',
            key='json_' + row['report_id'], on_click=log_download, args=(case_id, evidence_id, row['report_id'], 'json'))


    st.subheader('1. Select active case')
    cases, _ = selections(include_archived=True)
    if not cases:
        st.info('No active cases are available. Register evidence in New Investigation first.')
        st.stop()
    active_case = st.session_state.get('active_case_id')
    case_id = st.selectbox('Active case', cases, index=cases.index(active_case) if active_case in cases else None)
    if not case_id:
        st.info('Select an active case to continue.')
        st.stop()
    if st.session_state.get('active_case_id') != case_id:
        st.session_state.pop('active_evidence_id', None)
    st.session_state['active_case_id'] = case_id
    st.subheader('2. Select evidence item')
    _, evidence_ids = selections(case_id, include_archived=True)
    if not evidence_ids:
        st.info('No evidence is available for this case.')
        st.stop()
    active_evidence = st.session_state.get('active_evidence_id')
    evidence_id = st.selectbox('Evidence', evidence_ids,
        index=evidence_ids.index(active_evidence) if active_evidence in evidence_ids else None, key='report_evidence_' + case_id)
    if not evidence_id:
        st.info('Select evidence to continue.')
        st.stop()
    st.session_state['active_evidence_id'] = evidence_id
    try:
        page_opened(case_id, evidence_id)
        analyses = available_analyses(case_id, evidence_id)
    except Exception:
        st.error('The selected case and evidence could not be loaded.')
        st.stop()
    st.subheader('3. Select analysis version')
    if not analyses:
        st.info('Run Phishing Analysis before generating a report.')
        st.stop()
    choices = {r['analysis_id']: f"Version {r['analysis_version']} | {r['analysis_timestamp']}" for r in analyses}
    analysis_id = st.selectbox('Analysis version', list(choices), format_func=choices.get, key='report_analysis_' + case_id + evidence_id)
    st.subheader('4. Select human-decision version')
    decisions = available_decisions(case_id, evidence_id, analysis_id)
    if not decisions:
        # Use the same service gate as generation to record a safe blocked event.
        try:
            preview_report(case_id, evidence_id, analysis_id, None)
        except Exception:
            pass
        st.info(NO_DECISION)
        st.stop()
    decision_choices = {r['decision_id']: f"Version {r['decision_version']} | {r['decision_type']} | {r['created_at_utc']}" for r in decisions}
    decision_id = st.selectbox('Human-decision version', list(decision_choices), format_func=decision_choices.get,
                               key='report_decision_' + case_id + evidence_id + analysis_id)
    scope = case_id + evidence_id + analysis_id + decision_id
    st.subheader('5. Verify evidence integrity')
    document = None
    try:
        document = preview_report(case_id, evidence_id, analysis_id, decision_id)
        st.success('Pass — evidence integrity verified.')
    except ValueError as exc:
        st.error(BLOCKED if str(exc) == BLOCKED else 'Report preview is unavailable. Check the selected analysis and completed human decision.')
    except Exception:
        st.error('Report preview could not be loaded. No report was generated.')
    st.caption('Original evidence is freshly hashed for the preview and again immediately before report generation.')
    st.subheader('6. Preview report')
    if document:
        left, right = st.columns(2)
        with left:
            st.write('Automated Result')
            st.text(document['automated_analysis']['automated_classification'])
            st.text(str(document['automated_analysis']['rule_based_risk_score']) + '/100')
            st.text(document['automated_analysis']['score_statement'])
        with right:
            st.write('Human-Verified Result')
            st.text(document['human_verification']['human_verified_classification_or_status'])
            st.text(document['final_conclusion'])
        st.write('Supporting Evidence')
        for finding in document['automated_analysis']['findings']:
            st.text(finding['indicator'])
            st.text(finding['explanation'])
            st.text(finding['masked_supporting_snippet'])
        if not document['automated_analysis']['findings']:
            st.text('No configured indicators were detected.')
        st.write('Limitations')
        for limitation in document['limitations']:
            st.text(limitation)
        with st.expander('Full structured preview'):
            st.json(document)
        st.caption('This preview has no report ID or authoritative hash. Generation records a fresh immutable snapshot.')
    st.subheader('7. Generate report')
    try:
        history = report_history(case_id, evidence_id, analysis_id, decision_id)
    except Exception:
        st.error('Report history is unavailable. Generation is blocked.')
        st.stop()
    previous_id = history[0]['report_id'] if history else None
    reason = ''
    if history:
        st.info('Creating a new version will preserve the previous report.')
        st.text('Previous report: ' + previous_id + ' | Version ' + str(history[0]['report_version']))
        reason = st.text_area('Reason for creating a new report version', max_chars=5000, key=scope + previous_id + 'reason')
    if st.button('Generate report', type='primary', disabled=not may('report_generate', case_id) or document is None or (bool(history) and not reason.strip())):
        try:
            result = generate_report(case_id, evidence_id, analysis_id, decision_id, version_reason=reason,
                                     expected_previous_id=previous_id)
            st.session_state['report_receipt_' + scope] = result['report_id']
            st.rerun()
        except ValueError as exc:
            st.error(BLOCKED if str(exc) == BLOCKED else 'Report generation was blocked. Reload the preview and review the latest version.')
        except Exception:
            st.error('Report generation failed. Existing reports and source records are preserved.')
    st.subheader('8. Download report')
    receipt = st.session_state.get('report_receipt_' + scope)
    latest = history[0] if history else None
    if latest:
        if receipt == latest['report_id']:
            st.success('Forensic report generated successfully.')
        show_report(latest)
    else:
        st.info('Generate a report to enable HTML and JSON downloads.')
    st.subheader('9. View previously generated reports')
    if not history:
        st.info('No reports have been generated for this decision.')
    for row in history:
        with st.expander('Report ' + row['report_id'] + ' | Version ' + str(row['report_version'])):
            if latest and row['report_id'] == latest['report_id']:
                st.text('This is the latest report. Its download and verification controls appear above.')
                st.text(row['created_at_utc'])
            else:
                show_report(row)
