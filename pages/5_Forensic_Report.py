from modules.ui import page_errors

with page_errors():
    """Reports are saved securely, and previous versions remain available for review."""
    import streamlit as st
    from modules.ui import setup_page, may, technical_details, case_labels, email_label
    from modules.presentation import classification, date_label, report_sections
    from modules.verification_service import selections
    from modules.qa_service import available_analyses
    from modules.report_generator import (available_decisions, page_opened, preview_report, generate_report,
        report_history, verify_report_integrity, download_bytes, NO_DECISION, BLOCKED)

    setup_page('Investigation Report')
    st.title('Investigation Report')
    st.write('Review the investigation and generate a report.')
    st.caption('Download the report and open it in a browser to print or save as PDF.')


    def log_download(case, evidence, report, kind):
        try:
            download_bytes(case, evidence, report, kind, audit=True)
        except Exception:
            st.error('Download integrity validation failed. Reload the report history.')


    def show_report(row):
        st.caption('Generated: ' + date_label(row['created_at_utc']))
        technical_details(dict(row))
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
        from modules import auth, ui
        if auth.current_user(ui.AUTH_DB_PATH)['role'] == 'Administrator':
            with st.expander('Technical Details'):
                st.download_button('Download JSON report', manifest, file_name=filename + '.json', mime='application/json',
                    key='json_' + row['report_id'], on_click=log_download, args=(case_id, evidence_id, row['report_id'], 'json'))



    st.subheader('Case')
    cases, _ = selections(include_archived=True)
    if not cases:
        st.info('No active cases are available. Register evidence in New Investigation first.')
        st.stop()
    active_case = st.session_state.get('active_case_id')
    case_id = st.selectbox('Active case', cases, format_func=case_labels().get, index=cases.index(active_case) if active_case in cases else None)
    if not case_id:
        st.info('Select an active case to continue.')
        st.stop()
    if st.session_state.get('active_case_id') != case_id:
        st.session_state.pop('active_evidence_id', None)
    st.session_state['active_case_id'] = case_id
    st.subheader('Email')
    _, evidence_ids = selections(case_id, include_archived=True)
    if not evidence_ids:
        st.info('No evidence is available for this case.')
        st.stop()
    active_evidence = st.session_state.get('active_evidence_id')
    evidence_id = st.selectbox('Selected email', evidence_ids, format_func=email_label,
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
    st.subheader('Analysis')
    if not analyses:
        st.info('Analyze the email before generating a report.')
        st.stop()
    choices = {r['analysis_id']: f"Analysis {r['analysis_version']}" for r in analyses}
    analysis_id = st.selectbox('Analysis to include', list(choices), format_func=choices.get, key='report_analysis_' + case_id + evidence_id)
    st.subheader('Investigator review')
    decisions = available_decisions(case_id, evidence_id, analysis_id)
    if not decisions:
        # Use the same service gate as generation to record a safe blocked event.
        try:
            preview_report(case_id, evidence_id, analysis_id, None)
        except Exception:
            pass
        st.info(NO_DECISION)
        st.stop()
    decision_choices = {r['decision_id']: f"Review {r['decision_version']} | {date_label(r['created_at_utc'])}" for r in decisions}
    decision_id = st.selectbox('Decision to include', list(decision_choices), format_func=decision_choices.get,
                               key='report_decision_' + case_id + evidence_id + analysis_id)
    scope = case_id + evidence_id + analysis_id + decision_id
    st.subheader('Generate report')
    try:
        history = report_history(case_id, evidence_id, analysis_id, decision_id)
    except Exception:
        st.error('Report history is unavailable. Generation is blocked.')
        st.stop()
    previous_id = history[0]['report_id'] if history else None
    if history:
        st.info('Creating a new version will preserve the previous report.')

    reason = st.text_area('Reason for creating a new report version', max_chars=5000, key=scope + (previous_id or 'first') + 'reason')
    st.subheader('Email check')
    document = None
    try:
        document = preview_report(case_id, evidence_id, analysis_id, decision_id, version_reason=reason)
        st.success('Pass — evidence integrity verified.')
    except ValueError as exc:
        st.error(BLOCKED if str(exc) == BLOCKED else 'Report preview is unavailable. Check the selected analysis and completed human decision.')
    except Exception:
        st.error('Report preview could not be loaded. No report was generated.')

    st.subheader('Report preview')
    if document:
        for heading, value in report_sections(document).items():
            st.subheader(heading)
            if isinstance(value, dict):
                for label, text in value.items():
                    if isinstance(text, list):
                        st.text(label + ':')
                        for entry in text:
                            st.text('- ' + str(entry))
                    else:
                        st.text(label + ': ' + str(text))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        for label, text in item.items():
                            st.text(label + ': ' + str(text))
                    else:
                        st.text(str(item))
                if not value:
                    st.text('None recorded.')
            else:
                st.text(str(value))
        from modules import auth, ui
        if auth.current_user(ui.AUTH_DB_PATH)['role'] == 'Administrator':
            with st.expander('Technical Record'):
                st.json(document)
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
    st.subheader('Download report')
    receipt = st.session_state.get('report_receipt_' + scope)
    latest = history[0] if history else None
    if latest:
        if receipt == latest['report_id']:
            st.success('Investigation report generated.')
        show_report(latest)
    else:
        st.info('Generate a report to download it.')
    st.subheader('Previous reports')
    if not history:
        st.info('No reports have been generated for this decision.')
    for row in history:
        with st.expander('Report ' + str(row['report_version']) + ' | ' + date_label(row['created_at_utc'])):
            if latest and row['report_id'] == latest['report_id']:
                st.text('This is the latest report. Its download and verification controls appear above.')
                st.text(date_label(row['created_at_utc']))
            else:
                show_report(row)
