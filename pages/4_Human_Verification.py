from modules.ui import page_errors

with page_errors():
    import json
    import streamlit as st
    from modules.ui import setup_page, may, technical_details, case_labels, email_label
    from modules.presentation import classification, finding_text, date_label, decision_label
    from modules.qa_service import available_analyses
    from modules.verification_service import (selections, open_review, record_decision, decision_history,
        private_text, decision_text, CLASSIFICATIONS, ACTIONS, CONFIRMATION)

    setup_page('Investigator Review')
    st.title('Investigator Review')
    def show_decision(item):
        st.text('Decision: ' + decision_label(item['final_classification'] or 'Needs More Investigation'))
        saved_notes, saved_reason = decision_text(item)
        st.text('Reason: ' + saved_reason)
        st.text('Notes: ' + saved_notes)
        st.caption(date_label(item['created_at_utc'] or item['created_at']))
        if item['requested_actions']:
            try:
                requests = json.loads(item['requested_actions'])
                for action in requests.get('actions', []):
                    st.text(action if action in ACTIONS else '[PRIVATE]')
                if requests.get('other_description'):
                    st.text(private_text(requests['other_description']))
            except (ValueError, TypeError, AttributeError):
                st.text('Earlier requested checks are unavailable.')
        technical_details(dict(item))

    st.subheader('Selected email')
    cases, _ = selections(include_archived=True)
    if not cases:
        st.info('No active cases are available. Register evidence in New Investigation first.')
        st.stop()
    active = st.session_state.get('active_case_id')
    case_id = st.selectbox('Active case', cases, format_func=case_labels().get, index=cases.index(active) if active in cases else None,
                           placeholder='Select an active case')
    if not case_id:
        st.info('Select an active case to continue.')
        st.stop()
    if st.session_state.get('active_case_id') != case_id:
        st.session_state.pop('active_evidence_id', None)
    st.session_state['active_case_id'] = case_id
    _, evidence_ids = selections(case_id, include_archived=True)
    if not evidence_ids:
        st.info('No evidence is available for this case.')
        st.stop()
    active_evidence = st.session_state.get('active_evidence_id')
    evidence_id = st.selectbox('Selected email', evidence_ids, format_func=email_label,
        index=evidence_ids.index(active_evidence) if active_evidence in evidence_ids else None,
        key='hv_evidence_' + case_id, placeholder='Select evidence')
    if not evidence_id:
        st.info('Select evidence to continue.')
        st.stop()
    st.session_state['active_evidence_id'] = evidence_id
    analyses = available_analyses(case_id, evidence_id)
    if not analyses:
        st.info('Analyze the email on Email Analysis before recording a human decision.')
        st.stop()
    choices = {r['analysis_id']: f"Analysis {r['analysis_version']}" for r in analyses}
    analysis_id = st.selectbox('Analysis to review', list(choices), format_func=choices.get,
                                key='hv_analysis_' + case_id + evidence_id)
    try:
        review = open_review(case_id, evidence_id, analysis_id)
    except Exception:
        st.error('Review could not be loaded. Check the active case, evidence and analysis selection.')
        st.stop()
    analysis = review['analysis']
    valid = review['integrity_valid']
    if not valid:
        st.error('The email integrity check failed. A decision cannot be recorded.')
    st.subheader('Analysis summary')
    st.text('Result: ' + classification(analysis['classification']))
    st.metric('Risk Score', str(analysis['risk_score']) + '/100')
    for finding in analysis['findings']:
        st.text(finding_text(finding))
    if not analysis['findings']:
        st.text('No warning signs were found in the available information.')
    with st.expander('Supporting email excerpts'):
        for finding in analysis['findings']:
            st.text(private_text(finding['masked_evidence']))
    st.caption('Review the sender, links and attachments before deciding. A low score does not establish safety.')
    technical_details({'sha256': review['sha256'], 'analysis': analysis})
    st.subheader('Investigator’s decision')
    history = review['history']
    previous_id = history[0]['decision_id'] if history else None
    if history:
        st.info('Recording a new version will preserve the previous decision.')
        with st.expander('Previous decision'):
            show_decision(history[0])
    scope_key = case_id + evidence_id + analysis_id + (previous_id or 'first')
    choice = st.selectbox('Investigator’s decision', ['Confirm as Suspicious', 'Mark as Safe',
                          'Needs More Investigation', 'Update the Conclusion'], key='hv_type_' + scope_key)
    target = {'Confirm as Suspicious': 'Suspicious', 'Mark as Safe': 'No Significant Indicators Detected'}.get(choice)
    decision_type = ('Approve Analysis' if target == analysis['classification'] else 'Modify Conclusion') if target else (
        'Request Further Analysis' if choice == 'Needs More Investigation' else 'Modify Conclusion')
    # Conditional widgets rerun immediately and each review/version has its own scope.
    prefix = scope_key + choice
    name = st.text_input('Investigator name', type='password', max_chars=200, key=prefix + 'name')
    final = target
    change_reason = ''
    actions = []
    other = ''
    if choice == 'Update the Conclusion':
        final = st.selectbox('Updated conclusion', CLASSIFICATIONS, format_func=classification, index=None, key=prefix + 'final')
    change_reason = st.text_area('Reason for the decision', max_chars=5000, key=prefix + 'change')
    if decision_type == 'Request Further Analysis':
        actions = [action for action in ACTIONS if st.checkbox(action, key=prefix + action)]
        if 'Other' in actions:
            other = st.text_area('Other request description', max_chars=5000, key=prefix + 'other')
    notes = st.text_area('Notes', max_chars=5000, help='Enter at least 20 characters.', key=prefix + 'notes')
    version_reason = st.text_area('Reason for updating the previous decision', max_chars=5000, key=prefix + 'version') if history else ''
    confirmed = st.checkbox(CONFIRMATION, key=prefix + 'confirmed')
    ready = (may('decide', case_id) and valid and bool(name.strip()) and len(notes.strip()) >= 20 and confirmed and bool(change_reason.strip())
             and (not history or bool(version_reason.strip()))
             and (decision_type != 'Modify Conclusion' or (final in CLASSIFICATIONS and final != analysis['classification'] and bool(change_reason.strip())))
             and (decision_type != 'Request Further Analysis' or (bool(actions) and ('Other' not in actions or bool(other.strip())))))
    if st.button('Submit Decision', type='primary', disabled=not ready, key=prefix + 'submit'):
        try:
            result = record_decision(case_id, evidence_id, analysis_id, name, decision_type, notes, confirmed,
                final_classification=final, requested_actions=actions, other_description=other,
                decision_reason=change_reason, change_reason=change_reason, version_reason=version_reason, expected_previous_id=previous_id)
            st.session_state['hv_receipt_' + case_id + evidence_id + analysis_id] = result
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
        except Exception:
            st.error('Decision could not be recorded. Reload the review and try again.')
    receipt = st.session_state.get('hv_receipt_' + case_id + evidence_id + analysis_id)
    if receipt:
        st.success('Your decision has been recorded.')
        show_decision(receipt)
    st.subheader('Decision history')
    history = decision_history(case_id, evidence_id, analysis_id)
    if not history:
        st.info('No human decisions have been recorded for this analysis version.')
    for item in history:
        with st.expander(date_label(item['created_at_utc'] or item['created_at'])):
            show_decision(item)
