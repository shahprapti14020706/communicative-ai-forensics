from modules.ui import page_errors

with page_errors():
    """Step 5: human decisions remain separate from automated findings."""
    import json
    import streamlit as st
    from modules.ui import setup_page, may
    from modules.qa_service import available_analyses
    from modules.phishing_analyzer import RULES
    from modules.verification_service import (selections, open_review, record_decision, decision_history,
        private_text, DECISIONS, CLASSIFICATIONS, ACTIONS, WARNING, CONFIRMATION, BLOCKED)

    setup_page('Human Verification')
    st.title('Human Verification')
    st.warning(WARNING)
    st.caption('Local review only. Names are stored as masked investigator identifiers. Free text uses conservative masking; unfamiliar words and personal details are suppressed.')


    def show_decision(item):
        human_status = {'approve': 'Analysis approved; legacy classification unavailable',
                        'reject': 'Analysis rejected; no final classification',
                        'modify': 'Conclusion modified; legacy classification unavailable',
                        'reanalyse': 'Further analysis required'}
        for label, value in [
            ('Decision ID', item['decision_id']), ('Decision version', item['decision_version'] or 'Legacy'),
            ('UTC timestamp', item['created_at_utc'] or item['created_at']),
            ('Decision type', item['decision_type'] or item['decision']),
            ('Automated conclusion', item['automated_classification'] or 'Unavailable in legacy record'),
            ('Human-verified conclusion or status', item['final_classification'] or human_status.get(item['decision'], 'Legacy decision')),
        ]:
            st.caption(label)
            st.text(str(value))
        st.caption('Masked verification notes')
        st.text(private_text(item['masked_verification_notes'] or item['rationale']))
        if item['masked_change_reason']:
            st.text('Reason for changed conclusion: ' + private_text(item['masked_change_reason']))
        if item['masked_version_reason']:
            st.text('Reason for new version: ' + private_text(item['masked_version_reason']))
        if item['supersedes_decision_id']:
            st.text('Supersedes decision: ' + item['supersedes_decision_id'])
        if item['requested_actions']:
            try:
                requests = json.loads(item['requested_actions'])
                for action in requests.get('actions', []):
                    st.text(action if action in ACTIONS else '[PRIVATE]')
                if requests.get('other_description'):
                    st.text(private_text(requests['other_description']))
            except (ValueError, TypeError, AttributeError):
                st.text('Legacy requests unavailable.')


    st.subheader('1. Select evidence')
    cases, _ = selections(include_archived=True)
    if not cases:
        st.info('No active cases are available. Register evidence in New Investigation first.')
        st.stop()
    active = st.session_state.get('active_case_id')
    case_id = st.selectbox('Active case', cases, index=cases.index(active) if active in cases else None,
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
    evidence_id = st.selectbox('Evidence', evidence_ids,
        index=evidence_ids.index(active_evidence) if active_evidence in evidence_ids else None,
        key='hv_evidence_' + case_id, placeholder='Select evidence')
    if not evidence_id:
        st.info('Select evidence to continue.')
        st.stop()
    st.session_state['active_evidence_id'] = evidence_id
    analyses = available_analyses(case_id, evidence_id)
    if not analyses:
        st.info('Run Phishing Analysis on Evidence Analysis before recording a human decision.')
        st.stop()
    choices = {r['analysis_id']: f"Version {r['analysis_version']} | {r['analysis_timestamp']}" for r in analyses}
    analysis_id = st.selectbox('Analysis version', list(choices), format_func=choices.get,
                                key='hv_analysis_' + case_id + evidence_id)
    try:
        review = open_review(case_id, evidence_id, analysis_id)
    except Exception:
        st.error('Review could not be loaded. Check the active case, evidence and analysis selection.')
        st.stop()
    analysis = review['analysis']
    st.subheader('2. Verify integrity')
    valid = review['integrity_valid']
    if valid:
        st.success('Evidence integrity verified')
    else:
        st.error(BLOCKED)
    st.caption('Evidence SHA-256')
    st.code(str(review['sha256']), language=None)
    st.caption('Integrity is checked again against the original file when a decision is submitted.')
    st.subheader('3. Review automated findings')
    st.text('Automated classification: ' + analysis['classification'])
    st.metric('Rule-based risk score', str(analysis['risk_score']) + '/100')
    st.caption('This score is a rule-based indicator, not a probability of phishing.')
    for finding in analysis['findings']:
        rule = RULES.get(finding['rule_id'])
        indicator = rule[0] if rule and finding['indicator'] == rule[0] else private_text(finding['indicator'])
        st.text('Detected indicator: ' + indicator)
        st.text('Explanation: ' + private_text(finding['explanation']))
    if not analysis['findings']:
        st.text('No configured indicators were detected. This does not establish safety.')
    st.subheader('4. Review masked supporting evidence')
    for finding in analysis['findings']:
        st.text('Source: ' + private_text(finding['evidence_source']))
        st.text(private_text(finding['masked_evidence']))
    st.caption('Only conservatively masked finding excerpts are shown; the original message body is not displayed.')
    st.write('Analysis limitations')
    st.text('Deterministic rules can produce false positives and miss malicious content. Sender identity, link destinations and attachments have not been externally verified. Masking can remove useful context. Integrity confirms bytes match the registered hash, not authenticity or safety.')
    for limitation in analysis['missing_information']:
        st.text(private_text(limitation))
    st.subheader('5. Record human decision')
    history = review['history']
    previous_id = history[0]['decision_id'] if history else None
    if history:
        st.info('Recording a new version will preserve the previous decision.')
        with st.expander('Previous decision', expanded=True):
            show_decision(history[0])
    scope_key = case_id + evidence_id + analysis_id + (previous_id or 'first')
    decision_type = st.selectbox('Decision type', list(DECISIONS), key='hv_type_' + scope_key)
    st.text({'Approve Analysis': 'The investigator agrees with the automated classification.',
             'Reject Analysis': 'The investigator does not accept the automated classification.',
             'Modify Conclusion': 'The investigator selects a different final classification without changing the original automated result.',
             'Request Further Analysis': 'Additional examination is required before reaching a final conclusion.'}[decision_type])
    # Conditional widgets rerun immediately and each review/version has its own scope.
    prefix = scope_key + decision_type
    name = st.text_input('Investigator name', type='password', max_chars=200, key=prefix + 'name')
    final = None
    change_reason = ''
    actions = []
    other = ''
    if decision_type == 'Modify Conclusion':
        final = st.selectbox('Final classification', CLASSIFICATIONS, index=None, key=prefix + 'final')
        change_reason = st.text_area('Reason for changing the classification', max_chars=5000, key=prefix + 'change')
    if decision_type == 'Request Further Analysis':
        actions = [action for action in ACTIONS if st.checkbox(action, key=prefix + action)]
        if 'Other' in actions:
            other = st.text_area('Other request description', max_chars=5000, key=prefix + 'other')
    notes = st.text_area('Verification notes (at least 20 characters)', max_chars=5000, key=prefix + 'notes')
    version_reason = st.text_area('Reason for creating a new version', max_chars=5000, key=prefix + 'version') if history else ''
    confirmed = st.checkbox(CONFIRMATION, key=prefix + 'confirmed')
    ready = (may('decide', case_id) and valid and bool(name.strip()) and len(notes.strip()) >= 20 and confirmed
             and (not history or bool(version_reason.strip()))
             and (decision_type != 'Modify Conclusion' or (final in CLASSIFICATIONS and final != analysis['classification'] and bool(change_reason.strip())))
             and (decision_type != 'Request Further Analysis' or (bool(actions) and ('Other' not in actions or bool(other.strip())))))
    if st.button('Record human decision', type='primary', disabled=not ready, key=prefix + 'submit'):
        try:
            result = record_decision(case_id, evidence_id, analysis_id, name, decision_type, notes, confirmed,
                final_classification=final, requested_actions=actions, other_description=other,
                change_reason=change_reason, version_reason=version_reason, expected_previous_id=previous_id)
            st.session_state['hv_receipt_' + case_id + evidence_id + analysis_id] = result
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
        except Exception:
            st.error('Decision could not be recorded. Reload the review and check the local database.')
    receipt = st.session_state.get('hv_receipt_' + case_id + evidence_id + analysis_id)
    if receipt:
        st.success('Human verification decision recorded successfully.')
        show_decision(receipt)
    st.subheader('6. View decision history')
    history = decision_history(case_id, evidence_id, analysis_id)
    if not history:
        st.info('No human decisions have been recorded for this analysis version.')
    for item in history:
        with st.expander('Decision ' + item['decision_id']):
            show_decision(item)
