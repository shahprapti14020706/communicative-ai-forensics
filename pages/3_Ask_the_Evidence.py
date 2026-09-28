from modules.ui import page_errors

with page_errors():
    """Controlled local Q&A over selected masked evidence and stored analysis."""
    import streamlit as st
    from modules.ui import setup_page, page_permission
    from modules.qa_engine import SUGGESTIONS, MAX_QUESTION, MAX_MESSAGES
    from modules.qa_service import (available_analyses, load_context, ask, page_event, conversation_key,
                                    append_visible, clear_visible, ScopeError)

    setup_page('Ask the Evidence')
    page_permission('ask')
    st.title('Ask the Evidence')
    st.write('Deterministic local answers from masked evidence and the selected analysis. No language model or external service is used.')
    case_id = st.session_state.get('active_case_id')
    evidence_id = st.session_state.get('active_evidence_id')
    if not case_id or not evidence_id:
        st.info('Select a case and evidence by registering or opening evidence on New Investigation first.')
        st.stop()
    try:
        history = available_analyses(case_id, evidence_id)
        analysis_id = None
        if history:
            choices = {item['analysis_id']: f"Version {item['analysis_version']} | {item['analysis_timestamp']}" for item in history}
            selection_key = 'qa_analysis_' + case_id + '_' + evidence_id
            previous_selection = st.session_state.get('selected_analysis_' + evidence_id)
            if selection_key not in st.session_state or st.session_state[selection_key] not in choices:
                st.session_state[selection_key] = previous_selection if previous_selection in choices else next(iter(choices))
            analysis_id = st.selectbox('Selected analysis version (latest 100)', list(choices), format_func=choices.get, key=selection_key)
        context = load_context(case_id, evidence_id, analysis_id)
        page_event(case_id, evidence_id, 'Ask-the-Evidence page opened')
    except ScopeError:
        st.error('The selected case, evidence or analysis do not match. Reopen the intended evidence before asking questions.')
        st.stop()
    except Exception:
        st.error('The selected records could not be loaded. No original evidence was opened.')
        st.stop()

    metadata, analysis = context['metadata'], context.get('analysis')
    for label, value in [('Active Case ID', case_id), ('Active Evidence ID', evidence_id),
                         ('Evidence filename', metadata['original_filename']),
                         ('Selected classification', analysis['classification'] if analysis else 'No completed analysis'),
                         ('Selected risk score', str(analysis['risk_score']) + '/100 — not a probability' if analysis else 'Unavailable'),
                         ('Selected analysis version', str(analysis['analysis_version']) if analysis else 'Unavailable')]:
        st.caption(label)
        st.code(str(value), language=None)
    integrity = context.get('integrity')
    if integrity:
        st.info(('Last recorded integrity check: passed' if integrity['status'] == 'success' else 'Last recorded integrity check: failed') + ' | ' + integrity['created_at'])
    else:
        st.info('No recorded integrity verification is available.')
    st.caption('Q&A reports the stored integrity check only. Use Verify Integrity Again on Evidence Analysis for a fresh check.')
    if not context.get('working'):
        st.warning('Masked working JSON is unavailable. Evidence-field questions will identify missing information; originals are never used as a fallback.')
    if not analysis:
        st.info('Run Phishing Analysis first for classification, score, findings and analysis-related questions. Metadata questions remain available.')

    key = conversation_key(case_id, evidence_id, analysis_id)
    if st.button('Clear Conversation'):
        clear_visible(st.session_state, key, case_id, evidence_id)
        st.session_state.pop(key + ':limit', None)
        st.info('Visible conversation cleared. Persisted Q&A records and audit events are retained.')

    st.caption(f'Questions: maximum {MAX_QUESTION} characters. Conversation: latest {MAX_MESSAGES} messages. Answers: at most 10 snippets of 250 characters.')
    question = None
    columns = st.columns(2)
    for index, suggestion in enumerate(SUGGESTIONS):
        if columns[index % 2].button(suggestion, key='qa_suggestion_' + str(index), use_container_width=True):
            question = suggestion
    chat_question = st.chat_input('Ask about the selected evidence', max_chars=MAX_QUESTION)
    if chat_question:
        question = chat_question
    if question:
        try:
            result = ask(case_id, evidence_id, question, analysis_id)
            if append_visible(st.session_state, key, result):
                st.session_state[key + ':limit'] = True
        except ValueError as exc:
            # Validation messages are developer-owned, never the question or raw evidence.
            st.error(str(exc) if len(question) > MAX_QUESTION or not question.strip() else 'Question could not be processed for the selected evidence. Check the selected scope and audit log.')
        except Exception:
            st.error('Question processing failed. A safe error event was recorded; no original evidence was opened.')
    if st.session_state.get(key + ':limit'):
        st.warning('The 50-message display limit was reached. Older messages are hidden; persisted interactions and audit records remain unchanged.')

    # The transcript is display-only and partitioned by case, evidence and analysis.
    # Every submission above reloads evidence; none of these messages feed the engine.
    for interaction in st.session_state.get(key, []):
        with st.chat_message('user'):
            st.caption('Investigator question (masked)')
            st.text(interaction['question'])
        with st.chat_message('assistant'):
            st.caption('System answer — deterministic evidence retrieval')
            st.text(interaction['answer'])
            st.caption('Evidence sources and masked supporting evidence')
            for ref in interaction['evidence_references']:
                st.text(ref['source'] + ' | ' + ref['field'])
                snippet = ref['snippet'].replace('https://', 'hxxps://').replace('http://', 'hxxp://')
                st.code(snippet, language=None)
            st.caption('Limitations')
            for limitation in interaction['limitations']:
                st.text(limitation)
            for limit in interaction['limits_reached']:
                st.warning(limit)
            st.caption('Interaction ' + interaction['interaction_id'] + ' | UTC ' + interaction['created_at'])
