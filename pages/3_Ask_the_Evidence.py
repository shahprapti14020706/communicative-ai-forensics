from modules.ui import page_errors

with page_errors():
    """Controlled local Q&A over selected masked evidence and stored analysis."""
    import streamlit as st
    from modules.ui import setup_page, page_permission, technical_details
    from modules.qa_engine import MAX_QUESTION, MAX_MESSAGES
    from modules.presentation import SUGGESTIONS, UNSUPPORTED, classification, plain_answer, finding_text, NEXT_STEPS
    from modules.qa_service import (available_analyses, load_context, ask, page_event, conversation_key,
                                    append_visible, clear_visible, ScopeError)

    setup_page('Ask About the Email')
    page_permission('ask')
    st.title('Ask About the Email')
    st.write('Ask simple questions about the selected email.')
    case_id = st.session_state.get('active_case_id')
    evidence_id = st.session_state.get('active_evidence_id')
    if not case_id or not evidence_id:
        st.info('Select a case and evidence by registering or opening evidence on New Investigation first.')
        st.stop()
    try:
        history = available_analyses(case_id, evidence_id)
        analysis_id = None
        if history:
            choices = {item['analysis_id']: f"Analysis {item['analysis_version']}" for item in history}
            selection_key = 'qa_analysis_' + case_id + '_' + evidence_id
            previous_selection = st.session_state.get('selected_analysis_' + evidence_id)
            if selection_key not in st.session_state or st.session_state[selection_key] not in choices:
                st.session_state[selection_key] = previous_selection if previous_selection in choices else next(iter(choices))
            analysis_id = st.selectbox('Analysis to review', list(choices), format_func=choices.get, key=selection_key)
        context = load_context(case_id, evidence_id, analysis_id)
        page_event(case_id, evidence_id, 'Ask-the-Evidence page opened')
    except ScopeError:
        st.error('The selected case, evidence or analysis do not match. Reopen the intended evidence before asking questions.')
        st.stop()
    except Exception:
        st.error('The selected records could not be loaded. No original evidence was opened.')
        st.stop()

    metadata, analysis = context['metadata'], context.get('analysis')
    st.text('Selected email: ' + metadata['original_filename'])
    if analysis:
        st.text('Result: ' + classification(analysis['classification']))
    else:
        st.info('Analyze the email first to ask about warning signs.')
    if not context.get('working'):
        st.warning('The email preview is unavailable. Some questions cannot be answered.')

    key = conversation_key(case_id, evidence_id, analysis_id)
    if st.button('Clear Conversation'):
        clear_visible(st.session_state, key, case_id, evidence_id)
        st.session_state.pop(key + ':limit', None)
        st.info('Conversation cleared from this view.')


    question = None
    columns = st.columns(2)
    for index, suggestion in enumerate(SUGGESTIONS):
        if columns[index % 2].button(suggestion, key='qa_suggestion_' + str(index), use_container_width=True):
            question = suggestion
    chat_question = st.chat_input('Ask about the selected email', max_chars=MAX_QUESTION)
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
        st.warning('Showing the latest 50 messages. Earlier questions remain saved.')

    # The transcript is display-only and partitioned by case, evidence and analysis.
    # Every submission above reloads evidence; none of these messages feed the engine.
    for interaction in st.session_state.get(key, []):
        with st.chat_message('user'):
            st.caption('Investigator question (masked)')
            st.text(interaction['question'])
        with st.chat_message('assistant'):
            if interaction['status'] in {'unsupported', 'insufficient', 'clarification'}:
                st.text(UNSUPPORTED)
            else:
                st.text(plain_answer(interaction.get('display_answer') or interaction['answer']))
            if interaction['status'] == 'completed':
                st.caption('Sources reviewed')
                for ref in interaction['evidence_references']:
                    if ref['source'] in {'System scope', 'Question matcher'}:
                        continue
                    st.text('Email analysis' if 'analysis' in ref['source'].lower() else 'Email information')
                    field = ref.get('field', '')
                    if field in {'sender', 'recipient', 'subject', 'body', 'reply_to', 'urls', 'attachments'} or field.endswith('.masked_evidence'):
                        st.code(plain_answer(ref['snippet']).replace('https://', 'hxxps://').replace('http://', 'hxxp://'), language=None)
            technical_details(interaction)
