from modules.ui import page_errors

with page_errors():
    """Assigned case browsing and administrator lifecycle controls."""
    import streamlit as st
    from modules.ui import setup_page, may, page_permission
    from modules.case_service import (list_cases, open_case, archive_case, deletion_preview, request_deletion,
                                     delete_case, pending_deletions, finish_deletion, DELETION_WARNING)

    setup_page('User and Case Management')
    page_permission('admin')
    st.title('User and Case Management')
    if st.button('Manage users and assignments'):
        st.switch_page('pages/8_User_Management.py')
    search = st.text_input('Search by case ID or title', max_chars=200)
    cases = list_cases(search)
    if cases:
        st.dataframe(cases, hide_index=True)
        choices = {r['case_id']:r for r in cases}
        selected = st.selectbox('Accessible case', list(choices))
        if st.button('Open case'):
            evidence = open_case(selected)
            token = st.session_state['auth_token']
            st.session_state.clear()
            st.session_state['auth_token'] = token
            st.session_state['active_case_id'] = selected
            if evidence:
                st.session_state['active_evidence_id'] = evidence[0]
            st.success('Case opened.')
        if may('archive'):
            if st.button('Archive case'):
                archive_case(selected)
                st.rerun()
            if choices[selected]['status']=='Archived':
                st.warning(DELETION_WARNING)
                try:
                    st.write('The following application files and records will be removed:')
                    st.json(deletion_preview(selected))
                    if st.button('Mark case for deletion'):
                        request_deletion(selected)
                        st.success('Case marked for deletion by this administrator. Enter the exact confirmation to proceed.')
                    confirmation = st.text_input('Enter DELETE ' + selected, key='delete_'+selected)
                    if st.button('Permanently delete marked case', disabled=confirmation != 'DELETE '+selected):
                        result = delete_case(selected, confirmation)
                        if st.session_state.get('active_case_id') == selected:
                            token = st.session_state['auth_token']
                            st.session_state.clear()
                            st.session_state['auth_token'] = token
                        st.success('Case records removed. File cleanup status: ' + result['status'])
                except ValueError:
                    st.error('Deletion is unavailable. Check that this administrator marked the case and that all paths are valid.')
                except OSError:
                    st.error('Local file access prevented deletion. Existing records were retained, or cleanup remains pending.')
    else:
        st.info('No accessible cases match the search.')
    if may('admin'):
        for job in pending_deletions():
            st.warning('Pending file cleanup: ' + job['job_id'])
            if st.button('Retry file cleanup', key=job['job_id']):
                try:
                    finish_deletion(job['job_id'])
                    st.rerun()
                except (OSError, ValueError):
                    st.error('Cleanup could not be completed. Check local storage permissions.')
