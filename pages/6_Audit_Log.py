from modules.ui import page_errors

with page_errors():
    """Local custody timeline for the active case."""
    import streamlit as st
    from modules.ui import setup_page, page_permission
    from modules.case_service import audit_history

    setup_page('Audit Log')
    page_permission('audit')
    st.title('Audit Log')
    case_id = st.session_state.get('active_case_id')
    rows = audit_history(case_id)
    st.caption('Latest 500 events for the active case and unassigned validation events. Timestamps are UTC.')
    if rows:
        st.dataframe(rows, hide_index=True)
    else:
        st.info('No matching custody events have been recorded.')
