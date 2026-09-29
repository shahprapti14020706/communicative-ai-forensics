from modules.ui import page_errors

with page_errors():
    import streamlit as st
    from modules import ui
    from modules.ui import setup_page, page_permission, technical_details, render_workflow_progress
    from modules.case_service import audit_history, list_cases
    from modules.activity_service import activity_history, record_activity_view
    from modules.audit import SAFE_ACTIONS
    from modules.presentation import date_label

    progress_slot = setup_page('Activity History')
    user = page_permission('activity')
    st.title('Activity History')
    case_id = st.session_state.get('active_case_id')
    if user['role'] == 'Administrator':
        choices = [None] + [row['case_id'] for row in list_cases(db_path=ui.AUTH_DB_PATH)]
        selected = st.selectbox('Case filter', choices, index=choices.index(case_id) if case_id in choices else 0,
                                format_func=lambda value: value or 'All cases')
        event = st.selectbox('Event filter', [None] + sorted(SAFE_ACTIONS), format_func=lambda value: value or 'All events')
        status = st.selectbox('Status filter', [None, 'success', 'failure', 'pending'], format_func=lambda value: value or 'All statuses')
        offset = st.number_input('History offset', min_value=0, step=500, help='Shows up to 500 matching events. Increase the offset to view older records.')
        rows = audit_history(selected, db_path=ui.AUTH_DB_PATH, event_filter=event, status_filter=status, offset=offset)
        st.dataframe(rows, hide_index=True, use_container_width=True)
        technical_details(rows)
    else:
        if not case_id:
            st.info('Select an investigation to view its activity history.')
            st.stop()
        rows = activity_history(case_id, db_path=ui.AUTH_DB_PATH)
        activities = [{'Date': date_label(row['timestamp_utc']), 'Activity': row['activity'], 'Status': row['status']} for row in rows]
        if activities:
            st.dataframe(activities, hide_index=True, use_container_width=True)
        else:
            st.info('No activities have been recorded for this selection.')
    if case_id:
        record_activity_view(case_id, db_path=ui.AUTH_DB_PATH)
        render_workflow_progress(progress_slot, case_id)
