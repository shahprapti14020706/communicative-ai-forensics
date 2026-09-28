"""Metadata-only, authenticated investigation dashboard."""
import streamlit as st
from modules import ui, auth
from modules.case_service import list_cases, open_case
from modules.workflow import case_progress, recent_events
from modules.encryption import MESSAGE

with ui.page_errors():
    ui.setup_page('Dashboard')
    st.title('Communicative AI in Digital Forensics')
    st.caption('Academic prototype | A Human-in-the-Loop Framework for Cybercrime Investigation')
    user = auth.current_user(ui.AUTH_DB_PATH)
    st.text('Logged-in user: ' + user['user_id'] + ' | Role: ' + user['role'])
    st.caption('Generated account identifier shown to protect personal information.')
    st.warning(MESSAGE)
    cases = list_cases(db_path=ui.AUTH_DB_PATH)
    st.metric('Accessible cases', len(cases))
    ids = [row['case_id'] for row in cases]
    active = st.session_state.get('active_case_id')
    if any(row['case_id'] == active and row['masked_title'] == 'SYNTHETIC DEMONSTRATION' for row in cases):
        st.info('SYNTHETIC DEMONSTRATION — fictional sample evidence')
    if ids:
        selected = st.selectbox('Select accessible case', ids, index=ids.index(active) if active in ids else None)
        if st.button('Open selected case', disabled=selected is None):
            evidence = open_case(selected, db_path=ui.AUTH_DB_PATH)
            token = st.session_state['auth_token']
            st.session_state.clear()
            st.session_state.update(auth_token=token, active_case_id=selected)
            if evidence:
                st.session_state['active_evidence_id'] = evidence[0]
            st.rerun()
    else:
        st.info('No accessible cases. Create a synthetic investigation or ask an administrator for a case assignment.')
    progress = case_progress(active, ui.AUTH_DB_PATH)
    fields = [('Active case', active or 'None selected'), ('Case status', progress['status']),
              ('Evidence count', progress['evidence_count']), ('Latest analysis classification', progress['classification']),
              ('Human verification', progress['stages']['Human Decision Recorded']),
              ('Report status', progress['stages']['Report Generated'])]
    columns = st.columns(3)
    for index, (label, value) in enumerate(fields):
        with columns[index % 3].container(border=True):
            st.caption(label)
            st.text(str(value))
    st.subheader('Workflow progress')
    st.dataframe([{'Stage': stage, 'Status': status} for stage, status in progress['stages'].items()], hide_index=True)
    st.caption('Integrity reflects the last recorded check. Questions Reviewed means a supported interaction was recorded after the latest analysis; it does not certify human understanding. Earlier versions remain preserved.')
    st.subheader('Recommended next action')
    st.info(progress['next_action'])
    if user['role'] == 'Reviewer':
        st.caption('Reviewer access: review assigned evidence and record human decisions. Ask an investigator to run analysis, Q&A or generate reports.')
    next_permission = {'pages/1_New_Investigation.py': 'upload',
                       'pages/3_Ask_the_Evidence.py': 'ask'}.get(progress['next_page'], 'read')
    if st.button('Continue investigation', disabled=next_permission not in auth.PERMISSIONS[user['role']]):
        st.switch_page(progress['next_page'])
    st.subheader('Recent safe audit events')
    events = recent_events(active, ui.AUTH_DB_PATH)
    if events:
        st.dataframe(events, hide_index=True)
    else:
        st.info('No recent events are available for this selection.')
    st.caption('The dashboard displays identifiers and status metadata only.')
