"""Authenticated investigation home."""
import streamlit as st
from modules import ui
from modules.case_service import list_cases, open_case

with ui.page_errors():
    ui.setup_page('Home')
    st.title('Communicative AI Digital Forensics Assistant')
    st.write('A local investigation tool that helps review suspicious emails while keeping the investigator in control.')
    with st.container(border=True):
        st.subheader('Investigation workflow')
        st.write('Create Case → Upload Email → Review Analysis → Ask Questions → Record Decision → Generate Report')
    if st.button('Start New Investigation', type='primary', disabled=not ui.may('upload')):
        st.switch_page('pages/1_New_Investigation.py')
    cases = list_cases(db_path=ui.AUTH_DB_PATH)
    labels = {r['case_id']: r['masked_title'] for r in cases}
    if cases:
        st.subheader('Continue an investigation')
        ids = list(labels)
        active = st.session_state.get('active_case_id')
        selected = st.selectbox('Select case', ids, format_func=labels.get,
                                index=ids.index(active) if active in ids else None)
        if st.button('Open selected case', disabled=selected is None):
            evidence = open_case(selected, db_path=ui.AUTH_DB_PATH)
            token = st.session_state['auth_token']
            st.session_state.clear()
            st.session_state.update(auth_token=token, active_case_id=selected)
            if evidence:
                st.session_state['active_evidence_id'] = evidence[0]
            st.switch_page('pages/2_Evidence_Analysis.py')
