"""Shared presentation; never render evidence as HTML."""

import streamlit as st
import sqlite3
from contextlib import contextmanager
from modules import auth
from modules.database import DEFAULT_DB_PATH, initialize_database, connect_database
from modules.encryption import encryption_status

AUTH_DB_PATH = DEFAULT_DB_PATH


@contextmanager
def page_errors():
    """A final safe boundary for storage failures anywhere in a page execution."""
    try:
        yield
    except auth.AccessDenied:
        st.error(auth.DENIED + ' Sign in again or ask your administrator to check case access.')
        st.stop()
    except (sqlite3.Error, OSError):
        st.error('Local storage is temporarily unavailable. Close competing operations, check storage permissions and retry. Existing records are preserved.')
        st.stop()
    except (ValueError, TypeError, KeyError, AttributeError):
        st.error('The selected record is missing or malformed. Reopen the case and check its integrity. No automatic repair was attempted.')
        st.stop()


def require_login():
    initialize_database(AUTH_DB_PATH)
    try:
        return auth.current_user(AUTH_DB_PATH, token=st.session_state.get('auth_token'), touch=True)
    except auth.AccessDenied:
        if st.session_state.get('auth_token'):
            st.session_state.clear()
            st.warning('Your session expired or was revoked. Sign in again to continue.')
    st.title('Local investigator login')
    st.caption('Ask the local administrator to create your account. First setup: python -m modules.auth create-admin')
    with st.form('local_login', clear_on_submit=True):
        username = st.text_input('Username', max_chars=64)
        password = st.text_input('Password', type='password', max_chars=1024)
        submitted = st.form_submit_button('Login')
    if submitted:
        token = auth.login(username, password, AUTH_DB_PATH)
        if token:
            st.session_state.clear()
            st.session_state['auth_token'] = token
            st.rerun()
        st.error(auth.FAILURE)
    st.stop()


def page_permission(action):
    try:
        return auth.require_permission(action, db_path=AUTH_DB_PATH)
    except auth.AccessDenied:
        st.error(auth.DENIED)
        st.stop()


def may(action, case_id=None):
    try:
        user = auth.current_user(AUTH_DB_PATH)
        if action not in auth.PERMISSIONS[user['role']]:
            return False
        if case_id and action in {'upload','analyze','ask','decide','report_generate'}:
            connection = connect_database(AUTH_DB_PATH)
            try:
                row = connection.execute('SELECT archived_at_utc,deletion_requested_at_utc,status FROM cases WHERE case_id=?', (case_id,)).fetchone()
                return bool(row and not row[0] and not row[1] and row[2] != 'closed' and auth.can_access(connection, user, case_id))
            finally:
                connection.close()
        return True
    except auth.AccessDenied:
        return False

LIMITATION = (
    "This system is an academic proof-of-concept. It provides AI-assisted investigative "
    "leads and is not an operational forensic tool. Final conclusions must be verified "
    "by a qualified human investigator."
)


def setup_page(title: str) -> None:
    st.set_page_config(page_title=f"{title} | Communicative AI Forensics", layout="wide")
    user = require_login()
    if st.session_state.get('active_case_id') or st.session_state.get('active_evidence_id'):
        try:
            auth.require_permission('read', st.session_state.get('active_case_id'),
                                    st.session_state.get('active_evidence_id'), AUTH_DB_PATH)
        except auth.AccessDenied:
            token = st.session_state.get('auth_token')
            st.session_state.clear()
            st.session_state['auth_token'] = token
            st.error(auth.DENIED)
            st.stop()
    # Only static, developer-owned CSS is rendered as HTML.
    st.markdown(
        """<style>
        .stApp { background-color: #ffffff; color: #111111; }
        h1, h2, h3 { color: #12345a !important; }
        [data-testid="stSidebar"] { background-color: #f2f5f9; }
        [data-testid="stVerticalBlockBorderWrapper"] { border-radius: 8px; }
        pre, code { white-space: pre-wrap !important; overflow-wrap: anywhere; }
        </style>""",
        unsafe_allow_html=True,
    )
    with st.sidebar:
        st.title("Investigator workspace")
        st.text('User: ' + user['user_id'])
        st.text('Role: ' + user['role'])
        st.text('Current case: ' + str(st.session_state.get('active_case_id') or 'None'))
        if st.button('Logout'):
            auth.logout(st.session_state.get('auth_token'), st.session_state, AUTH_DB_PATH)
            st.rerun()
        st.caption(encryption_status(AUTH_DB_PATH)['message'])
        for page, label in [('app.py','Dashboard'),
            ('pages/1_New_Investigation.py','New Investigation'), ('pages/2_Evidence_Analysis.py','Evidence Analysis'),
            ('pages/3_Ask_the_Evidence.py','Ask the Evidence'), ('pages/4_Human_Verification.py','Human Verification'),
            ('pages/5_Forensic_Report.py','Forensic Report'), ('pages/6_Audit_Log.py','Audit Log'),
            ('pages/7_Case_Management.py','User and Case Management'),
            ('pages/9_About_the_Prototype.py','About the Prototype')]:
            if page == 'pages/7_Case_Management.py' and user['role'] != 'Administrator':
                continue
            if st.button(label, key='navigate_' + page):
                st.switch_page(page)
        if st.session_state.get('active_case_id'):
            from modules.workflow import case_progress
            progress = case_progress(st.session_state['active_case_id'], AUTH_DB_PATH)
            with st.expander('Active case progress'):
                for stage, status in progress['stages'].items():
                    st.text(stage + ': ' + status)
                st.caption(progress['next_action'])
        st.caption("Local academic prototype")
        st.info("Use the page navigation above to move through the workflow.")
        st.warning(LIMITATION)


def card(title: str, description: str) -> None:
    with st.container(border=True):
        st.subheader(title)
        st.write(description)


def placeholder(title: str, introduction: str, functions: list[tuple[str, str]]) -> None:
    setup_page(title)
    st.title(title)
    st.write(introduction)
    st.info("Planned capability · This page is an interface placeholder. No evidence is processed here.")
    for heading, description in functions:
        card(heading, description)
