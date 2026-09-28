from modules.ui import page_errors

with page_errors():
    """Administrator-only local users and assignments. No credential fields are read back."""
    import streamlit as st
    from modules.ui import setup_page, page_permission
    from modules.auth import list_users, create_user, set_enabled, reset_password, ROLES
    from modules.case_service import list_cases, assign_case

    setup_page('User Management')
    administrator = page_permission('admin')
    st.title('User Management')
    st.caption('Passwords require at least 12 characters, uppercase, lowercase, a number and a special character.')
    with st.form('create_user', clear_on_submit=True):
        username = st.text_input('Username', max_chars=64)
        role = st.selectbox('Role', ROLES)
        password = st.text_input('Password', type='password', max_chars=1024)
        confirmation = st.text_input('Confirm password', type='password', max_chars=1024)
        if st.form_submit_button('Create user'):
            try:
                if password != confirmation:
                    raise ValueError('Password confirmation failed.')
                create_user(username, password, role)
                st.success('User created.')
            except Exception:
                st.error('User creation failed. Check the requirements and choose an unused username.')
    users = list_users()
    st.dataframe(users, hide_index=True)
    if users:
        options = {u['user_id']:u for u in users}
        selected = st.selectbox('Account', list(options), format_func=lambda value: options[value]['username'] + ' | ' + options[value]['role'])
        enabled = st.checkbox('Account enabled', value=bool(options[selected]['enabled']), key=selected)
        if st.button('Save account status'):
            try:
                set_enabled(selected, enabled)
                if selected == administrator['user_id'] and not enabled:
                    st.session_state.clear()
                    st.rerun()
                st.success('Account status saved.')
            except ValueError:
                st.error('Account status could not be changed. The last enabled administrator must remain enabled.')
        with st.form('reset_password', clear_on_submit=True):
            new_password = st.text_input('New password', type='password', max_chars=1024)
            confirm_password = st.text_input('Confirm new password', type='password', max_chars=1024)
            if st.form_submit_button('Reset password'):
                try:
                    if new_password != confirm_password:
                        raise ValueError('Password confirmation failed.')
                    reset_password(selected, new_password)
                    if selected == administrator['user_id']:
                        st.session_state.clear()
                        st.rerun()
                    st.success('Password reset. Existing sessions for this user were revoked.')
                except ValueError:
                    st.error('Password reset failed. Check the password requirements.')
        cases = list_cases()
        if cases:
            case_id = st.selectbox('Case assignment', [c['case_id'] for c in cases])
            active = st.checkbox('Assignment active', value=True)
            if st.button('Save case assignment'):
                try:
                    assign_case(case_id, selected, active)
                    st.success('Case assignment saved.')
                except ValueError:
                    st.error('Assignment could not be saved. Select an enabled user.')
