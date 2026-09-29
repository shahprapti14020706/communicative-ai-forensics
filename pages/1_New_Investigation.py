from modules.ui import page_errors

with page_errors():
    """Create a case and upload authorized evidence."""
    from pathlib import Path
    import streamlit as st
    from modules.ui import setup_page, page_permission
    from modules.email_parser import csv_rows, parse_email
    from modules.privacy import mask_evidence
    from modules.evidence_handler import (register_evidence, validate_upload, sha256_bytes,
                                          DuplicateEvidence, log_event)

    setup_page('New Investigation')
    page_permission('upload')
    st.title('New Investigation')
    st.write('Create a case and upload the email you want to review.')
    with st.container(border=True):
        st.subheader('Investigation details')
        title = st.text_input('Case title', placeholder='Enter a short case title')
        investigator = st.text_input('Investigator name', placeholder='Enter your name')
        description = st.text_area('Case description', placeholder='Briefly describe the investigation')
        source = st.text_input('Evidence source', placeholder='For example: reported email')
    with st.container(border=True):
        st.subheader('Upload Email')
        st.caption('Use authorized evidence only. Personal details are masked in the working copy.')
        authorized = st.checkbox('I confirm that I am authorised to process this evidence and that it is synthetic, anonymised or lawfully obtained.')
        if not authorized:
            st.session_state.pop('intake_evidence', None)
        upload = st.file_uploader('Select email evidence', type=['eml', 'txt', 'csv'],
                                  disabled=not authorized, key='intake_evidence',
                                  help='Local evidence only: .eml, .txt or .csv, maximum 10 MB.')


    selected_row = None
    preview_error = None
    if upload is not None and authorized and Path(upload.name).suffix.lower() == '.csv':
        try:
            data = upload.getvalue()
            digest = sha256_bytes(data)
            validate_upload(upload.name, data)
            rows, warnings = csv_rows(data)
            selected_row = st.selectbox('CSV row to register (data row number)', [row[0] for row in rows], key=f'csv_row_{digest}')
            preview = mask_evidence(parse_email(data, '.csv', selected_row))
            st.caption('Masked preview of selected row')
            st.code(preview['subject'] + '\n' + preview['body'][:3000], language=None)
            for warning in preview['warnings']:
                st.warning(warning)
        except ValueError as exc:
            preview_error = str(exc)
            st.error(preview_error)
            key = (upload.name, sha256_bytes(upload.getvalue()))
            if st.session_state.get('invalid_csv_logged') != key:
                log_event(investigator, 'Validation failure', 'failure', details='CSV preview validation failed.')
                st.session_state['invalid_csv_logged'] = key


    if st.button('Create Case and Upload Email', type='primary'):
        try:
            case_id, evidence_id = register_evidence(
                title, investigator, description, source, authorized,
                upload.name if upload else '', upload.getvalue() if upload else b'', selected_row)
            st.session_state['active_case_id'] = case_id
            st.session_state['active_evidence_id'] = evidence_id
            st.session_state.pop('duplicate_evidence', None)
            st.success('Case created and email uploaded.')

        except DuplicateEvidence as exc:
            st.session_state['duplicate_evidence'] = (exc.case_id, exc.evidence_id)
        except ValueError as exc:
            st.error(str(exc))
        except Exception:
            st.error('Registration failed. No evidence was registered. Check local storage permissions and the audit log.')

    def cancel_duplicate():
        st.session_state.pop('duplicate_evidence', None)
        st.session_state.pop('intake_evidence', None)


    if st.session_state.get('duplicate_evidence'):
        case_id, evidence_id = st.session_state['duplicate_evidence']
        st.warning('Duplicate email found. You can open the existing email below.')

        st.button('Cancel duplicate upload', on_click=cancel_duplicate)
        if st.button('Open existing evidence'):
            st.session_state['active_case_id'] = case_id
            st.session_state['active_evidence_id'] = evidence_id
            st.switch_page('pages/2_Evidence_Analysis.py')
    if st.session_state.get('active_evidence_id'):
        if st.button('Open Email Analysis'):
            st.switch_page('pages/2_Evidence_Analysis.py')
