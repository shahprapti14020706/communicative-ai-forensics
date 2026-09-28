"""Host-configured demonstration accounts; never a browser-supplied signup path."""
import streamlit as st

from modules import auth
from modules.database import DEFAULT_DB_PATH, connect_database, initialize_database

MESSAGE = 'Demo account configuration is invalid. Ask the deployment owner to check the bootstrap secrets. Existing accounts are unchanged.'
SECTIONS = (('bootstrap_admin', 'Administrator'), ('bootstrap_investigator', 'Investigator'))


class BootstrapError(ValueError):
    """A fixed, credential-free error safe for the UI."""


def _configured_accounts():
    accounts = []
    try:
        for section, role in SECTIONS:
            try:
                config = st.secrets[section]
            except KeyError:
                continue
            username = auth._username(config['username'])
            password = config['password']
            display_name = config.get('display_name', '')
            if (not isinstance(password, str) or not isinstance(display_name, str)
                    or len(display_name) > 120 or any(ord(char) < 32 for char in display_name)):
                raise BootstrapError(MESSAGE)
            if any(account[0] == username for account in accounts):
                raise BootstrapError(MESSAGE)
            accounts.append((username, password, role, display_name))
    except FileNotFoundError as exc:
        # Streamlit uses this type for absent files and wraps TOML parse errors.
        # Missing local secrets are optional; malformed TOML must not leak details.
        if exc.__cause__ is not None:
            raise BootstrapError(MESSAGE) from None
        return []
    except (KeyError, TypeError, ValueError, AttributeError):
        raise BootstrapError(MESSAGE) from None
    return accounts


def initialize_demo_accounts(db_path=DEFAULT_DB_PATH):
    """Check on every startup/rerun, including after ephemeral DB recreation.

    Credentials come exclusively from st.secrets. There is no cache or browser
    input, and existing accounts are never updated, enabled or promoted.
    """
    initialize_database(db_path)
    accounts = _configured_accounts()
    if not accounts:
        return
    connection = connect_database(db_path)
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            for username, password, role, display_name in accounts:
                existing = connection.execute('SELECT role FROM users WHERE username=?', (username,)).fetchone()
                if existing:
                    if existing[0] != role:
                        raise BootstrapError(MESSAGE)
                    continue
                try:
                    auth._insert_user(connection, username, password, role, display_name=display_name)
                except (TypeError, ValueError):
                    raise BootstrapError(MESSAGE) from None
    finally:
        connection.close()
