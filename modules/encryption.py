"""Encryption is disabled in this installation; never generate or persist a key."""
import importlib.util
from modules.auth import guard, current_user, event
from modules.database import DEFAULT_DB_PATH, connect_database

MESSAGE = 'Encryption at rest is not configured.'


@guard('read')
def encryption_status(db_path=DEFAULT_DB_PATH):
    installed = importlib.util.find_spec('cryptography') is not None
    c = connect_database(db_path)
    try:
        with c:
            event(c, 'ENCRYPTION_STATUS_CHECKED', current_user(db_path)['user_id'], configured=False,
                  dependency_available=installed)
    finally:
        c.close()
    return {'configured':False, 'dependency_available':installed, 'message':MESSAGE}
