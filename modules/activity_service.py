"""Case-scoped activity summaries, separate from administrator audit access."""
from modules.auth import guard, current_user
from modules.audit import record
from modules.database import DEFAULT_DB_PATH, connect_database

ACTIVITIES = {'Case created': 'Case created', 'Evidence uploaded': 'Email uploaded',
              'Analysis completed': 'Analysis completed', 'Question submitted': 'Question asked',
              'DECISION_RECORDED': 'Decision recorded', 'REPORT_GENERATED': 'Report generated'}


@guard('activity')
def activity_history(case_id=None, db_path=DEFAULT_DB_PATH):
    if not case_id:
        return []
    c = connect_database(db_path)
    try:
        # Filter at the service boundary: no actors, identifiers, internal payloads,
        # global events or events from other cases are returned to the caller.
        rows = c.execute('SELECT created_at,action,status FROM audit_logs WHERE case_id=? '
            'AND action IN (' + ','.join('?' for _ in ACTIVITIES) + ') ORDER BY audit_id DESC LIMIT 500',
            (case_id, *ACTIVITIES))
        return [dict(timestamp_utc=stamp, activity=ACTIVITIES[action],
                     status='Completed' if status == 'success' else 'Not completed')
                for stamp, action, status in rows]
    finally:
        c.close()


@guard('activity')
def record_activity_view(case_id, db_path=DEFAULT_DB_PATH):
    if not case_id:
        return
    user = current_user(db_path)
    c = connect_database(db_path)
    try:
        with c:
            record(c, user['user_id'], 'ACTIVITY_HISTORY_VIEWED', case_id=case_id)
    finally:
        c.close()
