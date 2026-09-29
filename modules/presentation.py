"""Plain-language views of stored results; never changes analysis or evidence."""
from datetime import datetime

DISCLAIMER = 'This result is a preliminary assessment. The investigator makes the final decision.'
UNSUPPORTED = ('I could not answer that from the available email information. Try asking about '
               'the sender, message, links, attachments or warning signs.')
SUGGESTIONS = ['Why is this email suspicious?', 'Does it ask for personal information?',
               'Are there any suspicious links?', 'What should I check next?']
FINDINGS = {
    'urgency': 'The message creates a sense of urgency.',
    'credentials': 'It asks the recipient to provide login details.',
    'financial': 'It asks for money or financial details.',
    'organization': 'It may be pretending to represent a trusted organization.',
    'impersonation': 'It may be pretending to represent a trusted organization.',
    'reply_mismatch': 'Replies would go to a different organization than the sender.',
    'link_mismatch': 'A link may lead somewhere different from what it suggests.',
    'attachment': 'An attachment may be unsafe to open.',
    'sender': 'The sender address looks unusual.',
    'authentication': 'The email reports a failed sender check.',
    'emphasis': 'The message uses excessive capitals or punctuation.',
    'secrecy': 'It asks the recipient to keep secrets or skip normal checks.',
    'prompt_injection': 'The message contains instructions that try to influence this tool.',
    'url_ip': 'A link uses a numbered address instead of a website name.',
    'url_shortener': 'A shortened link hides the website it leads to.',
    'url_punycode': 'A website name may use lookalike characters.',
    'url_long': 'A link is unusually long.',
    'url_subdomains': 'A website address has an unusual number of parts.',
    'url_http': 'A link does not use a secure connection.',
    'url_userinfo': 'A link may disguise the website it leads to.',
    'url_port': 'A link uses an unusual connection setting.',
    'url_file': 'A link may download an unsafe file.',
    'url_domains': 'The email links to several unrelated websites.',
}
NEXT_STEPS = ['Do not click links or open attachments yet.',
              'Contact the organization using its official website or phone number.',
              'Record the final decision on the Investigator Review page.']


def classification(value):
    return {'Uncertain': 'Needs Review', 'No Significant Indicators Detected': 'No Warning Signs Found',
            'Further analysis required': 'Needs More Investigation',
            'Analysis rejected; no final classification': 'Needs More Investigation'}.get(value, value)


def finding_text(finding):
    from modules.phishing_analyzer import RULES
    key = finding.get('rule_id')
    if key not in FINDINGS:
        key = next((key for key, rule in RULES.items() if rule[0] == finding.get('indicator')), None)
    return FINDINGS.get(key, 'A warning sign needs investigator review.')


def date_label(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).astimezone().strftime('%d %b %Y, %I:%M %p')
    except (ValueError, TypeError):
        return 'Date unavailable'


def report_sections(document):
    case = document['case_information']
    email = document['evidence_information']
    analysis = document['automated_analysis']
    human = document['human_verification']
    return {
        'Case details': {'Title': case['case_title'], 'Purpose': case['purpose']},
        'Email summary': {'File': email['original_filename'], 'Type': email['file_type']},
        'Main warning signs': [finding_text(f) for f in analysis['findings']] or ['No warning signs found.'],
        'Risk result': {'Result': classification(analysis['automated_classification']),
                        'Risk Score': str(analysis['rule_based_risk_score']) + '/100', 'Risk Level': analysis['risk_level']},
        'Questions and answers': [{'Question': q['masked_question'], 'Answer': plain_answer(q.get('masked_display_answer') or q['masked_answer'])}
                                 for q in document['ask_the_evidence_summary']['interactions']],
        'Investigator’s final decision': {'Decision': decision_label(human['human_verified_classification_or_status']),
            'Reason': human.get('masked_decision_reason') or human.get('masked_change_reason') or 'Not recorded.', 'Requested checks': human['requested_further_actions']},
        'Investigator’s notes': human['masked_verification_notes'],
        'Report version details': {'Version': document['report_information'].get('report_version') or 'Not generated',
            'Reason for this version': document['report_information'].get('masked_version_reason') or 'Not recorded.'},
        'Date of review': date_label(human['decision_timestamp_utc']),
    }


def plain_answer(value):
    """Keep technical answers in the technical record, not in the normal transcript."""
    import re
    from modules.phishing_analyzer import DISCLAIMER as OLD_DISCLAIMER
    from modules.phishing_analyzer import RULES
    from modules.qa_engine import UNSUPPORTED as OLD_UNSUPPORTED
    if str(value).startswith(OLD_UNSUPPORTED):
        return UNSUPPORTED
    if 'Detected indicators:' in str(value):
        summary = '\n'.join(dict.fromkeys(FINDINGS[k] for k, rule in RULES.items() if rule[0] in str(value)))
        return summary or 'The stored answer has incomplete indicator details. Review the analysis findings and verify the email independently.'
    if str(value).startswith('Recorded manual-verification steps:'):
        return '\n'.join(NEXT_STEPS)
    value = str(value).replace(OLD_DISCLAIMER, '').replace('Uncertain', 'Needs Review')
    value = value.replace('No Significant Indicators Detected', 'No Warning Signs Found').replace('rule-based risk score', 'Risk Score')
    if value.startswith('Last recorded check:'):
        return value.split(' at ')[0] + '. Use Email Analysis to check again.'
    if 'deterministic local matching' in value or 'Parser' in value:
        return 'Some email details may be missing. Review the available message and confirm the sender independently.'
    if re.search(r'SPF|DKIM|DMARC|SHA.?256|UTC|ruleset|engine version|analysis.version|score.calculation|domain.lookup|domain.ownership|displayed.*destination|working JSON|CASE-|EVD-|ANA-|QAI-', value, re.I):
        return 'This question involves technical checks. Ask an administrator to review the technical details.'
    return value.strip() or 'No readable answer was recorded. Ask the question again using the selected email.'


def decision_label(value):
    return {'Suspicious': 'Confirmed as Suspicious', 'No Significant Indicators Detected': 'Marked as Safe', 'Uncertain': 'Needs More Investigation'}.get(value, classification(value))
