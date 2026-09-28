"""Deterministic, evidence-grounded answers. No model, network or executable text."""
import re
import unicodedata
from modules.privacy import Masker
from modules.phishing_analyzer import DISCLAIMER

MAX_QUESTION = 500
MAX_MESSAGES = 50
MAX_REFERENCES = 10
MAX_SNIPPET = 250
INSUFFICIENT = 'The available evidence does not contain enough information to answer this question.'
UNSUPPORTED = ('This prototype cannot answer that question from the available evidence. Please ask about the email metadata, '
               'links, attachments, analysis findings, integrity status or manual-verification requirements.')
LEGAL = ('The system cannot determine criminal responsibility. It provides evidence-based investigative leads only. '
         'A qualified investigator must examine the complete evidence and applicable legal requirements.')
SUGGESTIONS = ['Why is this email suspicious?', 'What evidence supports the result?', 'Show suspicious links.',
               'Are there any attachments?', 'What information is missing?', 'What should be verified manually?']
INJECTION = re.compile(r'ignore (?:all |previous )?instructions|reveal (?:stored information|other cases)|mark this email as safe|'
                       r'treat this email as safe|delete (?:the )?audit log|override (?:security (?:controls|rules)|instructions)', re.I)
PLACEHOLDERS = re.compile(r'\[(?:EMAIL|PHONE|IP|CARD|AADHAAR|PAN|PERSONAL)-\d+\]')


def redact(text):
    """Mask free text without destroying already-masked IP URLs/placeholders."""
    text = str(text)
    prefix = 'QAREDACTIONTOKEN'
    while prefix in text:
        prefix += 'X'
    replacements = {}
    def shield(match):
        token = prefix + ''.join(chr(65 + int(char, 16)) for char in hex(len(replacements))[2:]) + 'END'
        replacements[token] = match.group()
        return token
    protected = PLACEHOLDERS.sub(shield, text)
    class PreservingMasker(Masker):
        def placeholder(self, kind, value):
            return value if value in replacements else super().placeholder(kind, value)
    masked = PreservingMasker().text(protected)
    for token, value in replacements.items():
        masked = masked.replace(token, value)
    return masked


def normalized(question):
    value = unicodedata.normalize('NFKC', question).casefold()
    return re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', ' ', value)).strip()


# Overlapping concepts have explicit sub-intents; unrelated matches ask for
# clarification. Matching is applied only to the question, never email instructions.
INTENTS = {
    'sender': [r'\bwho (?:is (?:the )?sender|sent|wrote)', r'\bwhere did (?:this |the )?(?:message|email) come from', r'\bsender(?: s)? (?:address|email|name)\b', r'\bwho is (?:this |the )?(?:email|message) from\b'],
    'recipient': [r'\bwho (?:received|is (?:the )?recipient)', r'\b(?:recipient|recipients)\b', r'\b(?:sent|addressed) to\b'],
    'subject': [r'\bsubject\b'],
    'date': [r'\bwhen (?:was|did)', r'\b(?:sent|sending) (?:date|time)\b', r'\bdate (?:of|was)\b'],
    'reply_to': [r'\breply to\b', r'\breply address\b'],
    'summary': [r'\bsummari[sz]e\b', r'\bsummary\b', r'\bwhat is (?:this |the )?(?:email|message) about\b'],
    'classification': [r'\bclassification\b', r'\bhow (?:was|is) (?:this |the )?(?:email|message) classified\b'],
    'score': [r'\brisk score\b', r'\bwhat (?:is|was) (?:the )?score\b'],
    'risk_level': [r'\brisk level\b', r'\bhow risky\b'],
    'explanations': [r'\bwhy .*suspicious\b', r'\bexplain (?:the |this )?(?:result|score|classification|findings)\b',
                     r'\b(?:give )?reasons? for (?:this |the )?(?:score|result)\b', r'\bwhat evidence supports\b', r'\bevidence (?:for|behind) (?:the |this )?(?:result|score)\b'],
    'suspicious_words': [r'\bsuspicious (?:words|phrases|language)\b'],
    'urls': [r'\b(?:links?|urls?)\b'],
    'attachments': [r'\battachments?\b', r'\battached files?\b'],
    'credentials': [r'\b(?:password|otp|one time password|login (?:information|details)|credentials)\b'],
    'payment': [r'\b(?:payment|transfer money|gift cards?|financial request)\b'],
    'urgency': [r'\b(?:urgent|urgency|threatening)\b'],
    'mismatch': [r'\b(?:sender|reply to|from)\b.*\b(?:mismatch|different|match)\b', r'\bmismatch\b.*\b(?:sender|reply to)\b'],
    'authentication': [r'\b(?:spf|dkim|dmarc|authentication)\b'],
    'metadata_missing': [r'\b(?:metadata|headers?)\b.*\b(?:missing|unavailable|incomplete)\b', r'\b(?:missing|unavailable)\b.*\b(?:metadata|headers?)\b'],
    'missing_information': [r'\b(?:missing|unavailable|not available|unknown)\b'],
    'prompt_injection': [r'\bprompt injection\b', r'\binjection (?:text|instructions|detected)\b'],
    'masking': [r'\b(?:masked|masking|redacted|redaction)\b', r'\bpersonal information\b'],
    'manual_verification': [r'\bmanual(?:ly)?\b', r'\bwhat should (?:the investigator |i )?(?:verify|check)\b', r'\bverification (?:steps|requirements)\b'],
    'limitations': [r'\blimitations?\b'],
    'integrity': [r'\bintegrity\b', r'\boriginal (?:file|evidence) (?:unchanged|modified)\b'],
    'hash': [r'\bsha ?256\b', r'\bhash\b'],
    'case_id': [r'\bcase (?:id|identifier|number)\b'],
    'evidence_id': [r'\bevidence (?:id|identifier|number)\b'],
    'analysis_version': [r'\banalysis (?:version|id)\b', r'\b(?:ruleset|engine) version\b', r'\bwhat version\b'],
    'location': [r'\b(?:physical(?:ly)? location|physically located|sender located|sender live|ip location|geographic|country)\b'],
}
ANALYSIS_INTENTS = {'classification', 'score', 'risk_level', 'explanations', 'suspicious_words',
                    'mismatch', 'manual_verification', 'analysis_version', 'definite', 'safety'}


def match_intents(question):
    text = normalized(question)
    if re.search(r'\b(?:guilty|criminal responsibility|commit(?:ted)? (?:a )?(?:crime|cybercrime)|arrest(?:ed)?|criminal)\b', text):
        return ['legal_conclusion']
    if INJECTION.search(question) or re.search(r'\b(?:other|another|all|unrelated) cases?\b|\b(?:read|open|load|delete|execute|run|download)\b.*(?:[/\\]|\b(?:file|command|script|audit|sql)\b)', question, re.I):
        return ['unsupported']
    if re.search(r'\b(?:definitely|definitively|certainly|prove|proven)\b.*\bphishing\b|\bis (?:this|it|the email) phishing\b', text):
        return ['definite']
    if re.search(r'\b(?:safe|trust|trusted|harmless)\b', text):
        return ['safety']
    matches = [intent for intent, patterns in INTENTS.items() if any(re.search(pattern, text) for pattern in patterns)]
    if 'mismatch' in matches:
        matches = [intent for intent in matches if intent not in {'sender', 'reply_to'}]
    if 'authentication' in matches or 'metadata_missing' in matches:
        matches = [intent for intent in matches if intent != 'missing_information']
    if 'explanations' in matches:
        matches = [intent for intent in matches if intent not in {'classification', 'score'}]
    if 'prompt_injection' in matches:
        matches = [intent for intent in matches if intent != 'suspicious_words']
    return matches or ['unsupported']


def answer_question(question, context):
    """Only stored, scoped context supplied by qa_service is evidence."""
    intents = match_intents(question)
    result = {'intent': '+'.join(intents), 'answer': '', 'evidence_references': [],
              'limitations': [DISCLAIMER], 'status': 'completed', 'limits_reached': [],
              'analysis_used': False, 'injection_ignored': bool(INJECTION.search(question)),
              'high_risk_refused': False}
    metadata = context['metadata']
    working = context.get('working')
    analysis = context.get('analysis')
    if working and any(INJECTION.search(working.get(field, '')) for field in ('subject', 'body')):
        # Audit the handling without mentioning irrelevant instruction text in answers.
        result['injection_ignored'] = True
    text = normalized(question)
    # Only the two identifier requests can be combined without ambiguity.
    if len(intents) > 1 and set(intents) != {'case_id', 'evidence_id'}:
        result.update(status='clarification', answer='More than one supported topic matched. Please choose one: ' + ', '.join(intents) + '.')
        result['evidence_references'].append({'source': 'Question matcher', 'field': 'matched_intents', 'snippet': ', '.join(intents)})
        return result
    intent = intents[0]
    findings = analysis.get('findings', []) if analysis else []

    def reference(source, field, value, needle=None):
        if len(result['evidence_references']) >= MAX_REFERENCES:
            if 'Only the first 10 evidence snippets are displayed.' not in result['limits_reached']:
                result['limits_reached'].append('Only the first 10 evidence snippets are displayed.')
            return
        value = str(value)
        # Context content has already been masked; identifiers/hash are exact DB fields.
        start = max(0, value.casefold().find(needle.casefold()) - 60) if needle else 0
        excerpt = value[start:start + MAX_SNIPPET]
        if len(value) > len(excerpt):
            result['limits_reached'].append('Supporting excerpts are limited to 250 characters each.')
        result['evidence_references'].append({'source': source, 'field': field, 'snippet': excerpt})

    def insufficient(reason):
        result.update(status='insufficient', answer=INSUFFICIENT + ' ' + reason)
        reference('Availability check', 'missing_information', reason)

    def need_analysis():
        if not analysis:
            insufficient('No selected completed analysis is available. Run Phishing Analysis first for analysis-related questions.')
            return False
        result['analysis_used'] = True
        return True

    def finding_refs(items):
        for finding in items:
            index = findings.index(finding)
            reference('Selected analysis / ' + finding['evidence_source'], f'findings[{index}].masked_evidence', finding['masked_evidence'])

    def analysis_value(field):
        reference('Selected analysis', field, analysis[field])
        result['analysis_used'] = True
        return analysis[field]

    if intent == 'legal_conclusion':
        result.update(answer=LEGAL, status='refused', high_risk_refused=True)
        reference('System scope', 'legal_conclusions', 'Criminal responsibility and arrest decisions are outside this prototype.')
    elif intent == 'unsupported':
        result.update(answer=UNSUPPORTED, status='unsupported')
        reference('System scope', 'supported_topics', 'Metadata, links, attachments, stored findings, integrity and manual verification only.')
    elif intent == 'location':
        insufficient('Verified physical-location data is unavailable. The system does not perform external IP or domain lookups.')
    elif intent in {'case_id', 'evidence_id', 'hash'}:
        fields = ['case_id', 'evidence_id'] if len(intents) > 1 else [{'hash': 'sha256'}.get(intent, intent)]
        result['answer'] = '\n'.join(f'{field}: {metadata[field]}' for field in fields)
        for field in fields:
            reference('Selected evidence database record', field, metadata[field])
    elif intent == 'integrity':
        integrity = context.get('integrity')
        if not integrity:
            insufficient('No recorded integrity verification was found. Use Verify Integrity Again on Evidence Analysis.')
        else:
            value = 'Integrity verified' if integrity['status'] == 'success' else 'Integrity check failed'
            result['answer'] = f"Last recorded check: {value} at {integrity['created_at']}."
            reference('Selected evidence audit log', 'audit_logs.' + str(integrity['audit_id']), value + ' | ' + integrity['created_at'])
        result['limitations'].append('This answer reports a stored check, not a fresh hash verification. Recheck integrity on Evidence Analysis to establish current status.')
    elif intent in ANALYSIS_INTENTS and not need_analysis():
        if intent in {'definite', 'safety'}:
            result['high_risk_refused'] = True
            result['limitations'].append('No automated analysis establishes definitive phishing or guarantees safety.')
    elif intent in {'classification', 'score', 'risk_level', 'definite', 'safety'}:
        if intent == 'classification':
            result['answer'] = 'The selected analysis classification is ' + analysis_value('classification') + '.'
        elif intent == 'score':
            result['answer'] = f"The selected rule-based risk score is {analysis_value('risk_score')}/100. This score is not a probability of phishing."
            reference('Selected analysis', 'score_calculation', analysis.get('score_calculation', 'Calculation unavailable'))
        elif intent == 'risk_level':
            result['answer'] = 'The selected analysis risk level is ' + analysis_value('risk_level') + '.'
        elif intent == 'definite':
            result['answer'] = (f"The current rule-based result is {analysis_value('classification')} with a risk score of {analysis_value('risk_score')}/100. "
                                'This score is not a probability and does not establish that the email is definitively phishing. Human verification is required.')
            result.update(status='refused', high_risk_refused=True)
        else:
            result['answer'] = ('No automated analysis can guarantee that an email is safe. The current result indicates '
                                + analysis_value('classification') + ', but undetected threats or missing information may remain.')
            result.update(status='refused', high_risk_refused=True)
    elif intent == 'analysis_version':
        result['answer'] = (f"Selected analysis version: {analysis_value('analysis_version')}; ID: {analysis_value('analysis_id')}; "
                            f"engine: {analysis_value('engine_version')}; ruleset: {analysis_value('ruleset_version')}.")
    elif intent in {'explanations', 'suspicious_words'}:
        selected = findings if intent == 'explanations' else [item for item in findings if item['rule_id'] in {'urgency', 'credentials', 'financial', 'impersonation', 'secrecy', 'prompt_injection', 'emphasis'}]
        result['answer'] = 'The selected result is ' + analysis_value('classification') + '. '
        result['answer'] += ('Detected indicators: ' + '; '.join(item['indicator'] for item in selected[:10]) + '.') if selected else 'No matching indicators were recorded by the selected ruleset.'
        finding_refs(selected)
        if len(selected) > 10:
            result['limits_reached'].append('Only the first 10 indicators are summarized; view Evidence Analysis for all findings.')
        for item in selected[:3]:
            result['answer'] += '\n' + item['indicator'] + ': ' + item['explanation']
        result['limitations'].append('An indicator is not proof of phishing; quoted or legitimate content may match a rule.')
    elif intent == 'mismatch':
        selected = [item for item in findings if item['rule_id'] == 'reply_mismatch']
        if selected:
            result['answer'] = 'The selected analysis detected a sender/Reply-To domain mismatch.'
            finding_refs(selected)
        elif not working or not working.get('sender') or not working.get('reply_to'):
            insufficient('From or Reply-To metadata is unavailable for the comparison.')
        else:
            result['answer'] = 'No sender/Reply-To mismatch was recorded in the selected analysis; this does not establish sender identity.'
            reference('Selected analysis', 'findings.rule_id', 'No reply_mismatch finding')
    elif intent == 'manual_verification':
        steps = analysis.get('recommended_verification', [])
        result['answer'] = 'Recorded manual-verification steps:\n' + '\n'.join('- ' + step for step in steps[:10])
        for index, step in enumerate(steps):
            reference('Selected analysis', f'recommended_verification[{index}]', step)
    elif intent == 'limitations':
        result['answer'] = ('This component uses deterministic local matching, not a language model. It can only report retained masked fields and selected rule findings. '
                            'Rules can miss threats or flag legitimate text. Masking and parser limits can hide details. No external lookups, identity attribution, safety guarantees or legal conclusions are provided.')
        reference('System scope', 'limitations', 'Local deterministic retrieval; no external verification or legal conclusions.')
        if analysis:
            result['analysis_used'] = True
            for item in analysis.get('missing_information', [])[:3]:
                reference('Selected analysis', 'missing_information', item)
    elif intent == 'missing_information':
        missing = []
        if working:
            missing += ['No ' + label + ' field' for key, label in [('sender', 'From'), ('recipient', 'To'), ('subject', 'Subject'), ('date', 'Date'), ('reply_to', 'Reply-To')] if not working.get(key)]
            if working.get('truncated'):
                missing.append('Parser-truncated content is unavailable for this answer.')
        else:
            missing.append('Masked working copy is unavailable.')
        if analysis:
            result['analysis_used'] = True
            missing += analysis.get('missing_information', [])
        else:
            missing.append('No selected completed analysis. Run Phishing Analysis for analysis-specific missing information.')
        result['answer'] = 'Unavailable information: ' + '; '.join(dict.fromkeys(missing)) if missing else 'No missing metadata was identified in the available fields; this does not prove completeness.'
        reference('Masked working copy / selected analysis', 'missing_information', result['answer'])
    elif intent == 'authentication':
        if not need_analysis():
            pass
        else:
            auth = analysis.get('authentication', {})
            missing = [key.upper() for key in ('spf', 'dkim', 'dmarc') if not auth.get(key)]
            if 'missing' in text or 'unavailable' in text:
                result['answer'] = 'Missing reported authentication results: ' + ', '.join(missing) + '.' if missing else 'SPF, DKIM and DMARC reported values are all present.'
            elif len(missing) == 3:
                insufficient('No reported SPF, DKIM or DMARC results were retained in the selected analysis.')
            else:
                result['answer'] = '; '.join(key.upper() + ': ' + (', '.join(auth.get(key, [])) or 'Unavailable') for key in ('spf', 'dkim', 'dmarc'))
            for key in ('spf', 'dkim', 'dmarc'):
                reference('Selected analysis', 'authentication.' + key, ', '.join(auth.get(key, [])) or 'Unavailable')
            result['limitations'].append('These are reported header claims, not independently verified SPF, DKIM or DMARC checks.')
    elif not working:
        insufficient('The masked working-copy JSON is missing or invalid. The original email is never read by Q&A.')
    elif intent in {'sender', 'recipient', 'subject', 'date', 'reply_to'}:
        labels = {'sender': 'From', 'recipient': 'To', 'subject': 'Subject', 'date': 'Date', 'reply_to': 'Reply-To'}
        value = working.get(intent, '')
        if value:
            result['answer'] = f"{labels[intent]}: {value[:MAX_SNIPPET]}"
            reference('Masked working copy / ' + labels[intent], intent, value)
            if intent == 'sender':
                result['limitations'].append('The From field is a claimed sender, not verified identity.')
            if intent == 'date':
                result['limitations'].append('This is the supplied Date field, not an independently verified sending time.')
        else:
            insufficient('The ' + labels[intent] + ' field is missing from the masked working copy.')
    elif intent == 'metadata_missing':
        missing = [label for key, label in [('sender', 'From'), ('recipient', 'To'), ('subject', 'Subject'), ('date', 'Date'), ('reply_to', 'Reply-To'), ('message_id', 'Message-ID')] if not working.get(key)]
        result['answer'] = 'Missing retained metadata: ' + ', '.join(missing) + '.' if missing else 'All checked metadata fields are present. Their authenticity has not been established.'
        reference('Masked working copy', 'header availability', ', '.join(missing) or 'From, To, Subject, Date, Reply-To and Message-ID present')
    elif intent == 'summary':
        parts = []
        for key, label in [('sender', 'From'), ('recipient', 'To'), ('subject', 'Subject'), ('date', 'Date')]:
            if working.get(key):
                parts.append(label + ': ' + working[key][:120])
                reference('Masked working copy', key, working[key])
        parts.append(f"Retained unique URLs: {len(working.get('urls', []))}; attachments: {len(working.get('attachments', []))}.")
        reference('Masked working copy', 'urls / attachments', parts[-1])
        if analysis:
            result['analysis_used'] = True
            parts.append('Selected classification: ' + analysis_value('classification') + '.')
            indicators = [item['indicator'] for item in findings[:3]]
            if indicators:
                parts.append('Main recorded indicators: ' + '; '.join(indicators) + '.')
                finding_refs(findings[:3])
        result['answer'] = '\n'.join(parts) or INSUFFICIENT
        result['limitations'].append('This is a metadata and retained-indicator summary. The sender’s purpose is not inferred, and the complete body is not reproduced.')
    elif intent == 'urls':
        urls = working.get('urls', [])
        if re.search(r'\b(?:how many|number|count)\b', text):
            result['answer'] = f"The masked working copy retains {len(urls)} unique URL(s)."
            reference('Masked working copy', 'urls.length', len(urls))
            result['limitations'].append('This is a count of retained unique URLs, not all link occurrences; parser limits may omit links.')
        elif re.search(r'\b(?:suspicious|dangerous|malicious)\b', text):
            if need_analysis():
                selected = [item for item in findings if item['rule_id'].startswith('url_') or item['rule_id'] == 'link_mismatch']
                result['answer'] = 'URL-related indicators: ' + '; '.join(dict.fromkeys(item['indicator'] for item in selected)) + '.' if selected else 'No URL-related indicators were recorded in the selected analysis. This does not guarantee safe links.'
                finding_refs(selected)
        else:
            result['answer'] = f'The working copy retains {len(urls)} unique URL(s); see the masked references.'
            for index, url in enumerate(urls):
                reference('Masked working copy', f'urls[{index}]', url)
            if not urls:
                reference('Masked working copy', 'urls', 'No retained URLs')
        result['limitations'].append('No link was opened and no destination or redirect was checked.')
    elif intent == 'attachments':
        attachments = working.get('attachments', [])
        result['answer'] = f"The masked working copy lists {len(attachments)} attachment(s)."
        for index, attachment in enumerate(attachments):
            reference('Masked working copy', f'attachments[{index}]', f"{attachment['name']} | {attachment['type']} | {attachment['size']} bytes")
        if not attachments:
            reference('Masked working copy', 'attachments', 'No retained attachment metadata')
        result['limitations'].append('Only retained attachment names, declared types and sizes are available. Attachment contents were not opened.')
    elif intent in {'credentials', 'payment', 'urgency', 'prompt_injection'}:
        patterns = {'credentials': r'\b(?:password|otp|login details|login information|verify your account|confirm credentials)\b',
                    'payment': r'\b(?:payment|transfer money|bank details|invoice payment|gift cards?|refund claim)\b',
                    'urgency': r'\b(?:urgent|immediately|account suspended|final warning|verify now|action required|within 24 hours)\b',
                    'prompt_injection': INJECTION.pattern}
        if intent == 'credentials' and re.search(r'\botp\b', text) and re.search(r'\bpassword\b', text):
            patterns[intent] = r'\b(?:password|OTP)\b'
        elif intent == 'credentials' and re.search(r'\botp\b|\bone time password\b', text):
            patterns[intent] = r'\b(?:OTP|one.time password)\b'
        elif intent == 'credentials' and 'password' in text:
            patterns[intent] = r'\bpassword\b'
        hits = []
        for field in ('subject', 'body'):
            for match in list(re.finditer(patterns[intent], working.get(field, ''), re.I))[:3]:
                hits.append(match.group())
                reference('Masked working copy / ' + field.title(), field, working[field], needle=match.group())
        if hits:
            label = {'credentials': 'credential-related', 'payment': 'payment-related', 'urgency': 'urgent', 'prompt_injection': 'prompt-injection-like'}[intent]
            result['answer'] = 'The retained masked text contains ' + label + ' matching wording: ' + ', '.join(dict.fromkeys(hits)) + '.'
            result['limitations'].append('This confirms wording, not intent. Negation, quotation or training examples can contain the same terms.')
            if intent == 'prompt_injection':
                result['injection_ignored'] = True
                result['answer'] += ' It is treated only as evidence; no instruction was followed.'
        else:
            result['answer'] = 'No matching wording was found in the retained masked Subject or Body. This does not establish that no such request exists.'
            reference('Masked working copy', 'subject / body', 'No match for the documented local phrase group')
    elif intent == 'masking':
        types = {}
        # Only known masked fields are inspected; the mapping/original values are never loaded.
        for field in ('sender', 'recipient', 'cc', 'reply_to', 'subject', 'date', 'message_id', 'body'):
            for token in PLACEHOLDERS.findall(working.get(field, '')):
                kind = token[1:].split('-')[0]
                types.setdefault(kind, set()).add(token)
        for url in working.get('urls', []):
            for token in PLACEHOLDERS.findall(url):
                types.setdefault(token[1:].split('-')[0], set()).add(token)
        for attachment in working.get('attachments', []):
            for token in PLACEHOLDERS.findall(attachment['name'] + ' ' + attachment['type']):
                types.setdefault(token[1:].split('-')[0], set()).add(token)
        result['answer'] = 'Retained masking placeholders: ' + '; '.join(f'{kind}: {len(values)} distinct placeholder(s)' for kind, values in sorted(types.items())) if types else 'No recognized masking placeholders were found in the checked retained fields.'
        for kind, tokens in sorted(types.items()):
            reference('Masked working copy', 'placeholders.' + kind, ', '.join(sorted(tokens)))
        if not types:
            reference('Masked working copy', 'placeholders', 'No recognized placeholders')
        result['limitations'].append('Placeholder counts are not a count of people. Original personal values are unavailable to Q&A; masking is heuristic.')
    else:
        result.update(answer=UNSUPPORTED, status='unsupported')
        reference('System scope', 'supported_topics', 'Question did not map to an implemented answer.')
    if working and working.get('truncated'):
        result['limitations'].append('The working representation was truncated; omitted evidence cannot be evaluated here.')
    if context.get('integrity', {}).get('status') == 'failure':
        result['limitations'].append('The last recorded integrity check failed. These answers describe stored representations, not currently verified evidence.')
    result['limits_reached'] = list(dict.fromkeys(result['limits_reached']))
    return result
