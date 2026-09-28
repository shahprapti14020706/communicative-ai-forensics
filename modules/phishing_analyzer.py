"""Transparent local rules. No inference service, network, or executable evidence."""
import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlsplit, unquote

from modules.audit import utc_now
from modules.privacy import Masker

ENGINE_VERSION = '1.0.0'
RULESET_VERSION = '1.0.0'
DISCLAIMER = 'This automated result is an investigative lead and requires human verification.'
SCORE_LABEL = 'Rule-based risk score — not a probability of phishing.'
# Each rule contributes at most once. Authentication failures and sender anomalies
# are grouped. Related URL traits may coexist, but repeated URLs do not add points.
# Total = min(100, sum(contributions)); missing information contributes zero.
RULES = {
    'urgency': ('Urgent or threatening language', 'Medium', 10),
    'credentials': ('Credential request', 'High', 20),
    'financial': ('Financial request', 'Medium', 10),
    'url_ip': ('Raw IP address in URL', 'High', 15),
    'url_shortener': ('URL shortener', 'Medium', 8),
    'url_punycode': ('Punycode domain', 'Medium', 8),
    'url_long': ('Unusually long URL', 'Low', 4),
    'url_subdomains': ('Excessive subdomains', 'Medium', 6),
    'url_http': ('Unencrypted HTTP URL', 'Low', 4),
    'url_userinfo': ('Misleading @ in URL authority', 'High', 15),
    'url_port': ('Unusual URL port', 'Low', 4),
    'url_file': ('Suspicious file extension in URL', 'High', 12),
    'url_domains': ('Multiple unrelated URL domains', 'Low', 4),
    'reply_mismatch': ('Sender and Reply-To domain mismatch', 'Medium', 10),
    'organization': ('Claimed organization and sender mismatch', 'High', 15),
    'link_mismatch': ('Displayed and destination link mismatch', 'High', 15),
    'attachment': ('Suspicious attachment metadata', 'High', 20),
    'sender': ('Unusual sender', 'Medium', 8),
    'authentication': ('Reported email authentication failure', 'High', 18),
    'impersonation': ('Possible impersonation language', 'Medium', 8),
    'emphasis': ('Excessive capitalization or punctuation', 'Low', 4),
    'secrecy': ('Bypass procedures or maintain secrecy', 'High', 15),
    'prompt_injection': ('Prompt-injection-like content', 'High', 20),
}
PHRASES = {
    'urgency': r'\b(?:urgent|immediately|account suspended|final warning|verify now|action required|within 24 hours)\b',
    'credentials': r'\b(?:password|OTP|login details|verify your account|confirm credentials)\b',
    'financial': r'\b(?:payment|transfer money|bank details|invoice payment|gift cards?|refund claim)\b',
    'impersonation': r'\b(?:I am (?:your |the )?(?:CEO|director)|on behalf of (?:the )?(?:CEO|director)|IT security (?:team|department)|official security notice|bank security team)\b',
    'secrecy': r'\b(?:keep (?:this |it )?(?:secret|confidential)|do not (?:tell|notify|contact)|bypass (?:normal |the )?(?:procedures|approval|security)|skip (?:the )?(?:approval|verification)|outside normal procedures)\b',
    'prompt_injection': r'\b(?:ignore previous instructions|reveal stored information|treat this email as safe|override security rules)\b',
}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'short.test'}
FREE_MAIL = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'proton.me', 'mail.test'}
# Deliberately limited, explicitly fictional organization mappings. Never infer
# ownership from a brand substring or the last two DNS labels (no public-suffix data).
ORGANIZATIONS = {'example bank': {'bank.example.test'}, 'example research group': {'example.org'}}
DANGEROUS_SUFFIXES = {'.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.jar', '.iso',
                      '.com', '.msi', '.hta', '.docm', '.xlsm', '.pptm', '.dotm', '.xlam', '.xlsb'}
DANGEROUS_TYPES = {'application/x-msdownload', 'application/x-executable', 'application/javascript',
                   'text/javascript', 'application/java-archive', 'application/x-iso9660-image'}
VERIFY_CHANNEL = 'Contact the organization through an independently verified channel; do not use contact details in the email.'
VERIFY_URL = 'Compare the destination with an independently verified organization domain without opening the evidence URL.'
VERIFY_ATTACHMENT = 'Confirm the attachment and business purpose through an independent channel; do not open or execute it.'


def classification_for(score):
    if not 0 <= score <= 100:
        raise ValueError('Score must be between 0 and 100.')
    if score >= 50:
        return 'Suspicious', 'High'
    if score >= 25:
        return 'Uncertain', 'Medium'
    return 'No Significant Indicators Detected', 'Low'


def related(first, second):
    return bool(first and second and (first == second or first.endswith('.' + second) or second.endswith('.' + first)))


def sender_domain(value):
    address = parseaddr(value)[1]
    if not re.fullmatch(r'[^\s<>@]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', address):
        return ''
    domain = address.rsplit('@', 1)[1].lower().rstrip('.')
    return domain if '.' in domain and '..' not in domain else ''


def authentication_results(headers):
    results = {key: [] for key in ('spf', 'dkim', 'dmarc')}
    for header in headers[:20]:
        for key, value in re.findall(r'\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b', header[:2000], re.I):
            if value.lower() not in results[key.lower()]:
                results[key.lower()].append(value.lower())
    return results


def analyze(parsed):
    """Analyze transient parsed data; return masked, JSON-serializable output only."""
    # Bound again at the rule boundary, including callers other than the parser.
    text_fields = ('sender', 'recipient', 'reply_to', 'subject', 'date', 'body')
    data = {key: str(parsed.get(key, ''))[:100000 if key == 'body' else 2000] for key in text_fields}
    urls = [str(url)[:2000] for url in parsed.get('urls', [])[:100]]
    attachments = parsed.get('attachments', [])[:50]
    links = parsed.get('html_links', [])[:100]
    auth = authentication_results(parsed.get('authentication_results', [])[:20])
    masker = Masker()
    # Match parser field order, including CC/Message-ID, so preview and finding
    # placeholders are consistent for retained values. Never persist the map.
    for key in ('sender', 'recipient', 'cc', 'reply_to', 'subject', 'date', 'message_id', 'body'):
        masker.text(str(parsed.get(key, ''))[:100000 if key == 'body' else 2000])
    for url in urls:
        masker.text(url)
    findings = []
    seen = set()
    missing = []

    def add(rule, source, evidence, explanation, advice=VERIFY_CHANNEL, needle=None):
        if rule in seen:
            return
        seen.add(rule)
        name, severity, points = RULES[rule]
        masked = masker.text(evidence)
        offset = max(0, masked.lower().find(needle.lower()) - 70) if needle else 0
        snippet = masked[offset:offset + 260]
        findings.append({'rule_id': rule, 'indicator': name, 'severity': severity,
                         'score_contribution': points, 'evidence_source': source,
                         'masked_evidence': snippet, 'explanation': explanation,
                         'manual_verification': advice})

    explanations = {
        'urgency': 'The wording pressures the recipient to act quickly or threatens an adverse outcome. Context may also explain legitimate urgency.',
        'credentials': 'The message mentions credentials or account verification. Confirm whether it actually asks for secrets; quoted training material can also match.',
        'financial': 'The message contains payment or financial-request language. This can occur in legitimate correspondence and needs independent confirmation.',
        'impersonation': 'The text invokes an executive or security role that could be used to impersonate authority; the wording alone does not establish identity.',
        'secrecy': 'The wording asks for secrecy or a departure from normal procedures, which can obstruct independent checks.',
        'prompt_injection': 'The evidence contains instructions aimed at influencing an automated reviewer. These are treated solely as evidence and have no authority over this analysis.',
    }
    for rule, pattern in PHRASES.items():
        for key, source in (('subject', 'Subject'), ('body', 'Body')):
            match = re.search(pattern, data[key], re.I)
            if match:
                add(rule, source, data[key], explanations[rule], needle=match.group())
                break
    for key, source in (('subject', 'Subject'), ('body', 'Body')):
        letters = [char for char in data[key] if char.isalpha()]
        if (len(letters) >= 20 and sum(char.isupper() for char in letters) / len(letters) > .75) or re.search(r'[!?]{4,}', data[key]):
            add('emphasis', source, data[key], 'Heavy capitalization or repeated punctuation can amplify pressure; it is a weak contextual indicator.')

    hosts = []
    for url in urls:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or '').lower().rstrip('.')
            if not host or parts.scheme.lower() not in {'http', 'https'}:
                continue
            hosts.append(host)
            def url_finding(rule, explanation):
                add(rule, 'URL', url, explanation, VERIFY_URL)
            try:
                ipaddress.ip_address(host)
                url_finding('url_ip', 'The URL uses an IP address instead of a recognizable domain. This does not establish who operates it.')
            except ValueError:
                pass
            if any(related(host, short) and (host == short or host.endswith('.' + short)) for short in SHORTENERS):
                url_finding('url_shortener', 'A known shortener format hides the final destination. No redirect was followed.')
            if any(label.startswith('xn--') for label in host.split('.')):
                url_finding('url_punycode', 'The domain contains an internationalized-domain encoding, which can support look-alike names but is also used legitimately.')
            if len(url) > 200:
                url_finding('url_long', 'The URL exceeds the documented 200-character threshold and may obscure its destination or parameters.')
            if len(host.split('.')) > 5:
                url_finding('url_subdomains', 'The hostname has more than five labels. Extra labels can make the actual domain harder to identify.')
            if parts.scheme.lower() == 'http':
                url_finding('url_http', 'The link uses HTTP rather than HTTPS. HTTPS alone would not prove legitimacy either.')
            if '@' in parts.netloc:
                url_finding('url_userinfo', 'Text before @ is URL user information, not the destination host; it can mislead a reader.')
            try:
                if parts.port and parts.port not in {80, 443}:
                    url_finding('url_port', 'The destination specifies a port other than 80 or 443.')
            except ValueError:
                url_finding('url_port', 'The URL port is malformed and requires manual inspection.')
            path = unquote(parts.path).lower()
            if any(path.endswith(suffix) for suffix in DANGEROUS_SUFFIXES):
                url_finding('url_file', 'The URL path ends in an executable, disk-image or macro-enabled file extension.')
        except ValueError:
            missing.append('A malformed URL could not be fully evaluated.')
    unique_hosts = sorted(set(hosts))
    if any(not related(a, b) for index, a in enumerate(unique_hosts) for b in unique_hosts[index + 1:]):
        add('url_domains', 'URL', '\n'.join(urls), 'Multiple URL hosts have no direct parent/subdomain relationship. Ownership is unknown without independent checks; shared public suffixes are not treated as proof of common ownership.', VERIFY_URL)

    sender = sender_domain(data['sender'])
    reply = sender_domain(data['reply_to'])
    if not data['sender']:
        missing.append('No From header; sender identity could not be evaluated (zero points).')
    elif not sender:
        add('sender', 'From', data['sender'], 'The supplied sender does not contain a recognizable mailbox/domain. Formatting damage or partial export may explain this.')
    if not data['reply_to']:
        missing.append('No Reply-To header; a sender/Reply-To comparison was unavailable.')
    elif not reply:
        missing.append('Reply-To was malformed and could not be compared reliably.')
    elif sender and not related(sender, reply):
        add('reply_mismatch', 'From / Reply-To', data['sender'] + '\n' + data['reply_to'], 'The sender and reply address use different domain families. Legitimate third-party mail services can also cause this difference.')
    claimed_text = (data['sender'] + '\n' + data['subject'] + '\n' + data['body']).lower()
    matched_org = False
    for name, domains in ORGANIZATIONS.items():
        if re.search(r'\b' + re.escape(name) + r'\b', claimed_text):
            matched_org = True
            if sender and not any(sender == domain or sender.endswith('.' + domain) for domain in domains):
                add('organization', 'From / Subject / Body', data['sender'] + '\n' + data['subject'] + '\n' + data['body'],
                    'A named organization in the explicit local fictional-domain mapping does not match the sender domain. A mention may be quotation rather than an actual claim; verify context.', needle=name)
    institutional = re.search(r'\b(bank|institution|university|government)\b', parseaddr(data['sender'])[0], re.I) or re.search(r'\b(?:we are|on behalf of|from) (?:the )?(?:bank|institution|university|government)\b', claimed_text)
    if sender in FREE_MAIL and institutional:
        add('sender', 'From / Body', data['sender'] + '\n' + data['body'], 'An institutional claim accompanies a free-mail sender domain. This is an identity inconsistency, not proof of impersonation.')
    if not matched_org:
        missing.append('Organization/domain ownership could not be established from the limited local mapping; no ownership lookup was performed.')

    for link in links:
        displayed, destination = str(link.get('displayed', ''))[:2000].strip(), str(link.get('destination', ''))[:2000]
        try:
            visible = urlsplit(displayed if displayed.lower().startswith(('http://', 'https://')) else 'https://' + displayed)
            target = urlsplit(destination)
            if re.fullmatch(r'(?:https?://)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s]*)?', displayed, re.I) and target.scheme.lower() in {'http', 'https'} and visible.hostname and target.hostname and not related(visible.hostname.lower(), target.hostname.lower()):
                add('link_mismatch', 'HTML link', displayed + ' -> ' + destination,
                    'The visible link names a different domain family from its destination. No link was opened.', VERIFY_URL)
        except ValueError:
            missing.append('A malformed HTML link could not be compared.')
    if not links:
        missing.append('No displayed/destination HTML link pairs were available.')
    for attachment in attachments:
        name, kind = str(attachment.get('name', ''))[:2000], str(attachment.get('type', ''))[:2000]
        if any(name.lower().endswith(suffix) for suffix in DANGEROUS_SUFFIXES) or kind.lower() in DANGEROUS_TYPES or 'macroenabled' in kind.lower():
            add('attachment', 'Attachment', name + '\n' + kind, 'The filename or declared content type indicates executable, disk-image or macro-enabled content. Metadata can be misleading; contents were not opened or executed.', VERIFY_ATTACHMENT)
    if not attachments:
        missing.append('No attachments were reported by the parser.')
    for mechanism, values in auth.items():
        if not values:
            missing.append(f'No reported {mechanism.upper()} result; it could not be evaluated.')
    failed = [f'{key}={value}' for key, values in auth.items() for value in values if value in {'fail', 'softfail', 'permerror'}]
    if failed:
        add('authentication', 'Authentication-Results / Received-SPF', '; '.join(failed),
            'The supplied headers report an authentication failure or permanent error. These untrusted header claims were not independently verified.',
            'Ask the receiving mail administrator to verify trusted-boundary SPF, DKIM and DMARC results; copied headers can be forged.')
    if parsed.get('format') == '.txt':
        missing.append('Plain-text evidence does not contain reliably complete email headers or MIME context.')
    if parsed.get('format') == '.csv':
        missing.append('CSV metadata is incomplete; only the selected row and recognized columns were evaluated.')
    bounded = any(len(str(parsed.get(key, ''))) > (100000 if key == 'body' else 2000) for key in text_fields)
    if parsed.get('truncated') or bounded or len(parsed.get('urls', [])) > 100 or len(parsed.get('attachments', [])) > 50 or len(parsed.get('html_links', [])) > 100:
        missing.append('Content was truncated for analysis; omitted material was not evaluated.')
    if parsed.get('warnings'):
        missing.append('Parser warnings are present; consult the masked evidence preview for details.')
    score_sum = sum(item['score_contribution'] for item in findings)
    score = min(100, score_sum)
    classification, level = classification_for(score)
    recommendations = list(dict.fromkeys([VERIFY_CHANNEL] + [item['manual_verification'] for item in findings] +
                          ['Review missing information and the original through approved forensic procedures before reaching a conclusion.']))
    return {'classification': classification, 'risk_score': score, 'risk_level': level,
            'score_label': SCORE_LABEL, 'uncapped_score': score_sum,
            'score_calculation': f'min(100, {score_sum}) = {score}',
            'disclaimer': DISCLAIMER, 'findings': findings, 'missing_information': list(dict.fromkeys(missing)),
            'recommended_verification': recommendations, 'authentication': auth,
            'authentication_note': 'Reported header values only; not independently verified and potentially forged.',
            'analysis_timestamp': utc_now(), 'engine_version': ENGINE_VERSION, 'ruleset_version': RULESET_VERSION}
