"""Best-effort local masking with one stable mapping per evidence item."""
import re
import ipaddress
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

URL_RE = re.compile(r'https?://[^\s<>"\x27]+', re.I)
PATTERNS = [
    # Bounded mailbox components avoid quadratic scans over long unbroken text.
    ('EMAIL', re.compile(r'[\w.+-]{1,64}@[\w.-]{1,253}\.[A-Za-z]{2,63}')),
    ('PAN', re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', re.I)),
    ('IP', re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')),
    ('PHONE', re.compile(r'(?<!\w)\+\d{1,3}[ .-]?(?:\(\d{2,4}\)[ .-]?)?(?:\d[ .-]?){6,11}\d(?!\w)')),
    ('CARD', re.compile(r'(?<!\w)(?:\d[ -]?){12,18}\d(?!\w)')),
    ('AADHAAR', re.compile(r'(?<!\w)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\w)')),
    ('PHONE', re.compile(r'(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?(?:\d[ .-]?){9,11}\d(?!\w)')),
]
PERSONAL_KEYS = re.compile(r'email|name|phone|mobile|address|user|account|token|aadhaar|pan|dob|birth|ssn', re.I)


# Names require an explicit personal-name label, title, or mailbox display-name
# context. Capitalization alone is not enough to redact ordinary report prose.
NAME_WORD = r"[A-Z][a-z]+(?:[-'][A-Z]?[a-z]+)*"
NAME = NAME_WORD + r'(?:[ \t]+' + NAME_WORD + r'){1,3}'
LABELLED_NAME = NAME_WORD + r'(?:[ \t]+' + NAME_WORD + r'){0,3}'
NAME_CONTEXT = re.compile(r'(?P<label>\b(?i:full name|personal name|investigator name|name)\s*:\s*|\b(?:Mr|Mrs|Ms|Dr)\.?[ \t]+)(?P<name>' + LABELLED_NAME + r')')
MAILBOX_NAME = re.compile(r'(?P<name>' + NAME + r')(?=[ \t]+<?[\w.+-]{1,64}@[\w.-]{1,253}\.[A-Za-z]{2,63})')
STRUCTURED_ID = re.compile(r'(?P<label>\b(?i:passport|employee id|customer id|account number|ssn|access token|api key)\s*[:=]\s*)(?P<value>[A-Za-z0-9][A-Za-z0-9_-]{3,127})')


class Masker:
    def __init__(self):
        self.values = {}
        self.counts = {}

    def placeholder(self, kind, value):
        canonical = re.sub(r'\D', '', value) if kind in {'PHONE', 'CARD', 'AADHAAR'} else value.casefold()
        key = (kind, canonical)
        if key not in self.values:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            self.values[key] = f'[{kind}-{self.counts[kind]}]'
        return self.values[key]

    def text(self, value):
        def mask_url(match):
            try:
                url = urlsplit(match.group())
                query = [(k, (self.sensitive(v) if self.sensitive(v) != v else self.placeholder('PERSONAL', v)) if PERSONAL_KEYS.search(k) else v)
                         for k, v in parse_qsl(url.query, keep_blank_values=True, max_num_fields=200)]
                netloc = url.netloc
                if '@' in netloc:
                    netloc = self.placeholder('PERSONAL', netloc.rsplit('@', 1)[0]) + '@' + netloc.rsplit('@', 1)[1]
                return urlunsplit((url.scheme, netloc, url.path, urlencode(query, safe='[]'), url.fragment))
            except ValueError:
                return self.placeholder('PERSONAL', match.group())
        names = []
        def mask_name(match):
            names.append(match['name'])
            return (match.groupdict().get('label') or '') + self.placeholder('PERSONAL', match['name'])
        value = NAME_CONTEXT.sub(mask_name, value)
        value = MAILBOX_NAME.sub(mask_name, value)
        for name in names:
            value = re.sub(r'(?<!\w)' + re.escape(name) + r'(?!\w)',
                           lambda m: self.placeholder('PERSONAL', name), value)
        value = STRUCTURED_ID.sub(lambda m: m['label'] + self.placeholder('PERSONAL', m['value']), value)
        value = re.sub(r'(?<!\w)\d{3}-\d{2}-\d{4}(?!\w)', lambda m: self.placeholder('PERSONAL', m[0]), value)
        def mask_ipv6(match):
            try:
                ipaddress.IPv6Address(match[0])
                return self.placeholder('IP', match[0])
            except ValueError:
                return match[0]
        value = re.sub(r'(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])', mask_ipv6, value)
        value = URL_RE.sub(mask_url, value)
        return self.sensitive(value)

    def sensitive(self, value):
        for kind, pattern in PATTERNS:
            value = pattern.sub(lambda m: self.placeholder(kind, m.group()), value)
        return value

    def apply(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.apply(item) for item in value]
        if isinstance(value, dict):
            return {key: self.apply(item) for key, item in value.items()}
        return value


def mask_evidence(parsed):
    return Masker().apply(parsed)
