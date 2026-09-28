"""Bounded local parsing. Never fetch URLs or save attachment payloads."""
import csv
import io
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from modules.privacy import URL_RE

MAX_HEADER = 2000
MAX_BODY = 100000
MAX_URLS = 100
MAX_ATTACHMENTS = 50
MAX_PARTS = 200
MAX_CSV_ROWS = 500
MAX_CSV_COLUMNS = 50
HEADERS = {'from': 'sender', 'to': 'recipient', 'cc': 'cc', 'reply-to': 'reply_to',
           'subject': 'subject', 'date': 'date', 'message-id': 'message_id'}
TEXT_COLUMNS = {'body', 'message', 'text', 'content', 'subject'}


class ParseError(ValueError):
    pass


class TextHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0
        self.links = []
        self.active_link = None
        self.links_truncated = False

    def handle_starttag(self, tag, attrs):
        if tag == 'a' and len(self.links) >= MAX_URLS:
            self.links_truncated = True
            self.active_link = None
        if tag == 'a' and len(self.links) < MAX_URLS and not self.hidden:
            self.active_link = {'displayed': '', 'destination': dict(attrs).get('href', '') or ''}
            self.links.append(self.active_link)
        if tag in {'script', 'style'}:
            self.hidden += 1
        if tag in {'p', 'br', 'div', 'li', 'tr'}:
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag == 'a':
            self.active_link = None
        if tag in {'script', 'style'} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)
            if self.active_link is not None:
                self.active_link['displayed'] += data[:MAX_HEADER + 1 - len(self.active_link['displayed'])]


def html_to_text(value):
    parser = TextHTML()
    parser.feed(value)
    return ''.join(parser.parts)


def csv_rows(data):
    warnings = []
    try:
        reader = csv.reader(io.StringIO(data.decode('utf-8-sig', errors='replace')))
        columns = next(reader, [])
        if not columns or len(columns) > MAX_CSV_COLUMNS:
            raise ParseError('CSV column limit exceeded or headers missing.')
        columns = [column.strip().lower() for column in columns]
        if len(set(columns)) != len(columns):
            raise ParseError('CSV headers must be unique.')
        if not TEXT_COLUMNS.intersection(columns):
            raise ParseError('CSV needs a body, message, text, content or subject column.')
        rows = []
        for index, row in enumerate(reader):
            if index >= MAX_CSV_ROWS:
                warnings.append('CSV row limit reached; remaining rows were not previewed.')
                break
            if len(row) > MAX_CSV_COLUMNS or len(row) != len(columns):
                raise ParseError('CSV row has an invalid number of columns.')
            item = dict(zip(columns, row))
            if any(item.get(key, '').strip() for key in TEXT_COLUMNS):
                rows.append((index + 1, item))
        if not rows:
            raise ParseError('CSV contains no usable email content.')
        return rows, warnings
    except (csv.Error, UnicodeError) as exc:
        raise ParseError('CSV is malformed or a field exceeds the parser limit.') from exc


def parse_email(data, extension, selected_row=None):
    result = {key: '' for key in HEADERS.values()}
    result.update(body='', urls=[], attachments=[], warnings=[], truncated=False,
                  format=extension, html_links=[], authentication_results=[])

    def bounded(value, limit, label):
        if len(value) > limit:
            result['truncated'] = True
            result['warnings'].append(f'{label} truncated at {limit} characters.')
        return value[:limit]

    bodies = []
    url_sources = []
    if extension == '.eml':
        try:
            message = BytesParser(policy=policy.default).parsebytes(data)
            for header, key in HEADERS.items():
                result[key] = bounded(str(message.get(header, '')), MAX_HEADER, 'Header')
            auth_headers = message.get_all('Authentication-Results', [])
            spf_headers = message.get_all('Received-SPF', [])
            if len(auth_headers) + len(spf_headers) > 20:
                result['truncated'] = True
                result['warnings'].append('Authentication header limit reached.')
            result['authentication_results'] = [bounded(str(value), MAX_HEADER, 'Authentication header')
                                                for value in auth_headers[:20]]
            result['authentication_results'].extend(
                'spf=' + bounded(str(value), MAX_HEADER, 'Received-SPF header')
                for value in spf_headers[:max(0, 20 - len(result['authentication_results']))])
            for index, part in enumerate(message.walk()):
                if index >= MAX_PARTS:
                    result['warnings'].append('MIME part limit reached.')
                    result['truncated'] = True
                    break
                if part.defects:
                    result['warnings'].append('Malformed MIME content encountered.')
                if part.is_multipart():
                    continue
                filename = part.get_filename()
                content_type = part.get_content_type()
                payload = part.get_payload(decode=True) or b''
                if filename or part.get_content_disposition() == 'attachment' or content_type not in {'text/plain', 'text/html'}:
                    if len(result['attachments']) < MAX_ATTACHMENTS:
                        result['attachments'].append({'name': bounded(filename or '(unnamed)', MAX_HEADER, 'Attachment name'),
                                                      'type': content_type, 'size': len(payload)})
                    else:
                        result['truncated'] = True
                        result['warnings'].append('Attachment metadata limit reached.')
                    continue
                try:
                    text = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
                except LookupError:
                    text = payload.decode('utf-8', errors='replace')
                    result['warnings'].append('Unknown character set; UTF-8 fallback used.')
                text = bounded(text, MAX_BODY, 'Body part')
                url_sources.append(text)
                if content_type == 'text/html':
                    html = TextHTML()
                    html.feed(text)
                    if html.links_truncated:
                        result['truncated'] = True
                        result['warnings'].append('HTML link metadata limit reached.')
                    bodies.append(''.join(html.parts))
                    for link in html.links:
                        if len(result['html_links']) >= MAX_URLS:
                            result['truncated'] = True
                            result['warnings'].append('HTML link metadata limit reached.')
                            break
                        result['html_links'].append({key: bounded(value, MAX_HEADER, 'HTML link')
                                                     for key, value in link.items()})
                else:
                    bodies.append(text)
        except (ValueError, RecursionError, LookupError) as exc:
            raise ParseError('Email MIME structure could not be parsed safely.') from exc
    elif extension == '.txt':
        text = data.decode('utf-8-sig', errors='replace')
        body = []
        in_headers = True
        for line in text.splitlines(keepends=True):
            match = re.match(r'^(From|To|Cc|Reply-To|Subject|Date|Message-ID|Authentication-Results|Received-SPF):\s*(.*)', line, re.I)
            if in_headers and match:
                header_name = match[1].lower()
                if header_name in {'authentication-results', 'received-spf'}:
                    if len(result['authentication_results']) < 20:
                        result['authentication_results'].append(
                            ('spf=' if header_name == 'received-spf' else '') + bounded(match[2], MAX_HEADER, 'Authentication header'))
                    else:
                        result['truncated'] = True
                        result['warnings'].append('Authentication header limit reached.')
                else:
                    result[HEADERS[header_name]] = bounded(match[2], MAX_HEADER, 'Header')
            else:
                in_headers = False
                body.append(line)
        bodies.append(''.join(body))
    elif extension == '.csv':
        rows, warnings = csv_rows(data)
        result['warnings'].extend(warnings)
        result['truncated'] = bool(warnings)
        if selected_row is None and len(rows) != 1:
            raise ParseError('Select one CSV row before registration.')
        chosen = rows[0] if selected_row is None else next((r for r in rows if r[0] == selected_row), None)
        if chosen is None:
            raise ParseError('Selected CSV row is unavailable.')
        result['selected_csv_row'] = chosen[0]
        row = chosen[1]
        for column, key in {**HEADERS, 'sender': 'sender', 'recipient': 'recipient'}.items():
            if row.get(column):
                result[key] = bounded(row[column], MAX_HEADER, 'Header')
        bodies.append('\n'.join(row[key] for key in ('body', 'message', 'text', 'content') if row.get(key)))
    else:
        raise ParseError('Unsupported evidence format.')
    result['body'] = bounded('\n'.join(bodies), MAX_BODY, 'Body')
    urls = dict.fromkeys(m.group().rstrip('.,);') for text in [result['body'], *url_sources] for m in URL_RE.finditer(text))
    if len(urls) > MAX_URLS:
        result['truncated'] = True
        result['warnings'].append('URL limit reached.')
    result['urls'] = [bounded(url, MAX_HEADER, 'URL') for url in list(urls)[:MAX_URLS]]
    result['warnings'] = list(dict.fromkeys(result['warnings']))
    return result
