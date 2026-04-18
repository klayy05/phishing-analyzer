import email
import re

def parse_email(filepath):
    with open(filepath, 'rb') as f:
        msg = email.message_from_bytes(f.read())

    results = {}

    results['subject'] = msg.get('Subject', 'N/A')
    results['from'] = msg.get('From', 'N/A')
    results['reply_to'] = msg.get('Reply-To', 'N/A')
    results['date'] = msg.get('Date', 'N/A')
    results['message_id'] = msg.get('Message-ID', 'N/A')

    received_headers = msg.get_all('Received', [])
    results['hop_count'] = len(received_headers)
    results['received_chain'] = received_headers

    auth_results = msg.get('Authentication-Results', '')
    results['spf'] = 'pass' if 'spf=pass' in auth_results.lower() else \
                     'fail' if 'spf=fail' in auth_results.lower() else 'none'
    results['dkim'] = 'pass' if 'dkim=pass' in auth_results.lower() else \
                      'fail' if 'dkim=fail' in auth_results.lower() else 'none'
    results['dmarc'] = 'pass' if 'dmarc=pass' in auth_results.lower() else \
                       'fail' if 'dmarc=fail' in auth_results.lower() else 'none'

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    results['originating_ip'] = None
    if received_headers:
        ips = re.findall(ip_pattern, received_headers[-1])
        if ips:
            results['originating_ip'] = ips[0]

    from_header = results['from']
    display_match = re.match(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
    results['display_name_spoof'] = False
    if display_match:
        display_name = display_match.group(1).strip().lower()
        email_domain = display_match.group(2).split('@')[-1].lower()
        if display_name.replace(' ', '') not in email_domain:
            results['display_name_spoof'] = True

    results['body'] = ''
    results['attachments'] = []
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' and not part.get_filename():
            results['body'] += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        elif part.get_filename():
            results['attachments'].append({
                'filename': part.get_filename(),
                'content_type': content_type,
                'size': len(part.get_payload(decode=True) or b'')
            })

    return results