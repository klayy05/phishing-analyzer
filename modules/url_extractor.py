import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.link', '.work'}
URGENCY_KEYWORDS = ['verify', 'account', 'suspended', 'confirm', 'urgent',
                    'login', 'password', 'update', 'security', 'alert', 'click here']

def extract_urls(body_text):
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    raw_urls = re.findall(url_pattern, body_text)

    results = []
    seen = set()

    for url in raw_urls:
        url = url.rstrip('.,;)')
        if url in seen:
            continue
        seen.add(url)

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''

        results.append({
            'url': url,
            'domain': domain,
            'suspicious_tld': tld in SUSPICIOUS_TLDS,
            'ip_url': bool(re.match(r'\d{1,3}(\.\d{1,3}){3}', domain)),
            'long_subdomain': domain.count('.') > 3,
            'encoded': '%' in url,
        })

    return results

def check_urgency(body_text):
    body_lower = body_text.lower()
    found = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    return found