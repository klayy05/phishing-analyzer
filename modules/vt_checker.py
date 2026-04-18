import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')

VT_BASE = 'https://www.virustotal.com/api/v3'
VT_HEADERS = {'x-apikey': VT_API_KEY}

ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2'
ABUSEIPDB_HEADERS = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}

def check_url(url):
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    try:
        r = requests.get(f'{VT_BASE}/urls/{url_id}', headers=VT_HEADERS, timeout=10)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            return {
                'url': url,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'error': False
            }
        elif r.status_code == 404:
            return {'url': url, 'malicious': 0, 'suspicious': 0, 'error': False, 'not_found': True}
        else:
            return {'url': url, 'malicious': 0, 'suspicious': 0, 'error': True}
    except requests.exceptions.Timeout:
        return {'url': url, 'malicious': 0, 'suspicious': 0, 'error': True, 'reason': 'timeout'}
    except Exception as e:
        return {'url': url, 'malicious': 0, 'suspicious': 0, 'error': True, 'reason': str(e)}

def check_ip(ip):
    try:
        params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True}
        r = requests.get(
            f'{ABUSEIPDB_BASE}/check',
            headers=ABUSEIPDB_HEADERS,
            params=params,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()['data']
            return {
                'ip': ip,
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'domain': data.get('domain', 'Unknown'),
                'last_reported': data.get('lastReportedAt', 'Never'),
                'is_tor': data.get('isTor', False),
                'usage_type': data.get('usageType', 'Unknown'),
                'error': False
            }
        else:
            return {'ip': ip, 'abuse_score': 0, 'error': True}
    except requests.exceptions.Timeout:
        return {'ip': ip, 'abuse_score': 0, 'error': True, 'reason': 'timeout'}
    except Exception as e:
        return {'ip': ip, 'abuse_score': 0, 'error': True, 'reason': str(e)}