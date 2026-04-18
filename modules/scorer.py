def calculate_score(header_data, urls, urgency_words, vt_results, ip_result=None):
    score = 0
    indicators = []

    # Authentication failures
    if header_data['spf'] == 'fail':
        score += 25
        indicators.append({'label': 'SPF failed', 'weight': 25, 'severity': 'high'})
    if header_data['dkim'] == 'fail':
        score += 20
        indicators.append({'label': 'DKIM failed', 'weight': 20, 'severity': 'high'})
    if header_data['dmarc'] == 'fail':
        score += 20
        indicators.append({'label': 'DMARC failed', 'weight': 20, 'severity': 'high'})

    # Spoofing
    if header_data.get('display_name_spoof'):
        score += 30
        indicators.append({'label': 'Display name spoofing detected', 'weight': 30, 'severity': 'critical'})

    if header_data.get('reply_to') and header_data['reply_to'] != header_data['from']:
        score += 15
        indicators.append({'label': 'Reply-To differs from From address', 'weight': 15, 'severity': 'medium'})

    # URL indicators
    for url_data in urls:
        if url_data.get('suspicious_tld'):
            score += 15
            indicators.append({'label': f"Suspicious TLD in URL: {url_data['domain']}", 'weight': 15, 'severity': 'medium'})
        if url_data.get('ip_url'):
            score += 20
            indicators.append({'label': f"IP address used as URL: {url_data['domain']}", 'weight': 20, 'severity': 'high'})
        if url_data.get('long_subdomain'):
            score += 10
            indicators.append({'label': f"Long subdomain chain: {url_data['domain']}", 'weight': 10, 'severity': 'medium'})
        if url_data.get('encoded'):
            score += 10
            indicators.append({'label': f"URL encoding detected: {url_data['domain']}", 'weight': 10, 'severity': 'low'})

    # VirusTotal results
    for vt in vt_results:
        if vt.get('malicious', 0) > 0:
            score += 40
            indicators.append({
                'label': f"VirusTotal: {vt['malicious']} engines flagged {vt['url'][:50]}",
                'weight': 40,
                'severity': 'critical'
            })
        elif vt.get('suspicious', 0) > 0:
            score += 15
            indicators.append({
                'label': f"VirusTotal: {vt['suspicious']} engines marked suspicious",
                'weight': 15,
                'severity': 'medium'
            })

    # Urgency / social engineering
    if len(urgency_words) >= 3:
        score += 10
        indicators.append({
            'label': f"Urgency language detected: {', '.join(urgency_words[:5])}",
            'weight': 10,
            'severity': 'low'
        })

    # Dangerous attachments
    dangerous_exts = {'.exe', '.bat', '.ps1', '.vbs', '.js', '.docm', '.xlsm', '.zip', '.rar', '.iso'}
    for att in header_data.get('attachments', []):
        ext = '.' + att['filename'].split('.')[-1].lower()
        if ext in dangerous_exts:
            score += 35
            indicators.append({
                'label': f"Dangerous attachment: {att['filename']}",
                'weight': 35,
                'severity': 'critical'
            })

            # AbuseIPDB IP reputation
    if ip_result and not ip_result.get('error'):
        if ip_result['abuse_score'] >= 80:
            score += 35
            indicators.append({
                'label': f"IP {ip_result['ip']} has abuse score {ip_result['abuse_score']}% ({ip_result['total_reports']} reports) — ISP: {ip_result['isp']}",
                'weight': 35,
                'severity': 'critical'
            })
        elif ip_result['abuse_score'] >= 40:
            score += 20
            indicators.append({
                'label': f"IP {ip_result['ip']} has moderate abuse score {ip_result['abuse_score']}% ({ip_result['total_reports']} reports)",
                'weight': 20,
                'severity': 'high'
            })
        elif ip_result['abuse_score'] >= 10:
            score += 10
            indicators.append({
                'label': f"IP {ip_result['ip']} has low abuse score {ip_result['abuse_score']}% ({ip_result['total_reports']} reports)",
                'weight': 10,
                'severity': 'medium'
            })
        if ip_result.get('is_tor'):
            score += 20
            indicators.append({
                'label': f"Originating IP {ip_result['ip']} is a Tor exit node",
                'weight': 20,
                'severity': 'critical'
            })

    # Verdict
    if score >= 70:
        verdict = 'MALICIOUS'
        verdict_color = 'danger'
    elif score >= 35:
        verdict = 'SUSPICIOUS'
        verdict_color = 'warning'
    else:
        verdict = 'BENIGN'
        verdict_color = 'success'

    return {
        'score': min(score, 100),
        'verdict': verdict,
        'verdict_color': verdict_color,
        'indicators': sorted(indicators, key=lambda x: x['weight'], reverse=True)
    }