import sys
import time
from modules.header_parser import parse_email
from modules.url_extractor import extract_urls, check_urgency
from modules.vt_checker import check_url, check_ip
from modules.scorer import calculate_score
from jinja2 import Environment, FileSystemLoader

def analyze(eml_path, output_path='output/report.html'):
    print('\n========================================')
    print('   Phishing Email Analyzer v1.0')
    print('========================================\n')

    # Step 1 - Parse headers and body
    print('[1/4] Parsing email headers and body...')
    try:
        header_data = parse_email(eml_path)
    except FileNotFoundError:
        print(f'[ERROR] File not found: {eml_path}')
        sys.exit(1)
    except Exception as e:
        print(f'[ERROR] Failed to parse email: {e}')
        sys.exit(1)

    print(f'      From    : {header_data["from"]}')
    print(f'      Subject : {header_data["subject"]}')
    print(f'      SPF     : {header_data["spf"].upper()}')
    print(f'      DKIM    : {header_data["dkim"].upper()}')
    print(f'      DMARC   : {header_data["dmarc"].upper()}')
    print(f'      Spoof   : {"YES - FLAGGED" if header_data["display_name_spoof"] else "No"}')

    # Step 2 - Extract URLs and urgency words
    print('\n[2/4] Extracting URLs and scanning body...')
    urls = extract_urls(header_data['body'])
    urgency_words = check_urgency(header_data['body'])
    print(f'      URLs found     : {len(urls)}')
    print(f'      Urgency words  : {", ".join(urgency_words) if urgency_words else "None"}')
    print(f'      Attachments    : {len(header_data["attachments"])}')

    if urls:
        print('      URLs detected:')
        for u in urls:
            flags = []
            if u['suspicious_tld']: flags.append('suspicious TLD')
            if u['ip_url']: flags.append('IP-based URL')
            if u['long_subdomain']: flags.append('long subdomain')
            if u['encoded']: flags.append('encoded')
            flag_str = f' [{", ".join(flags)}]' if flags else ''
            print(f'        - {u["url"][:70]}{flag_str}')
     
     # Step 3
    print('\n[3/4] Checking URLs against VirusTotal + IP against AbuseIPDB...')
    vt_results = []
    ip_result = None

    if not urls:
        print('      No URLs to check.')
    else:
        for url_item in urls[:5]:
            print(f'      [VT]  Checking: {url_item["url"][:60]}...')
            vt = check_url(url_item['url'])
            vt_results.append(vt)
            if vt.get('error'):
                print(f'             Result : ERROR - {vt.get("reason", "unknown")}')
            elif vt.get('not_found'):
                print(f'             Result : Not in VirusTotal database')
            else:
                print(f'             Result : {vt["malicious"]} malicious, {vt["suspicious"]} suspicious')
            time.sleep(0.5)

    if header_data.get('originating_ip'):
        print(f'      [ABUSEIPDB] Checking IP: {header_data["originating_ip"]}...')
        ip_result = check_ip(header_data['originating_ip'])
        if ip_result.get('error'):
            print(f'             Result : ERROR')
        else:
            print(f'             Abuse score : {ip_result["abuse_score"]}%')
            print(f'             Reports     : {ip_result["total_reports"]}')
            print(f'             Country     : {ip_result["country"]}')
            print(f'             ISP         : {ip_result["isp"]}')
            print(f'             Tor node    : {"YES" if ip_result["is_tor"] else "No"}')

    # Step 4 - Calculate score and generate report
    print('\n[4/4] Calculating risk score...')
    score_data = calculate_score(header_data, urls, urgency_words, vt_results, ip_result)

    print(f'\n========================================')
    print(f'   VERDICT  : {score_data["verdict"]}')
    print(f'   SCORE    : {score_data["score"]}/100')
    print(f'========================================')

    if score_data['indicators']:
        print('\n   Risk indicators found:')
        for ind in score_data['indicators']:
            print(f'   [{ind["severity"].upper()}] {ind["label"]} (+{ind["weight"]})')

    # Generate HTML report
    print(f'\n[*] Generating HTML report...')
    try:
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report.html')
        html = template.render(
            header=header_data,
            urls=urls,
            urgency=urgency_words,
            score=score_data,
            ip_result=ip_result,
            eml_path=eml_path,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        )
        with open(output_path, 'w') as f:
            f.write(html)
        print(f'[+] Report saved to: {output_path}')
        print(f'[+] Open it in your browser to view the full report.\n')
    except Exception as e:
        print(f'[ERROR] Failed to generate report: {e}')

    return score_data

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 analyzer.py <email.eml> [output.html]')
        print('Example: python3 analyzer.py samples/test.eml output/report.html')
        sys.exit(1)
    eml_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else 'output/report.html'
    analyze(eml_path, out_path)