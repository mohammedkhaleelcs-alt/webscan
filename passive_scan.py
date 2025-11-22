# scanners/passive_scan.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import time

EXPECTED_HEADERS = [
    ('strict-transport-security', 'HSTS'),
    ('content-security-policy', 'CSP'),
    ('x-frame-options', 'X-Frame-Options'),
    ('x-content-type-options', 'X-Content-Type-Options'),
    ('referrer-policy', 'Referrer-Policy'),
    ('x-xss-protection', 'X-XSS-Protection')
]

def analyze_headers(headers):
    results = []
    lower = {k.lower(): v for k, v in headers.items()}
    for key, title in EXPECTED_HEADERS:
        if key not in lower:
            results.append({
                'id': f'missing_{key}',
                'title': f'Missing {title}',
                'severity': 'medium',
                'remediation': f'Add {title} header',
                'header': key
            })
    if 'server' in lower:
        results.append({
            'id': 'server_banner',
            'title': 'Server header present (fingerprinting)',
            'severity': 'low',
            'remediation': 'Remove or obfuscate Server header',
            'value': lower.get('server')
        })
    return results

def inspect_html_for_deprecated(html_text):
    results = []
    soup = BeautifulSoup(html_text or '', 'html.parser')
    scripts = [s.get('src') for s in soup.find_all('script') if s.get('src')]
    for src in scripts:
        s = src.lower()
        if 'jquery' in s:
            if '/1.' in s or '/2.' in s or 'jquery-1' in s or 'jquery-2' in s:
                results.append({
                    'id': 'deprecated_jquery',
                    'title': 'Old jQuery detected',
                    'severity': 'low',
                    'remediation': 'Upgrade jQuery to latest 3.x or remove dependency',
                    'value': src
                })
    return results

def same_domain(url1, url2):
    return urlparse(url1).netloc.split(':')[0] == urlparse(url2).netloc.split(':')[0]

def crawl_and_scan(start_url, max_pages=10, max_depth=1, timeout=10):
    """
    Crawl same-domain pages up to max_pages and max_depth.
    Returns combined passive findings and page list.
    """
    start = time.time()
    seen = set()
    to_visit = [(start_url, 0)]
    findings = []
    pages = []

    headers = {'User-Agent': 'WebScan/1.0'}
    while to_visit and len(seen) < max_pages:
        url, depth = to_visit.pop(0)
        if url in seen or depth > max_depth:
            continue
        try:
            r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        except Exception as e:
            findings.append({'id': 'fetch_error', 'title': f'Failed to fetch {url}', 'severity': 'low', 'remediation': str(e)})
            seen.add(url)
            continue

        seen.add(url)
        pages.append({'url': url, 'status_code': r.status_code})
        # header checks
        findings.extend(analyze_headers(r.headers))
        # html checks
        findings.extend(inspect_html_for_deprecated(r.text))

        # extract links for further crawling (same domain only)
        if depth < max_depth:
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                joined = urljoin(url, href)
                if same_domain(start_url, joined) and joined not in seen:
                    to_visit.append((joined, depth + 1))

    return {'results': findings, 'pages': pages, 'duration': time.time() - start}
