# app.py
from flask import Flask, render_template, request, jsonify, send_file
from scanners.passive_scan import crawl_and_scan
from scanners.active_scan import run_nmap
from utils.export_csv import generate_csv
from utils.export_pdf import generate_pdf
import json, os, datetime
from io import BytesIO

app = Flask(__name__, template_folder='templates', static_folder='static')

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none';"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Server'] = 'WebScan'
    return response


DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
with open(os.path.join(DATA_DIR, 'advice.json'), 'r') as f:
    ADVICE = json.load(f)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan/passive', methods=['POST'])
def passive_scan():
    # params: url, max_pages (int), max_depth (int)
    payload = request.form or request.get_json() or {}
    url = payload.get('url')
    if not url:
        return jsonify({'error': 'missing url'}), 400
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        max_pages = int(payload.get('max_pages', 10))
    except Exception:
        max_pages = 10
    try:
        max_depth = int(payload.get('max_depth', 1))
    except Exception:
        max_depth = 1
    result = crawl_and_scan(url, max_pages=max_pages, max_depth=max_depth)
    result['timestamp'] = datetime.datetime.utcnow().isoformat()
    return jsonify(result)

@app.route('/scan/active', methods=['POST'])
def active_scan():
    payload = request.form or request.get_json() or {}
    url = payload.get('url')
    consent = payload.get('consent')
    if consent != 'on' and consent is not True and str(consent).lower() != 'true':
        return jsonify({'error': 'consent required'}), 403
    if not url:
        return jsonify({'error': 'missing url'}), 400
    if not url.startswith('http'):
        url = 'http://' + url
    from urllib.parse import urlparse
    host = urlparse(url).netloc.split(':')[0]
    ports = payload.get('ports')  # optional ports string like "80,443" or None
    result = run_nmap(host, ports=ports)
    result['timestamp'] = datetime.datetime.utcnow().isoformat()
    return jsonify(result)

@app.route('/export/csv', methods=['POST'])
def export_csv():
    payload = request.get_json() or {}
    target = payload.get('target', 'unknown')
    passive = payload.get('passive', [])
    active = payload.get('active', {})
    csv_str = generate_csv(passive, active, target)
    filename = f'webscan_{target.replace(":", "_").replace("/", "_")}.csv'
    return (csv_str, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename="{filename}"'
    })

@app.route('/export/pdf', methods=['POST'])
def export_pdf():
    payload = request.get_json() or {}
    target = payload.get('target', 'unknown')
    passive = payload.get('passive', [])
    active = payload.get('active', {})
    pdf_buf = generate_pdf(passive, active, target)
    return send_file(pdf_buf, as_attachment=True, download_name=f'webscan_{target}.pdf', mimetype='application/pdf')

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json() or {}
    q = (data.get('q', '') or '').lower()
    for k, v in ADVICE.items():
        if k in q:
            return jsonify({'answer': v})
    if 'hsts' in q:
        return jsonify({'answer': ADVICE.get('hsts')})
    if 'xss' in q:
        return jsonify({'answer': ADVICE.get('xss')})
    return jsonify({'answer': ADVICE.get('default')})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
