# utils/export_csv.py
import pandas as pd
from io import StringIO

def generate_csv(passive_results, active_results, target_url):
    rows = []
    for p in passive_results:
        rows.append({
            'type': 'passive',
            'id': p.get('id'),
            'title': p.get('title'),
            'severity': p.get('severity'),
            'remediation': p.get('remediation', '')
        })
    for a in active_results.get('ports', []) if active_results else []:
        rows.append({
            'type': 'active',
            'id': None,
            'title': a.get('raw'),
            'severity': '',
            'remediation': ''
        })
    df = pd.DataFrame(rows)
    buf = StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue()
