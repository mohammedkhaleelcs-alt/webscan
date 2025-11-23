# utils/export_pdf.py
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
import datetime

def generate_pdf(passive_results, active_results, target_url):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 40
    c.setFont('Helvetica-Bold', 14)
    c.drawString(40, y, f'WebScan Report - {target_url}')
    y -= 24
    c.setFont('Helvetica', 10)
    c.drawString(40, y, f'Generated: {datetime.datetime.utcnow().isoformat()} UTC')
    y -= 20

    if passive_results:
        c.setFont('Helvetica-Bold', 12)
        c.drawString(40, y, 'Passive Findings:')
        y -= 18
        c.setFont('Helvetica', 10)
        for p in passive_results:
            if y < 80:
                c.showPage()
                y = height - 40
            c.drawString(50, y, f"- {p.get('title')} ({p.get('severity')})")
            y -= 14
            if p.get('remediation'):
                c.drawString(70, y, f"Remediation: {p.get('remediation')}")
                y -= 16

    if active_results and active_results.get('ports'):
        if y < 120:
            c.showPage()
            y = height - 40
        c.setFont('Helvetica-Bold', 12)
        c.drawString(40, y, 'Active Findings:')
        y -= 18
        c.setFont('Helvetica', 10)
        for a in active_results.get('ports'):
            if y < 80:
                c.showPage()
                y = height - 40
            c.drawString(50, y, f"- {a.get('raw')}")
            y -= 14

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer
