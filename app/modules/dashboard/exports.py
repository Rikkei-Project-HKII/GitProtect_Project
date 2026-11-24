"""CSV/PDF exports read an explicit allowlist of fields, never repository credentials."""
import csv
import io
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from fastapi import HTTPException
from sqlalchemy import select
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Flowable

from app.models import Repository, SecurityAlert

MAX_ROWS = 5000
COLUMNS = ('id', 'repo_name', 'rule_name', 'severity', 'status', 'source', 'file_path',
           'line_number', 'commit_sha', 'secret_masked', 'detected_at')
PALETTE = {'critical': '#dc2626', 'high': '#ea580c', 'medium': '#ca8a04', 'low': '#2563eb'}


def masked_only(value):
    """Fail closed if a legacy/imported row contains a plaintext value."""
    if not value:
        return ''
    if '****' not in value:
        return '[REDACTED]'
    prefix, _, suffix = value.partition('****')
    return prefix[:12] + '****' + suffix[-4:]


def collect_rows(db, repo_id=None, severity=None, status=None):
    if repo_id is not None and db.get(Repository, repo_id) is None:
        raise HTTPException(404, 'Repository not found')
    columns = [SecurityAlert.id, Repository.repo_name, SecurityAlert.rule_name,
               SecurityAlert.severity, SecurityAlert.status, SecurityAlert.source, SecurityAlert.file_path,
               SecurityAlert.line_number, SecurityAlert.commit_sha,
               SecurityAlert.secret_masked, SecurityAlert.detected_at]
    query = select(*columns).join(Repository, Repository.id == SecurityAlert.repo_id)
    for column, value in ((SecurityAlert.repo_id, repo_id), (SecurityAlert.severity, severity),
                          (SecurityAlert.status, status)):
        if value is not None:
            query = query.where(column == value)
    rows = db.execute(query.order_by(SecurityAlert.detected_at.desc(), SecurityAlert.id.desc())
                      .limit(MAX_ROWS + 1)).all()
    if len(rows) > MAX_ROWS:
        raise HTTPException(413, 'Export exceeds 5000 alerts; narrow repository, severity or status filters')
    result = []
    for row in rows:
        item = dict(zip(COLUMNS, row))
        item['secret_masked'] = masked_only(item['secret_masked'])
        item['detected_at'] = item['detected_at'].isoformat() if item['detected_at'] else ''
        result.append(item)
    return result


def csv_cell(value):
    if value is None:
        return ''
    value = str(value)
    # CSV quoting alone does not stop Excel/LibreOffice formulas.
    if value.startswith(('\t', '\r', '\n')) or value.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def csv_bytes(rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output, lineterminator='\r\n')
    writer.writerow(COLUMNS)
    writer.writerows([csv_cell(row.get(key)) for key in COLUMNS] for row in rows)
    return output.getvalue().encode('utf-8-sig')


def register_fonts():
    if 'GP-Regular' in pdfmetrics.getRegisteredFontNames():
        return
    custom = os.getenv('GITPROTECT_FONT_DIR')
    candidates = []
    if custom:
        candidates.append((Path(custom) / 'DejaVuSans.ttf', Path(custom) / 'DejaVuSans-Bold.ttf'))
    candidates += [
        (Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
         Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf')),
        (Path('C:/Windows/Fonts/arial.ttf'), Path('C:/Windows/Fonts/arialbd.ttf')),
    ]
    for regular, bold in candidates:
        if regular.is_file() and bold.is_file():
            pdfmetrics.registerFont(TTFont('GP-Regular', str(regular)))
            pdfmetrics.registerFont(TTFont('GP-Bold', str(bold)))
            pdfmetrics.registerFontFamily('GP-Regular', normal='GP-Regular', bold='GP-Bold',
                                          italic='GP-Regular', boldItalic='GP-Bold')
            return
    raise HTTPException(503, 'PDF font unavailable; install DejaVu Sans or set GITPROTECT_FONT_DIR')


class SeverityChart(Flowable):
    """Vector bars and logo; remain sharp when printed or zoomed."""
    def __init__(self, counts):
        Flowable.__init__(self)
        self.counts = counts
        self.width, self.height = 260 * mm, 42 * mm

    def draw(self):
        c = self.canv
        c.setFillColor(colors.HexColor('#0f766e'))
        c.roundRect(0, 70, 48, 42, 8, stroke=0, fill=1)
        c.setFillColor(colors.white)
        c.setFont('GP-Bold', 17)
        c.drawCentredString(24, 84, 'GP')
        maximum = max(self.counts.values(), default=1) or 1
        for i, (severity, color) in enumerate(PALETTE.items()):
            y = 96 - 25 * i
            c.setFont('GP-Regular', 9)
            c.setFillColor(colors.HexColor('#334155'))
            c.drawString(68, y, severity.title())
            c.setFillColor(colors.HexColor('#f1f5f9'))
            c.roundRect(130, y - 3, 490, 13, 3, stroke=0, fill=1)
            width = 490 * self.counts.get(severity, 0) / maximum
            if width:
                c.setFillColor(colors.HexColor(color))
                c.roundRect(130, y - 3, width, 13, 3, stroke=0, fill=1)
            c.setFillColor(colors.HexColor('#0f172a'))
            c.drawString(630, y, str(self.counts.get(severity, 0)))


def pdf_bytes(rows):
    register_fonts()
    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle('GPTitle', fontName='GP-Bold', fontSize=23, leading=29,
                              textColor=colors.HexColor('#0f172a'), spaceAfter=8))
    styles.add(ParagraphStyle('GPBody', fontName='GP-Regular', fontSize=9, leading=14,
                              textColor=colors.HexColor('#475569')))
    styles.add(ParagraphStyle('GPCell', fontName='GP-Regular', fontSize=7.5, leading=11,
                              wordWrap='CJK'))
    styles.add(ParagraphStyle('GPHeader', parent=styles['GPCell'], fontName='GP-Bold',
                              textColor=colors.white))
    now = datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')
    counts = Counter(row['severity'] for row in rows)
    repo_count = len({row['repo_name'] for row in rows})
    opened = sum(row['status'] in ('open', 'in_review') for row in rows)
    story = [
        Paragraph('GitProtect | Báo cáo an ninh', styles['GPTitle']),
        Paragraph(escape(now) + ' · Tổng hợp dữ liệu theo bộ lọc xuất báo cáo', styles['GPBody']),
        Spacer(1, 5 * mm),
        Paragraph(f'<b>{len(rows)}</b> cảnh báo · <b>{repo_count}</b> kho có cảnh báo · '
                  f'<b>{opened}</b> cảnh báo đang mở', styles['GPBody']),
        Spacer(1, 4 * mm), SeverityChart(counts), Spacer(1, 3 * mm),
        Paragraph('Chuỗi bí mật chỉ xuất ở dạng đã che. CSV giữ đường dẫn đầy đủ; '
                  'PDF rút gọn đường dẫn dài để dễ đọc.', styles['GPBody']),
        Spacer(1, 5 * mm),
    ]
    fields = ('id', 'repo_name', 'severity', 'status', 'rule_name', 'file_path', 'secret_masked')
    labels = ('ID', 'Kho lưu trữ', 'Mức độ', 'Trạng thái', 'Quy tắc', 'Vị trí', 'Bí mật đã che')
    data = [[Paragraph(label, styles['GPHeader']) for label in labels]]
    for row in rows:
        cells = []
        for field in fields:
            value = str(row.get(field) or '')
            if field == 'file_path':
                value = value[:140] + ('…' if len(value) > 140 else '')
                if row.get('line_number'):
                    value += ':' + str(row['line_number'])
            cells.append(Paragraph(escape(value), styles['GPCell']))
        data.append(cells)
    if rows:
        table = Table(data, colWidths=[12*mm, 42*mm, 21*mm, 26*mm, 40*mm, 78*mm, 46*mm],
                      repeatRows=1, hAlign='LEFT')
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f766e')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f1f5f9')]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LINEBELOW', (0, 0), (-1, 0), .5, colors.HexColor('#0f766e')),
        ]))
        story.append(table)
    else:
        story.append(Paragraph('Không có cảnh báo phù hợp với bộ lọc.', styles['GPBody']))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont('GP-Regular', 8)
        canvas.setFillColor(colors.HexColor('#64748b'))
        canvas.drawString(16*mm, 9*mm, 'GitProtect v1.1 · Báo cáo nội bộ')
        canvas.drawRightString(281*mm, 9*mm, 'Trang ' + str(document.page))
        canvas.restoreState()

    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), leftMargin=16*mm,
                            rightMargin=16*mm, topMargin=14*mm, bottomMargin=18*mm,
                            title='GitProtect - Báo cáo an ninh', author='GitProtect')
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
