# parsers/report_gen.py
"""
Improved PDF report generator for artifacts and correlations.

Fix included:
- Escape user-provided strings before passing to reportlab.platypus.Paragraph
  to avoid 'parse ended with X unclosed tags para' errors when names/paths
  contain '<' or other special characters.
- Truncate extremely long cell text for PDF table cells to avoid Flowable/Table
  "tallest cell ... too large" errors while preserving full data elsewhere.
- Provide `allow_markup` option for content we intentionally format with
  minimal ReportLab markup (e.g. <font> tags for colored labels).
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image,
)
from reportlab.lib.units import mm
import datetime
import sqlite3
import hashlib
from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional
import os
import html

# Constants
PAGE_MARGIN_MM = 18
MAX_SAMPLE_ROWS = 1000  # limit to avoid enormous PDFs
DEFAULT_FONT = "Helvetica"


# ---------------------------
# Helpers
# ---------------------------

def _truncate_text(s: Optional[str], max_chars: int = 400) -> str:
    """
    Truncate long strings for PDF table cells while preserving readability.
    - Replace long runs of whitespace/newlines with single space.
    - Truncate at max_chars, adding ellipsis.
    """
    if s is None:
        return ""
    try:
        text = str(s)
        # normalize whitespace, keep it short
        text = " ".join(text.split())
        if len(text) <= max_chars:
            return text
        # prefer to cut at a space near the boundary
        idx = text.rfind(" ", 0, max_chars)
        if idx == -1 or idx < int(max_chars * 0.6):
            idx = max_chars
        return text[:idx].rstrip() + "..."
    except Exception:
        try:
            return str(s)[:max_chars] + "..."
        except Exception:
            return ""


def _sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _safe_isoformat(ts: Optional[str]) -> str:
    if not ts:
        return ""
    try:
        s = ts
        if s.endswith("Z"):
            s = s[:-1]
        dt = datetime.datetime.fromisoformat(s)
        return dt.isoformat() + "Z"
    except Exception:
        return ts


def _coalesce_time(row: Dict[str, Any]) -> str:
    return (row.get("timestamp") or row.get("last_access") or "") or ""


def _parse_time_for_sort(s: str):
    if not s:
        return datetime.datetime(1970, 1, 1)
    try:
        t = s
        if t.endswith("Z"):
            t = t[:-1]
        return datetime.datetime.fromisoformat(t)
    except Exception:
        return datetime.datetime(1970, 1, 1)


def _get_styles():
    styles = getSampleStyleSheet()
    normal = ParagraphStyle(
        "NormalWrap",
        parent=styles["Normal"],
        fontName=DEFAULT_FONT,
        fontSize=9,
        leading=12,
        wordWrap="CJK",
    )
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], alignment=1, fontName=DEFAULT_FONT, fontSize=18, leading=22)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontName=DEFAULT_FONT, fontSize=14, leading=18)
    h3 = ParagraphStyle("H3", parent=styles["Heading3"], fontName=DEFAULT_FONT, fontSize=11, leading=14)
    small = ParagraphStyle("Small", parent=styles["Normal"], fontName=DEFAULT_FONT, fontSize=8, leading=10)
    mono = ParagraphStyle("Mono", parent=styles["Normal"], fontName="Courier", fontSize=8, leading=10, wordWrap="CJK")
    italic = ParagraphStyle("ItalicSmall", parent=styles["Italic"], fontName=DEFAULT_FONT, fontSize=8, leading=10)

    type_colors = {
        "prefetch": colors.HexColor("#2E7D32"),
        "lnk": colors.HexColor("#1565C0"),
        "recycle": colors.HexColor("#C62828"),
        "shellbag": colors.HexColor("#EF6C00"),
        "unknown": colors.HexColor("#424242"),
    }

    return {"normal": normal, "h1": h1, "h2": h2, "h3": h3, "small": small, "mono": mono, "italic": italic, "type_colors": type_colors}


def _content_width(doc):
    page_w, page_h = doc.pagesize
    left = doc.leftMargin
    right = doc.rightMargin
    return page_w - left - right


def _hex_of_type(atype: str) -> str:
    mapping = {"prefetch": "#2E7D32", "lnk": "#1565C0", "recycle": "#C62828", "shellbag": "#EF6C00", "unknown": "#424242"}
    if not atype:
        return mapping["unknown"]
    return mapping.get(atype.lower(), mapping["unknown"])


def _embed_image_if_exists(story, path_or_stream, doc, caption=None, max_width_ratio=0.92):
    try:
        if not path_or_stream:
            return
        if isinstance(path_or_stream, str) and not os.path.exists(path_or_stream):
            return
        img = Image(path_or_stream)
        content_w = _content_width(doc)
        max_w = content_w * max_width_ratio
        iw, ih = img.imageWidth, img.imageHeight
        if iw <= 0 or ih <= 0:
            return
        scale = min(1.0, max_w / iw)
        img.drawWidth = iw * scale
        img.drawHeight = ih * scale
        story.append(img)
        if caption:
            story.append(_p(caption, _get_styles()["small"]))
        story.append(Spacer(1, 8))
    except Exception:
        # ignore embedding errors to avoid breaking report generation
        pass


# ---------------------------
# Paragraph helper (ESCAPING)
# ---------------------------

def _p(text: Any, style, allow_markup: bool = False) -> Paragraph:
    """
    Create a ReportLab Paragraph while safely escaping user-supplied content.

    - text: value to render
    - style: ReportLab ParagraphStyle
    - allow_markup: when True, text is NOT escaped (use only when you intentionally
      include small, safe ReportLab inline tags like <font> or <b>). All other
      user strings should be left with allow_markup=False.
    """
    if text is None:
        text = ""
    s = str(text)

    # Replace literal 4 spaces with non-breaking spaces for nicer appearance in PDF
    s = s.replace("    ", "&nbsp;&nbsp;&nbsp;&nbsp;")

    if not allow_markup:
        # Escape special HTML characters so ReportLab doesn't try to parse them.
        # Also convert newlines to <br/> so text wraps on separate lines inside Paragraph
        s = html.escape(s)
        s = s.replace("\n", "<br/>")
    else:
        # If markup allowed, still normalize newlines to <br/>
        s = s.replace("\n", "<br/>")

    return Paragraph(s, style)


# ---------------------------
# Data fetcher
# ---------------------------
def fetch_artifacts(db_path: str) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM artifacts")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ---------------------------
# PDF Generators
# ---------------------------
def generate_pdf_report(db_path: str, output_path: str, title: str = "Artifacts Report", metadata: Optional[Dict[str, str]] = None) -> str:
    rows = fetch_artifacts(db_path)
    total = len(rows)
    by_type = Counter([r.get("artifact_type") or "unknown" for r in rows])
    rows_sorted = sorted(rows, key=lambda r: _parse_time_for_sort(_coalesce_time(r)))

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=PAGE_MARGIN_MM * mm,
        leftMargin=PAGE_MARGIN_MM * mm,
        topMargin=PAGE_MARGIN_MM * mm,
        bottomMargin=PAGE_MARGIN_MM * mm,
    )
    styles = _get_styles()
    story = []

    story.append(Paragraph(title, styles["h1"]))
    story.append(Spacer(1, 6))
    gen_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    story.append(Paragraph(f"Generated (UTC): {gen_time}", styles["normal"]))
    story.append(Spacer(1, 6))

    if metadata is None:
        metadata = {}

    # Define the order of metadata keys
    metadata_order = [
        'Case ID', 'Evidence ID', 'Description', 'Examiner', 'Notes',
        'Source', 'OS', 'Tool Version', 'DB SHA256'
    ]
    
    metadata["DB SHA256"] = _sha256_file(db_path)

    meta_lines = []
    for key in metadata_order:
        if key in metadata:
            value = metadata[key]
            meta_lines.append([Paragraph(f"<b>{html.escape(str(key))}</b>", styles["small"]), _p(str(value), styles["small"], allow_markup=False)])

    meta_lines.append([Paragraph("<b>Total artifacts</b>", styles["small"]), Paragraph(str(total), styles["small"])])
    types_summary = ", ".join(f"{html.escape(str(k))} ({v})" for k, v in by_type.most_common())
    meta_lines.append([Paragraph("<b>Artifact types</b>", styles["small"]), _p(types_summary, styles["small"], allow_markup=False)])

    meta_tbl = Table(meta_lines, colWidths=[40 * mm, _content_width(doc) - 40 * mm])
    meta_tbl.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, 0), 0.25, colors.lightgrey),
            ]
        )
    )
    story.append(meta_tbl)
    story.append(Spacer(1, 12))

    # embed charts if provided
    chart_counts = metadata.get("chart_counts") if isinstance(metadata, dict) else None
    chart_timeline = metadata.get("chart_timeline") if isinstance(metadata, dict) else None
    if chart_counts:
        _embed_image_if_exists(story, chart_counts, doc, caption="Artifact counts (by type)")
    if chart_timeline:
        _embed_image_if_exists(story, chart_timeline, doc, caption="Event distribution over time (histogram)")

    story.append(Paragraph("Timeline (chronological sample)", styles["h2"]))
    header = ["Time (UTC)", "Type", "Name", "Path", "Extra"]
    data = [[_p(h, styles["h3"], allow_markup=False) for h in header]]

    sample = rows_sorted[:MAX_SAMPLE_ROWS]
    for r in sample:
        time_text = _safe_isoformat(_coalesce_time(r))
        a_type = r.get("artifact_type") or "unknown"
        # we intentionally add a small <font> tag for colored label — allow_markup=True
        a_label = f'<font color="{_hex_of_type(a_type)}"><b>{html.escape(str(a_type))}</b></font>'

        # Truncate long fields for PDF display to avoid ReportLab blowups
        name_short = _truncate_text(r.get("name") or "", max_chars=200)
        path_short = _truncate_text(r.get("path") or "", max_chars=300)
        extra_short = _truncate_text(r.get("extra") or "", max_chars=300)

        data.append([
            _p(time_text, styles["mono"], allow_markup=False),
            _p(a_label, styles["normal"], allow_markup=True),
            _p(name_short, styles["normal"], allow_markup=False),
            _p(path_short, styles["normal"], allow_markup=False),
            _p(extra_short, styles["normal"], allow_markup=False),
        ])

    if len(rows_sorted) > MAX_SAMPLE_ROWS:
        data.append([_p("...", styles["small"], allow_markup=False)] + [_p("", styles["small"], allow_markup=False)] * (len(header) - 1))

    total_width = _content_width(doc)
    col_widths = [total_width * 0.18, total_width * 0.12, total_width * 0.22, total_width * 0.30, total_width * 0.18]
    sum_widths = sum(col_widths)
    if sum_widths != total_width:
        ratio = total_width / sum_widths
        col_widths = [w * ratio for w in col_widths]

    timeline_tbl = Table(data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EFEFEF")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)])
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.add("BACKGROUND", (0, i), (-1, i), colors.whitesmoke)
    timeline_tbl.setStyle(style)
    story.append(timeline_tbl)
    story.append(PageBreak())

    story.append(Paragraph("Detailed artifacts (grouped by type)", styles["h2"]))
    grouped = defaultdict(list)
    for r in rows_sorted:
        grouped[r.get("artifact_type") or "unknown"].append(r)

    for atype, items in grouped.items():
        story.append(Paragraph(f"{html.escape(str(atype))} ({len(items)})", styles["h3"]))
        hdr = ["Time", "Name", "Path", "Extra"]
        table_data = [[_p(h, styles["h3"], allow_markup=False) for h in hdr]]
        for r in items[:200]:
            # Truncate for PDF table cells
            name_short = _truncate_text(r.get("name") or "", max_chars=200)
            path_short = _truncate_text(r.get("path") or "", max_chars=400)
            extra_short = _truncate_text(r.get("extra") or "", max_chars=500)

            table_data.append([
                _p(_safe_isoformat(_coalesce_time(r)), styles["mono"], allow_markup=False),
                _p(name_short, styles["normal"], allow_markup=False),
                _p(path_short, styles["normal"], allow_markup=False),
                _p(extra_short, styles["normal"], allow_markup=False),
            ])

        t = Table(table_data, colWidths=[total_width * 0.16, total_width * 0.24, total_width * 0.40, total_width * 0.20], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F8F8F8")), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        for i in range(1, len(table_data)):
            if i % 2 == 0:
                t.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), colors.whitesmoke)]))
        story.append(t)
        story.append(Spacer(1, 8))

    story.append(Spacer(1, 12))
    type_colors = _get_styles()["type_colors"]
    legend_items = []
    legend_row = []
    for i, (k, col) in enumerate(type_colors.items()):
        legend_row.append(Paragraph(f'<font color="{col}">{html.escape(str(k))}</font>', _get_styles()["small"]))
    while len(legend_row) < 4:
        legend_row.append(Paragraph("", _get_styles()["small"]))
    legend = Table([legend_row], colWidths=[total_width / 4] * 4)
    story.append(Paragraph("Legend: artifact type color coding", _get_styles()["h3"]))
    story.append(legend)
    story.append(Spacer(1, 6))
    story.append(Paragraph("Notes: Times are taken from 'timestamp' or 'last_access' where available. This report contains a sample view of data; full DB exported separately.", _get_styles()["italic"]))

    doc.build(story)
    return output_path


def generate_correlation_pdf(db_path: str, output_path: str, title: str = "Artifacts Correlation Report", metadata: Optional[Dict[str, str]] = None) -> str:
    try:
        from correlator import correlate_artifacts
    except Exception as exc:
        raise RuntimeError(f"Could not import correlator.correlate_artifacts: {exc}")

    conn = sqlite3.connect(db_path)
    try:
        rows = correlate_artifacts(conn)
    finally:
        conn.close()

    sessions = defaultdict(list)
    for r in rows:
        sess = r.get("session", 0)
        sessions[sess].append(r)

    total_sessions = len(sessions)
    total_events = len(rows)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=PAGE_MARGIN_MM * mm,
        leftMargin=PAGE_MARGIN_MM * mm,
        topMargin=PAGE_MARGIN_MM * mm,
        bottomMargin=PAGE_MARGIN_MM * mm,
    )
    styles = _get_styles()
    story = []

    story.append(Paragraph(title, styles["h1"]))
    story.append(Spacer(1, 6))
    
    if metadata is None:
        metadata = {}

    # Define the order of metadata keys
    metadata_order = [
        'Case ID', 'Evidence ID', 'Description', 'Examiner', 'Notes',
        'Source', 'OS', 'Tool Version', 'DB SHA256'
    ]
    
    metadata["DB SHA256"] = _sha256_file(db_path)

    meta_lines = []
    for key in metadata_order:
        if key in metadata:
            value = metadata[key]
            meta_lines.append([Paragraph(f"<b>{html.escape(str(key))}</b>", styles["small"]), _p(str(value), styles["small"], allow_markup=False)])
    
    meta_lines.append([Paragraph("<b>Total Sessions</b>", styles["small"]), Paragraph(str(total_sessions), styles["small"])])
    meta_lines.append([Paragraph("<b>Total Events</b>", styles["small"]), Paragraph(str(total_events), styles["small"])])

    meta_tbl = Table(meta_lines, colWidths=[40 * mm, _content_width(doc) - 40 * mm])
    meta_tbl.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, 0), 0.25, colors.lightgrey),
            ]
        )
    )
    story.append(meta_tbl)
    story.append(Spacer(1, 12))


    # embed charts if present
    if metadata:
        chart_counts = metadata.get("chart_counts")
        chart_timeline = metadata.get("chart_timeline")
        if chart_counts:
            _embed_image_if_exists(story, chart_counts, doc, caption="Artifact counts (by type)")
        if chart_timeline:
            _embed_image_if_exists(story, chart_timeline, doc, caption="Event distribution over time (histogram)")

    summary = [["Session ID", "Event Count", "First Time", "Last Time"]]
    for sess_id, items in sorted(sessions.items()):
        times = [i.get("timestamp") or i.get("last_access") or "" for i in items]
        parsed = sorted([_parse_time_for_sort(t) for t in times if t])
        first = parsed[0].isoformat() + "Z" if parsed else ""
        last = parsed[-1].isoformat() + "Z" if parsed else ""
        summary.append([_p(str(sess_id), styles["normal"], allow_markup=False), _p(str(len(items)), styles["normal"], allow_markup=False), _p(first, styles["mono"], allow_markup=False), _p(last, styles["mono"], allow_markup=False)])

    total_w = _content_width(doc)
    tbl = Table(summary, colWidths=[total_w * 0.12, total_w * 0.12, total_w * 0.38, total_w * 0.38], repeatRows=1)
    tbl.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F5F5F5")), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
    story.append(tbl)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Session Details (chronological)", styles["h2"]))
    session_count = 0
    for sess_id, items in sorted(sessions.items()):
        session_count += 1
        story.append(Paragraph(f"Session {html.escape(str(sess_id))} — {len(items)} event(s)", styles["h3"]))
        data = [[_p("Time", styles["h3"], allow_markup=False), _p("Type", styles["h3"], allow_markup=False), _p("Detail", styles["h3"], allow_markup=False), _p("Anomaly", styles["h3"], allow_markup=False)]]

        def _key_item(i):
            t = i.get("timestamp") or i.get("last_access") or ""
            return _parse_time_for_sort(t)

        for it in sorted(items, key=_key_item):
            t = _safe_isoformat(it.get("timestamp") or it.get("last_access") or "")
            atype = it.get("artifact_type") or ""
            detail = it.get("detail") or ""
            anomaly = it.get("anomaly") or ""

            # Truncate detail and anomaly for PDF presentation
            detail_short = _truncate_text(detail, max_chars=500)
            anomaly_short = _truncate_text(anomaly, max_chars=200)

            data.append([
                _p(t, styles["mono"], allow_markup=False),
                _p(atype, styles["normal"], allow_markup=False),
                _p(detail_short, styles["normal"], allow_markup=False),
                _p(anomaly_short, styles["normal"], allow_markup=False),
            ])

        total_w = _content_width(doc)
        col_w = [total_w * 0.16, total_w * 0.12, total_w * 0.56, total_w * 0.16]
        t = Table(data, colWidths=col_w, repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FAFAFA")), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        for i in range(1, len(data)):
            if i % 2 == 0:
                t.setStyle(TableStyle([("BACKGROUND", (0, i), (-1, i), colors.whitesmoke)]))
        story.append(t)
        story.append(Spacer(1, 8))
        if session_count % 4 == 0:
            story.append(PageBreak())

    story.append(Spacer(1, 12))
    story.append(Paragraph("Note: Events grouped into sessions by time gaps (parser logic). Export contains full DB for detailed artifact review.", _get_styles()["italic"]))

    doc.build(story)
    return output_path
