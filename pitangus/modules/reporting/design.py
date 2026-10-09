"""Design system for the PDF reports: one source for all of them (technical, audit, threats).

Rules (the same as the panel's; see .claude/skills/pitangus-design):
- Colors: only the panel tokens (web/src/index.css) in hex; no ad-hoc palettes.
  Text ≥ 4.5:1 against its background; borders and marks that identify something ≥ 3:1.
- Structure: the conclusion first (key figures and what to do), then the detail; the exhaustive part goes to an
  appendix or stays in the JSON/SARIF. Group by action (a package, a rule), not by individual advisory.
- No orphan headings: every section is preceded by a conditional break.
- All text that comes from a repository, a model or a form is data: it gets escaped (t()).
"""

from __future__ import annotations

import html
import io
import re
from collections.abc import Sequence
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A3, A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, NextPageTemplate, PageBreak, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

from pitangus.shared import i18n

# Panel tokens in light mode (web/src/index.css), in hex for the PDF and the SVG.
BRAND_HEX = "#9c4a1e"
BRAND, BRAND_BG = colors.HexColor(BRAND_HEX), colors.HexColor("#fbf5e6")
INK, MUTED, LINE, SOFT = colors.HexColor("#171717"), colors.HexColor("#636363"), colors.HexColor("#e5e5e5"), colors.HexColor("#f5f5f5")
SUCCESS, SUCCESS_BG = colors.HexColor("#006e42"), colors.HexColor("#e9f8ef")
DANGER, DANGER_BG = colors.HexColor("#b71824"), colors.HexColor("#ffefed")
ATTENTION, ATTENTION_BG = colors.HexColor("#a34100"), colors.HexColor("#fff0e4")
SEVERITY = {  # text, background
    "critical": (colors.HexColor("#ffffff"), colors.HexColor("#b71824")),
    "high": (ATTENTION, ATTENTION_BG),
    "medium": (colors.HexColor("#8a4c00"), colors.HexColor("#fef4df")),
    "low": (colors.HexColor("#00649e"), colors.HexColor("#ebf5fd")),
    "info": (MUTED, SOFT),
}
ORDER = {level: index for index, level in enumerate(("critical", "high", "medium", "low", "info"))}

# Type: Source Serif 4 for titles and prose, IBM Plex Sans for labels and tables, IBM Plex Mono for code and identifiers
# (SIL OFL-1.1, embedded in every PDF; see assets/ and docs/third-party-notices.md).
ASSETS = Path(__file__).with_name("assets")
SERIF, SERIF_SEMIBOLD, SERIF_ITALIC = "PSerif", "PSerif-Semibold", "PSerif-Italic"
SANS, SANS_MEDIUM, SANS_SEMIBOLD = "PSans", "PSans-Medium", "PSans-SemiBold"
MONO, MONO_MEDIUM = "PMono", "PMono-Medium"
for name, file in ((SERIF, "SourceSerif4-Regular"), (SERIF_SEMIBOLD, "SourceSerif4-Semibold"), (SERIF_ITALIC, "SourceSerif4-It"),
                   (SANS, "IBMPlexSans-Regular"), (SANS_MEDIUM, "IBMPlexSans-Medium"), (SANS_SEMIBOLD, "IBMPlexSans-SemiBold"),
                   (MONO, "IBMPlexMono-Regular"), (MONO_MEDIUM, "IBMPlexMono-Medium")):
    if name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(name, str(ASSETS / f"{file}.ttf")))
# <b> and <i> inside a paragraph map to the family's own weights (Plex Sans has no italic here: it stays upright).
pdfmetrics.registerFontFamily(SERIF, normal=SERIF, bold=SERIF_SEMIBOLD, italic=SERIF_ITALIC, boldItalic=SERIF_SEMIBOLD)
pdfmetrics.registerFontFamily(SANS, normal=SANS, bold=SANS_SEMIBOLD, italic=SANS, boldItalic=SANS_SEMIBOLD)
pdfmetrics.registerFontFamily(MONO, normal=MONO, bold=MONO_MEDIUM, italic=MONO, boldItalic=MONO_MEDIUM)

# Severity as coloured text (no filled chips): each colour ≥ 4.5:1 on white.
SEVERITY_INK = {"critical": DANGER, "high": ATTENTION, "medium": colors.HexColor("#8a4c00"), "low": colors.HexColor("#00649e"), "info": MUTED}
RULE = INK  # the strong rule above tables and figure rows
BODY_INK, SUBTLE_INK, LABEL_INK = colors.HexColor("#262626"), colors.HexColor("#333333"), colors.HexColor("#4d4d4d")  # greys of INK
CODE_BG = SOFT  # behind code samples

STYLE = {
    "eyebrow": ParagraphStyle("eyebrow", fontName=SANS, fontSize=9, leading=12, textColor=MUTED, spaceAfter=6),
    "title": ParagraphStyle("title", fontName=SERIF_SEMIBOLD, fontSize=24, leading=28, textColor=INK, spaceAfter=6),
    "subtitle": ParagraphStyle("subtitle", fontName=SERIF, fontSize=11, leading=16, textColor=MUTED, spaceAfter=12),
    "cover_kind": ParagraphStyle("cover_kind", fontName=SANS, fontSize=10.5, leading=14, textColor=MUTED, spaceAfter=10),
    "cover_title": ParagraphStyle("cover_title", fontName=SERIF_SEMIBOLD, fontSize=38, leading=42, textColor=INK, spaceAfter=14),
    "cover_subtitle": ParagraphStyle("cover_subtitle", fontName=SERIF, fontSize=14, leading=21, textColor=SUBTLE_INK),
    # No keepWithNext: it would tie the heading to the whole table and push all of it to the next page.
    # Each heading is preceded by a conditional break (CondPageBreak) that prevents orphan headings.
    "h2": ParagraphStyle("h2", fontName=SERIF_SEMIBOLD, fontSize=17, leading=21, textColor=INK, spaceBefore=16, spaceAfter=8),
    "h3": ParagraphStyle("h3", fontName=SANS_SEMIBOLD, fontSize=9.5, leading=13, textColor=INK, spaceBefore=10, spaceAfter=4),
    "body": ParagraphStyle("body", fontName=SERIF, fontSize=10.2, leading=15, textColor=BODY_INK, spaceAfter=5),
    "text": ParagraphStyle("text", fontName=SANS, fontSize=9, leading=13, textColor=INK, spaceAfter=4),
    "note": ParagraphStyle("note", fontName=SANS, fontSize=8, leading=11.5, textColor=MUTED, spaceAfter=4),
    "cell": ParagraphStyle("cell", fontName=SANS, fontSize=8.2, leading=11.2, textColor=INK),
    "cellmuted": ParagraphStyle("cellmuted", fontName=SANS, fontSize=7.8, leading=10.8, textColor=MUTED),
    "head": ParagraphStyle("head", fontName=SANS_MEDIUM, fontSize=7.8, leading=10.5, textColor=MUTED),
    "label": ParagraphStyle("label", fontName=SANS, fontSize=7.8, leading=10, textColor=MUTED),
    "value": ParagraphStyle("value", fontName=SANS_MEDIUM, fontSize=9.5, leading=12.5, textColor=INK),
    "kpi": ParagraphStyle("kpi", fontName=SERIF_SEMIBOLD, fontSize=24, leading=27),
    "kpilabel": ParagraphStyle("kpilabel", fontName=SANS, fontSize=8.2, leading=10.5, textColor=LABEL_INK),
    "mono": ParagraphStyle("mono", fontName=MONO, fontSize=8, leading=11, textColor=INK),
    "id": ParagraphStyle("id", fontName=MONO, fontSize=8.5, leading=11.5, textColor=BRAND),
    "chip": ParagraphStyle("chip", fontName=SANS_SEMIBOLD, fontSize=8, leading=10.5),
    "code": ParagraphStyle("code", fontName=MONO, fontSize=7.8, leading=11, textColor=INK),
    "sheet_title": ParagraphStyle("sheet_title", fontName=SERIF_SEMIBOLD, fontSize=14, leading=18, textColor=INK, spaceBefore=3, spaceAfter=8),
    "h4": ParagraphStyle("h4", fontName=SANS_SEMIBOLD, fontSize=8.8, leading=12, textColor=INK, spaceBefore=9, spaceAfter=2),
}
MARGIN = 18 * mm
WIDTH = A4[0] - 2 * MARGIN


def hexval(color: colors.Color) -> str:
    return color.hexval().replace("0x", "#")


def t(value, limit: int = 400) -> str:
    """Untrusted text → safe ReportLab markup (escaped, one line, bounded)."""
    text = " ".join(str(value or "").split())
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return html.escape(text, quote=False)


def rich(value, limit: int = 400) -> str:
    """Like t(), and `code` written between backticks is shown in a monospaced font instead of the raw marks."""
    return re.sub(r"`([^`<>]+)`", rf'<font name="{MONO}">\1</font>', t(value, limit))


def plain(value, limit: int = 400) -> str:
    """Like t(), without the backticks: a narrow table cell can't fit monospaced code."""
    return t(str(value or "").replace("`", ""), limit)


def path(value, width: int = 30, lines: int = 3) -> str:
    """A file location that fits a narrow column: it breaks after «/» and, when too long, drops the middle of the
    path, never the file name and line (the part that says where to look)."""
    text = " ".join(str(value or "").split())
    if len(text) > width * lines:
        head, _, tail = text.rpartition("/")
        keep = width * lines - len(tail) - 2
        text = (head[:keep] + "…/" if head and keep > 4 else "…/") + tail
    parts, rows = re.split(r"(?<=/)", text), [""]
    for part in parts:
        if rows[-1] and len(rows[-1]) + len(part) > width:
            rows.append("")
        rows[-1] += part
    return "<br/>".join(html.escape(row, quote=False) for row in rows if row)


def built_from(record: dict, locale: str | None = None) -> str:
    """«owner/repo @ 9f3c2a1b7d4e (from the image's label)» for an image: the repository it is built from, the commit
    when known, and who says so — the image's own label is a claim, a manual link names who set it. "" otherwise."""
    source = record.get("source") or {}
    link = source.get("built_from") or (source.get("image") or {}).get("built_from") or {}
    name = link.get("name") or link.get("repository")
    if not name:
        return ""
    where = " @ ".join(value for value in (str(name), str(link.get("revision") or "")[:12]) if value)
    origin = (i18n.t("reports.design.built_from_manual", locale, by=link.get("by") or "—") if link.get("how") == "manual"
              else i18n.t("reports.design.built_from_label", locale))
    return f"{where} ({origin})"


def location(finding: dict) -> str:
    """Where a finding is: a dependency advisory points at its manifest (its line says nothing), code at path:line."""
    if finding.get("scanner") == "sca" or not finding.get("line"):
        return str(finding.get("path") or "—")
    return f"{finding.get('path')}:{finding.get('line')}"


def percent(value: float, locale: str | None = None) -> str:
    """0.975 → «97.5 %», with the locale's decimal separator."""
    text = f"{value * 100:.1f}"
    return (text.replace(".", ",") if i18n.t("reports.design.decimal_separator", locale) == "," else text) + " %"


def day(value) -> str:
    text = str(value or "")
    return text[:10] if re.match(r"\d{4}-\d{2}-\d{2}", text) else "—"


def severity_label(level, locale: str | None = None) -> str:
    return i18n.t(f"reports.common.severity.{level}", locale) if level in SEVERITY else str(level or "—")


def count(key: str, value: int, locale: str | None = None) -> str:
    """«3 findings»: a `reports.count.*` phrase with its plural."""
    return i18n.t(f"reports.count.{key}", locale, count=value)


def n(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def listing(items: list[str], limit: int = 6, *, locale: str | None = None) -> str:
    """«a, b, c and 4 more»: a bounded enumeration that doesn't fill half a page."""
    items = [item for item in items if item]
    if len(items) > limit:
        return i18n.t("reports.design.listing_more", locale, items=", ".join(items[:limit]), count=len(items) - limit)
    if len(items) > 1:
        return i18n.t("reports.design.listing_last", locale, items=", ".join(items[:-1]), last=items[-1])
    return items[0] if items else ""


def grid(rows, widths, *, header=True, zebra=False) -> Table:
    """A ruled table: a strong rule on top, hairlines between rows, no fills (zebra is kept for callers, unused)."""
    table = Table(rows, colWidths=widths, hAlign="LEFT", repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
             ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
             ("LINEABOVE", (0, 0), (-1, 0), 1.2, RULE)]
    if header:
        style += [("LINEBELOW", (0, 0), (-1, 0), 0.6, RULE)]
    table.setStyle(TableStyle(style))
    return table


def table(headers: list[str], rows: list[list], widths: list[float], *, zebra=False) -> Table:
    """Table with a header row: text cells already marked up (str) are wrapped in paragraphs."""
    body = [[cell if not isinstance(cell, str) else Paragraph(cell, STYLE["cell"]) for cell in row] for row in rows]
    return grid([[Paragraph(label, STYLE["head"]) for label in headers], *body], widths)


def chip(severity: str, label: str | None = None, *, locale: str | None = None) -> Paragraph:
    """The severity, as coloured text."""
    ink = SEVERITY_INK.get(severity, MUTED)
    return Paragraph(f'<font color="{hexval(ink)}">{label or severity_label(severity, locale)}</font>', STYLE["chip"])


def kpis(items: Sequence[tuple[str, object, colors.Color, colors.Color]], width: float = WIDTH) -> Table:
    """Key figures in one ruled row: (label, value, value colour, unused fill). Four reads best; six at most."""
    cells = [[Paragraph(f'<font color="{hexval(ink)}">{value}</font>', STYLE["kpi"]), Paragraph(label, STYLE["kpilabel"])]
             for label, value, ink, _ in items]
    result = Table([cells], colWidths=[width / len(items)] * len(items), hAlign="LEFT")
    result.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 8),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 10), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                ("LINEABOVE", (0, 0), (-1, 0), 1.5, RULE), ("LINEBELOW", (0, 0), (-1, 0), 0.4, LINE)]))
    return result


def meta(pairs: list[tuple]) -> Table:
    """Metadata grid (who, what, when), three per row. A third element "mono" shows an identifier whole, in a smaller
    monospaced font: a reference or a hash is evidence and is never cut."""
    rows = []
    for start in range(0, len(pairs), 3):
        chunk = pairs[start:start + 3] + [("", "")] * (3 - len(pairs[start:start + 3]))
        rows += [[Paragraph(t(pair[0]), STYLE["label"]) for pair in chunk],
                 [Paragraph(t(pair[1], 160), STYLE["mono" if pair[2:] == ("mono",) else "value"]) for pair in chunk]]
    table = Table(rows, colWidths=[WIDTH / 3] * 3, hAlign="LEFT")
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 1),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 1), ("LINEABOVE", (0, 0), (-1, 0), 0.6, LINE),
                               *[("BOTTOMPADDING", (0, row), (-1, row), 9) for row in range(1, len(rows), 2)],
                               *[("TOPPADDING", (0, row), (-1, row), 8) for row in range(0, len(rows), 2)]]))
    return table


def header(eyebrow: str, title: str, subtitle: str = "") -> list:
    story = [Paragraph(html.escape(eyebrow), STYLE["eyebrow"]), Paragraph(t(title, 160), STYLE["title"])]
    if subtitle:
        story.append(Paragraph(t(subtitle, 400), STYLE["subtitle"]))
    return story


def cover(kind: str, title: str, subtitle: str, fields: list[tuple], *, note: str = "") -> list:
    """The first page: what this is, about what, for whom and when, and nothing else. `fields` as in meta(); the
    page itself (logo, «Confidential», `note`) is drawn by the cover template."""
    rule = Table([[""]], colWidths=[22 * mm], rowHeights=[1.2 * mm], hAlign="LEFT")
    rule.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), BRAND)]))
    story = [_CoverStart(note), Spacer(1, 62 * mm), Paragraph(t(kind, 120), STYLE["cover_kind"]),
             Paragraph(t(title, 160), STYLE["cover_title"]), rule, Spacer(1, 10)]
    if subtitle:
        story.append(Paragraph(t(subtitle, 400), STYLE["cover_subtitle"]))
    story += [Spacer(1, 48 * mm), meta(fields)]
    return story + [NextPageTemplate("normal"), PageBreak()]


class _CoverStart(Spacer):
    """Marks a story that opens with a cover, and carries the note the cover template prints at its foot."""

    def __init__(self, note: str):
        super().__init__(1, 0)
        self.note = note


def h2(text: str, *, number: bool = True) -> Paragraph:
    """A section heading; build() numbers it (1., 2.…) unless `number` is False (appendices, sign-off)."""
    heading = Paragraph(html.escape(text), STYLE["h2"])
    heading.numbered = number  # type: ignore[attr-defined]
    return heading


def bullets(items: list[str], style: str = "body") -> list:
    """Bullets whose text the caller has already escaped or marked up."""
    return [Paragraph("•&nbsp;&nbsp;" + item, STYLE[style]) for item in items]


def signoff(prepared_by: str = "", *, locale: str | None = None) -> list:
    columns = [i18n.t(f"reports.columns.{name}", locale) for name in ("role", "name", "signature", "date")]
    roles = [(i18n.t("reports.design.prepared_by", locale), prepared_by), (i18n.t("reports.design.reviewed_by", locale), ""),
             (i18n.t("reports.design.approved_by", locale), "")]
    rows = [[Paragraph(html.escape(label), STYLE["head"]) for label in columns]]
    rows += [[Paragraph(html.escape(role), STYLE["cell"]), Paragraph(t(name, 60), STYLE["cell"]), Paragraph("", STYLE["cell"]),
              Paragraph("", STYLE["cell"])] for role, name in roles]
    table = grid(rows, [32 * mm, 50 * mm, WIDTH - 112 * mm, 30 * mm])
    table.setStyle(TableStyle([("TOPPADDING", (0, 1), (-1, -1), 12), ("BOTTOMPADDING", (0, 1), (-1, -1), 12)]))
    return [Spacer(1, 8), h2(i18n.t("reports.design.signoff", locale), number=False), table]


def wide_page(flowables: list, *, size=None) -> list:
    """A landscape page (e.g. the diagram) in the middle of the report; afterwards it goes back to portrait A4."""
    return [NextPageTemplate("wide-a3" if size == "a3" else "wide"), PageBreak(), *flowables, NextPageTemplate("normal"), PageBreak()]


def _guard_headings(story: list) -> list:
    # A heading never sits alone at the bottom: if a few rows don't fit below it, it moves to the next page.
    # Section headings get their number here, in reading order.
    room = {"h2": 32 * mm, "h3": 22 * mm, "h4": 20 * mm}
    result, number = [], 0
    for flowable in story:
        if isinstance(flowable, Paragraph) and flowable.style.name in room:
            if flowable.style.name == "h2" and getattr(flowable, "numbered", False):
                number += 1
                flowable = Paragraph(f"{number}.&nbsp;&nbsp;{flowable.text}", flowable.style)
            result += [CondPageBreak(room[flowable.style.name]), flowable]
        else:
            result.append(flowable)
    return result


def build(story: list, *, title: str, footer: str, version: str, author: str = "Pitangus", subject: str = "",
          locale: str | None = None, reference: str = "") -> bytes:
    """A4 PDF: a cover when the story starts with cover(), a running header (`footer`: what the document is about, and
    «Confidential»), a footer with the version, the reference and «page N of M», and landscape pages when requested."""
    output = io.BytesIO()
    confidential = i18n.t("reports.design.confidential", locale)
    note = story[0].note if story and isinstance(story[0], _CoverStart) else ""
    left_foot = " · ".join(value for value in (f"Pitangus {version}", reference[:60]) if value)

    def running(canvas, document):
        canvas._is_cover = False
        canvas.saveState()
        width, height = canvas._pagesize
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, height - 11 * mm, width - MARGIN, height - 11 * mm)
        canvas.line(MARGIN, 13 * mm, width - MARGIN, 13 * mm)
        canvas.setFont(SANS, 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN, height - 9 * mm, footer[:110])
        canvas.drawString(MARGIN, 8.5 * mm, left_foot)
        canvas.setFont(SANS_MEDIUM, 7.5)
        canvas.setFillColor(BRAND)
        canvas.drawRightString(width - MARGIN, height - 9 * mm, confidential)
        canvas.restoreState()

    def front(canvas, document):
        canvas.saveState()
        width, height = canvas._pagesize
        top = height - 22 * mm
        logo = ASSETS / "logo.png"
        canvas.drawImage(str(logo), MARGIN, top - 4 * mm, width=11 * mm, height=11 * mm, mask="auto")
        canvas.setFont(SANS_SEMIBOLD, 12)
        canvas.setFillColor(INK)
        canvas.drawString(MARGIN + 14 * mm, top, "Pitangus")
        canvas.setFont(SANS_MEDIUM, 8.5)
        canvas.setFillColor(BRAND)
        canvas.drawRightString(width - MARGIN, top, confidential)
        canvas.setFont(SANS, 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN, 14 * mm, note[:140])
        canvas.drawRightString(width - MARGIN, 14 * mm, "Arodium")
        canvas.restoreState()

    class Numbered(Canvas):
        """Draws «page N of M» once the total is known (the pages are kept until the document is saved)."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages: list[dict] = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            for number, state in enumerate(self._pages, 1):
                self.__dict__.update(state)
                if not getattr(self, "_is_cover", False):
                    self.setFont(SANS, 7.5)
                    self.setFillColor(MUTED)
                    self.drawRightString(self._pagesize[0] - MARGIN, 8.5 * mm,
                                         i18n.t("reports.design.page_footer", locale, page=number, total=len(self._pages)))
                super().showPage()
            super().save()

    def template(name: str, size) -> PageTemplate:
        body = Frame(MARGIN, 18 * mm, size[0] - 2 * MARGIN, size[1] - 34 * mm, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        return PageTemplate(id=name, frames=[body], onPage=running, pagesize=size)

    def cover_page(canvas, document):
        canvas._is_cover = True
        front(canvas, document)

    cover_template = PageTemplate(id="cover", frames=[Frame(MARGIN, 24 * mm, A4[0] - 2 * MARGIN, A4[1] - 50 * mm, leftPadding=0,
                                                            rightPadding=0, topPadding=0, bottomPadding=0)],
                                  onPage=cover_page, pagesize=A4)
    document = BaseDocTemplate(output, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=16 * mm, bottomMargin=18 * mm,
                               title=title[:120], author=author[:80] or "Pitangus", subject=subject[:120], creator=f"Pitangus {version}")
    templates = [template("normal", A4), template("wide", landscape(A4)), template("wide-a3", landscape(A3)), cover_template]
    starts_with_cover = bool(story) and isinstance(story[0], _CoverStart)
    document.addPageTemplates([templates[3], *templates[:3]] if starts_with_cover else templates)
    document.build(_guard_headings(story[1:] if starts_with_cover else story), canvasmaker=Numbered)
    return output.getvalue()


def wide_size(name: str | None) -> tuple[float, float]:
    """Usable area of a landscape page (to scale a drawing before placing it)."""
    width, height = landscape(A3 if name == "a3" else A4)
    return width - 2 * MARGIN, height - 34 * mm


STEP_STATES = ("completed", "partial", "not_tested", "inconclusive", "failed", "pending", "skipped")
GAP_STATES = ("partial", "not_tested", "inconclusive", "failed")


def step_status(status, locale: str | None = None) -> str:
    return i18n.t(f"reports.common.step_status.{status}", locale) if status in STEP_STATES else str(status or "—")


def coverage_gaps(steps: list[dict], *, locale: str | None = None) -> list[str]:
    """Engines that didn't fully finish, with their state: what wasn't analyzed doesn't mean «no findings»."""
    return [f"{i18n.text(step.get('name'), locale)} ({step_status(step.get('status'), locale)})" for step in steps
            if step.get("status") in GAP_STATES and (step.get("tool") or step.get("status") != "partial" or step.get("detail"))]


def disclaimer(locale: str | None = None) -> str:
    return i18n.t("reports.design.disclaimer", locale)


def __getattr__(name: str):
    # DISCLAIMER stays importable for reports that don't pass a locale yet.
    if name == "DISCLAIMER":
        return disclaimer()
    raise AttributeError(name)
