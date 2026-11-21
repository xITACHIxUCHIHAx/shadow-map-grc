from datetime import datetime, timezone
from grc.datetime_utils import format_datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


NAVY = colors.HexColor("#10243A")
TEAL = colors.HexColor("#087F8C")
PALE_TEAL = colors.HexColor("#DFF3F7")
LIGHT_GREY = colors.HexColor("#E8EEF3")
TEXT = colors.HexColor("#243B50")
MUTED = colors.HexColor("#5B6B7C")
WHITE = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#9F2638"),
    "high": colors.HexColor("#C45135"),
    "medium": colors.HexColor("#B7791F"),
    "low": colors.HexColor("#287A58"),
    "info": colors.HexColor("#47718F"),
}


def _safe(value):
    """Convert arbitrary stored values into safe ReportLab paragraph text."""
    if value is None or str(value).strip() == "":
        return "—"
    return escape(str(value)).replace("\n", "<br/>")


def _paragraph(value, style):
    return Paragraph(_safe(value), style)


def _severity(value):
    label = str(value or "Unknown").strip()
    color = SEVERITY_COLORS.get(label.casefold(), MUTED)
    cell = Paragraph(
        f'<font color="{WHITE.hexval()}"><b>{escape(label)}</b></font>',
        ParagraphStyle(
            "SeverityLabel",
            fontName="Helvetica",
            fontSize=8,
            leading=10,
        ),
    )
    table = Table([[cell]], colWidths=[25 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("BOX", (0, 0), (-1, -1), 0, color),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return table


def _make_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ShadowTitle", parent=base["Title"],
            fontName="Helvetica-Bold", fontSize=21,
            leading=25, textColor=NAVY, alignment=0,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "ShadowSubtitle", parent=base["Normal"],
            fontSize=9, leading=13, textColor=MUTED,
            spaceAfter=12,
        ),
        "section": ParagraphStyle(
            "ShadowSection", parent=base["Heading2"],
            fontName="Helvetica-Bold", fontSize=13,
            leading=17, textColor=TEAL,
            spaceBefore=12, spaceAfter=7,
            keepWithNext=True,
        ),
        "heading": ParagraphStyle(
            "ShadowHeading", parent=base["Heading3"],
            fontName="Helvetica-Bold", fontSize=9,
            leading=12, textColor=NAVY,
            spaceBefore=5, spaceAfter=3,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "ShadowBody", parent=base["BodyText"],
            fontSize=8.5, leading=12, textColor=TEXT,
            spaceAfter=4,
            wordWrap="CJK",
        ),
        "small": ParagraphStyle(
            "ShadowSmall", parent=base["BodyText"],
            fontSize=7.5, leading=10, textColor=MUTED,
            spaceAfter=3,
            wordWrap="CJK",
        ),
        "table_header": ParagraphStyle(
            "ShadowTableHeader", parent=base["Normal"],
            fontName="Helvetica-Bold", fontSize=7.5,
            leading=9, textColor=WHITE,
        ),
        "table_cell": ParagraphStyle(
            "ShadowTableCell", parent=base["Normal"],
            fontSize=7.5, leading=10, textColor=TEXT,
            wordWrap="CJK",
        ),
    }


def _page_chrome(canvas, document):
    canvas.saveState()
    width, height = A4

    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 15 * mm, width, 15 * mm, fill=1, stroke=0)

    logo_path = (
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "static" / "images" / "shadow-map-grc-mark.png"
    )
    if logo_path.is_file():
        canvas.drawImage(
            str(logo_path),
            17 * mm,
            height - 13 * mm,
            width=10 * mm,
            height=10 * mm,
            preserveAspectRatio=True,
            mask="auto",
        )

    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(30 * mm, height - 9.5 * mm, "SHADOW MAP GRC")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(
        width - 18 * mm, height - 9.5 * mm, "GRC SECURITY REPORT"
    )

    canvas.setStrokeColor(LIGHT_GREY)
    canvas.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)

    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(
        18 * mm, 9 * mm,
        f"Generated {format_datetime(datetime.now(timezone.utc))}"
    )
    canvas.drawRightString(
        width - 18 * mm, 9 * mm, f"Page {document.page}"
    )
    canvas.restoreState()


def _detail_block(title, fields, styles):
    content = [
        Paragraph(_safe(title), styles["heading"]),
    ]
    for label, value in fields:
        content.append(Paragraph(
            f"<b>{_safe(label)}:</b> {_safe(value)}",
            styles["body"],
        ))
    return KeepTogether(content)


def build_grc_pdf(
    *,
    title="GRC Security Assessment Report",
    subtitle="Security findings and risk assessment",
    targets=None,
    findings=None,
    risks=None,
    summary=None,
    scope_note=None,
):
    """Build a branded A4 PDF and return its bytes."""
    targets = targets or []
    findings = findings or []
    risks = risks or []
    summary = summary or {}

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=23 * mm,
        bottomMargin=20 * mm,
        title=title,
        author="Shadow Map GRC",
        subject="Security assessment and GRC report",
    )

    styles = _make_styles()
    story = [
        Paragraph(_safe(title), styles["title"]),
        Paragraph(_safe(subtitle), styles["subtitle"]),
    ]

    if scope_note:
        story.append(Paragraph(
            f"<b>Report scope:</b> {_safe(scope_note)}",
            styles["body"],
        ))

    story.append(Paragraph("Executive Summary", styles["section"]))

    summary_rows = [
        [
            Paragraph("<b>Targets</b>", styles["table_cell"]),
            Paragraph("<b>Findings</b>", styles["table_cell"]),
            Paragraph("<b>Risks</b>", styles["table_cell"]),
        ],
        [
            str(summary.get("targets", len(targets))),
            str(summary.get("findings", len(findings))),
            str(summary.get("risks", len(risks))),
        ],
    ]
    summary_table = Table(
        summary_rows,
        colWidths=[55 * mm, 55 * mm, 55 * mm],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PALE_TEAL),
        ("TEXTCOLOR", (0, 0), (-1, -1), NAVY),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F7FAFC")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 1), (-1, 1), 15),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_GREY),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, LIGHT_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([summary_table, Spacer(1, 5 * mm)])

    if targets:
        story.append(Paragraph("Assessment Scope", styles["section"]))
        story.append(Paragraph(
            ", ".join(_safe(target) for target in targets),
            styles["body"],
        ))

    if findings:
        story.append(Paragraph("Security Findings", styles["section"]))
        for finding in findings:
            story.append(_detail_block(
                finding.get("title", "Untitled finding"),
                [
                    ("Target", finding.get("target")),
                    ("Source", finding.get("source")),
                    ("Severity", finding.get("suggested_severity")),
                    ("Status", finding.get("status")),
                    ("Description", finding.get("description")),
                    ("Evidence", finding.get("evidence")),
                    ("Recommendation", finding.get("recommendation")),
                    ("ISO controls", finding.get("iso_controls")),
                    ("ISO review decisions", finding.get("iso_review_summary")),
                    ("Linked risk", finding.get("linked_risk_title")),
                ],
                styles,
            ))
            story.append(Spacer(1, 2 * mm))

    if risks:
        story.append(Paragraph("Risk Register", styles["section"]))
        for risk in risks:
            story.append(_detail_block(
                risk.get("title", "Untitled risk"),
                [
                    ("Asset", risk.get("asset")),
                    ("Category", risk.get("category")),
                    ("Inherent risk", risk.get("inherent_level")),
                    ("Inherent score", risk.get("inherent_score")),
                    ("Residual risk", risk.get("residual_level")),
                    ("Residual score", risk.get("residual_score")),
                    ("Owner", risk.get("owner")),
                    ("Status", risk.get("status")),
                    ("Due date", risk.get("due_date")),
                    ("Business impact", risk.get("business_impact")),
                    ("Evidence", risk.get("evidence")),
                    ("Treatment", risk.get("treatment")),
                    ("ISO controls", risk.get("iso_controls")),
                    ("ISO review decisions", risk.get("iso_review_summary")),
                    ("Review flags", ", ".join(risk.get("review_flags", []))),
                ],
                styles,
            ))
            story.append(Spacer(1, 2 * mm))

    if not findings and not risks:
        story.append(Paragraph(
            "No findings or risks matched the selected report scope.",
            styles["body"],
        ))

    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(
        "This report is generated from records stored in Shadow Map GRC. "
        "ISO control references indicate traceability mappings and do not "
        "represent certification or an independent compliance audit.",
        styles["small"],
    ))

    document.build(
        story,
        onFirstPage=_page_chrome,
        onLaterPages=_page_chrome,
    )

    return buffer.getvalue()


def build_nmap_pdf(*, scan, ports=None, findings=None, counts=None):
    """Build a branded PDF for one saved Nmap scan."""
    ports = ports or []
    findings = findings or []
    counts = counts or {}
    styles = _make_styles()

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=23 * mm,
        bottomMargin=20 * mm,
        title=f"Nmap Assessment - {scan['target']}",
        author="Shadow Map GRC",
        subject="Nmap network assessment",
    )

    story = [
        Paragraph("Nmap Security Assessment", styles["title"]),
        Paragraph(
            f"Saved scan #{scan['id']} · {_safe(scan['target'])}",
            styles["subtitle"],
        ),
        Paragraph("Scan Overview", styles["section"]),
        _detail_block("Scan Details", [
            ("Scan ID", scan["id"]),
            ("Target", scan["target"]),
            ("Status", scan["status"]),
            ("Host state", scan["host_state"]),
            ("Started (IST)", format_datetime(scan["started_at"])),
            ("Finished (IST)", format_datetime(scan["finished_at"])),
            ("Duration (seconds)", scan["duration_seconds"]),
            ("Nmap command", scan["command_display"]),
            ("MAC address", scan["mac_address"]),
            ("MAC vendor", scan["mac_vendor"]),
            ("OS match", scan["os_match"]),
            ("OS accuracy", scan["os_accuracy"]),
            ("OS detection status", scan["os_detection_status"]),
            ("Scan warning / error", scan["error"]),
        ], styles),
        Paragraph("Port State Summary", styles["section"]),
    ]

    summary_rows = [[
        Paragraph("<b>Open</b>", styles["table_cell"]),
        Paragraph("<b>Closed</b>", styles["table_cell"]),
        Paragraph("<b>Filtered</b>", styles["table_cell"]),
        Paragraph("<b>Other</b>", styles["table_cell"]),
    ], [
        str(counts.get("open", 0)),
        str(counts.get("closed", 0)),
        str(counts.get("filtered", 0)),
        str(counts.get("other", 0)),
    ]]
    summary_table = Table(
        summary_rows,
        colWidths=[43.5 * mm] * 4,
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PALE_TEAL),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F7FAFC")),
        ("TEXTCOLOR", (0, 0), (-1, -1), NAVY),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 13),
        ("BOX", (0, 0), (-1, -1), 0.5, LIGHT_GREY),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, LIGHT_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([summary_table, Spacer(1, 3 * mm)])

    story.append(Paragraph("Port Details", styles["section"]))
    if ports:
        headers = ["Port", "Protocol", "State", "Service", "Product / Version", "Reason"]
        rows = [[
            Paragraph(f"<b>{_safe(item)}</b>", styles["table_header"])
            for item in headers
        ]]
        for port in ports:
            product_version = " ".join(
                str(port[key]).strip()
                for key in ("product", "version", "extra_info")
                if port[key] and str(port[key]).strip()
            )
            values = [
                port["port"],
                port["protocol"],
                port["state"],
                port["service"],
                product_version,
                port["reason"],
            ]
            rows.append([
                Paragraph(_safe(value), styles["table_cell"])
                for value in values
            ])

        port_table = Table(
            rows,
            colWidths=[
                13 * mm, 16 * mm, 19 * mm,
                27 * mm, 61 * mm, 34 * mm,
            ],
            repeatRows=1,
            splitByRow=1,
        )
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                WHITE, colors.HexColor("#F4F8FA")
            ]),
            ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(port_table)
    else:
        story.append(Paragraph(
            "No individual port entries were returned. "
            "This does not prove that the target has no open ports.",
            styles["body"],
        ))

    if findings:
        story.append(Paragraph("Linked Security Findings", styles["section"]))
        for finding in findings:
            story.append(_detail_block(
                finding["title"] or "Untitled finding",
                [
                    ("Severity", finding["suggested_severity"]),
                    ("Status", finding["status"]),
                    ("Description", finding["description"]),
                    ("Evidence", finding["evidence"]),
                    ("Recommendation", finding["recommendation"]),
                    ("ISO controls", finding["iso_controls"]),
                ],
                styles,
            ))
            story.append(Spacer(1, 2 * mm))
    else:
        story.append(Paragraph(
            "No linked security findings are currently recorded for this scan.",
            styles["body"],
        ))

    story.extend([
        Spacer(1, 4 * mm),
        Paragraph(
            "An open port indicates an exposed network service, not "
            "automatically a vulnerability. Filtered states are inconclusive. "
            "Service and operating-system identification may be incomplete "
            "or inaccurate. Assess only systems for which you have "
            "authorization.",
            styles["small"],
        ),
    ])

    document.build(
        story,
        onFirstPage=_page_chrome,
        onLaterPages=_page_chrome,
    )
    return buffer.getvalue()


def build_web_security_pdf(*, scan, result):
    """Build a branded PDF from a saved Web Security assessment."""
    from reportlab.platypus import PageBreak

    styles = _make_styles()
    story = [
        Paragraph("WEB SECURITY ASSESSMENT", styles["title"]),
        Paragraph(
            f"Target: {_safe(scan['target'])}",
            styles["subtitle"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Executive Summary", styles["section"]),
    ]

    headers = result.get("headers") or []
    cookies = result.get("cookies") or []
    discovery = result.get("discovery") or {}
    pages = discovery.get("pages") or []
    forms = discovery.get("forms") or []
    discovered_urls = discovery.get("discovered_urls") or []
    api_endpoints = discovery.get("api_endpoints") or []

    present = sum(1 for item in headers if item.get("present"))
    missing = sum(1 for item in headers if not item.get("present"))

    summary = [
        ["Assessment", _safe(scan["status"])],
        ["HTTP response", _safe(result.get("status_code"))],
        ["Security headers present", f"{present} of {len(headers)}"],
        ["Security headers missing", str(missing)],
        ["Cookies observed", str(len(cookies))],
        ["Pages discovered", str(len(pages))],
        ["Additional URLs discovered", str(len(discovered_urls))],
        ["Forms observed (not submitted)", str(len(forms))],
        ["Likely API endpoints identified", str(len(api_endpoints))],
    ]
    table = Table(summary, colWidths=[65 * mm, 105 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PALE_TEAL),
        ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([table, Spacer(1, 5 * mm)])

    story.append(Paragraph("Assessment Details", styles["section"]))
    story.append(_detail_block("Saved Scan", [
        ("Scan ID", scan["id"]),
        ("Target", scan["target"]),
        ("Status", scan["status"]),
        ("Started (IST)", format_datetime(scan["started_at"])),
        ("Finished (IST)", format_datetime(scan["finished_at"])),
        ("Duration", f"{scan['duration_seconds']:.2f} seconds"
         if scan["duration_seconds"] is not None else "—"),
        ("Error", scan["error"]),
    ], styles))

    if headers:
        story.append(Paragraph("Security Header Observations", styles["section"]))
        data = [[
            Paragraph("Header", styles["table_header"]),
            Paragraph("Observed", styles["table_header"]),
            Paragraph("Assessment", styles["table_header"]),
            Paragraph("Value", styles["table_header"]),
            Paragraph("Purpose", styles["table_header"]),
        ]]
        for item in headers:
            data.append([
                Paragraph(_safe(item.get("name")), styles["table_cell"]),
                Paragraph("Present" if item.get("present") else "Missing",
                          styles["table_cell"]),
                Paragraph(_safe(item.get("assessment")), styles["table_cell"]),
                Paragraph(_safe(item.get("value")), styles["table_cell"]),
                Paragraph(_safe(item.get("purpose")), styles["table_cell"]),
            ])
        table = Table(
            data,
            colWidths=[31 * mm, 19 * mm, 23 * mm, 42 * mm, 55 * mm],
            repeatRows=1,
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
            ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([table, Spacer(1, 5 * mm)])

    story.append(Paragraph("Cookie Attribute Observations", styles["section"]))
    if cookies:
        data = [[
            Paragraph("Cookie", styles["table_header"]),
            Paragraph("Secure", styles["table_header"]),
            Paragraph("HttpOnly", styles["table_header"]),
            Paragraph("SameSite", styles["table_header"]),
        ]]
        for cookie in cookies:
            data.append([
                Paragraph(_safe(cookie.get("number")), styles["table_cell"]),
                Paragraph("Yes" if cookie.get("secure") else "Not observed",
                          styles["table_cell"]),
                Paragraph("Yes" if cookie.get("httponly") else "Not observed",
                          styles["table_cell"]),
                Paragraph("Yes" if cookie.get("samesite") else "Not observed",
                          styles["table_cell"]),
            ])
        table = Table(data, colWidths=[45 * mm, 40 * mm, 40 * mm, 45 * mm],
                      repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
            ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
    else:
        story.append(Paragraph(
            "No Set-Cookie headers were observed in the saved response.",
            styles["body"],
        ))

    # Vulnerability assessment coverage (available in newer saved scans).
    reflected_assessment = result.get("reflected_input_assessment") or {}
    sql_assessment = result.get("sql_injection_assessment") or {}
    assessment_plan = result.get("assessment_plan") or {}
    boolean_checks = assessment_plan.get("sql_boolean_based_checks") or []

    has_assessment_data = any(
        key in result
        for key in (
            "reflected_input_assessment",
            "sql_injection_assessment",
            "assessment_plan",
        )
    )

    if has_assessment_data:
        story.append(Paragraph(
            "Vulnerability Assessment Coverage", styles["section"]
        ))

        assessment_rows = [[
            Paragraph("Assessment", styles["table_header"]),
            Paragraph("Parameter", styles["table_header"]),
            Paragraph("Status", styles["table_header"]),
            Paragraph("Confidence", styles["table_header"]),
            Paragraph("Verification", styles["table_header"]),
        ]]

        for label, assessment in (
            ("Reflected-input check", reflected_assessment),
            ("Error-based SQL injection", sql_assessment),
        ):
            checks = assessment.get("checks") or []
            if checks:
                for check in checks:
                    assessment_rows.append([
                        Paragraph(_safe(label), styles["table_cell"]),
                        Paragraph(_safe(check.get("parameter") or "—"),
                                  styles["table_cell"]),
                        Paragraph(_safe(
                            (check.get("status") or assessment.get("status")
                             or "not recorded").replace("_", " ").title()
                        ), styles["table_cell"]),
                        Paragraph(_safe(check.get("confidence") or "—"),
                                  styles["table_cell"]),
                        Paragraph(
                            "Not verified" if check.get("verified") is False
                            else "Not recorded",
                            styles["table_cell"],
                        ),
                    ])
            elif assessment:
                assessment_rows.append([
                    Paragraph(_safe(label), styles["table_cell"]),
                    Paragraph("—", styles["table_cell"]),
                    Paragraph(_safe(
                        (assessment.get("status") or "not recorded")
                        .replace("_", " ").title()
                    ), styles["table_cell"]),
                    Paragraph("—", styles["table_cell"]),
                    Paragraph("Not verified", styles["table_cell"]),
                ])

        for check in boolean_checks:
            assessment_rows.append([
                Paragraph("Boolean-based SQL injection", styles["table_cell"]),
                Paragraph(_safe(check.get("parameter") or "—"),
                          styles["table_cell"]),
                Paragraph("Planned — Not Tested", styles["table_cell"]),
                Paragraph("—", styles["table_cell"]),
                Paragraph("Not verified", styles["table_cell"]),
            ])

        if len(assessment_rows) == 1:
            assessment_rows.append([
                Paragraph("Assessment coverage", styles["table_cell"]),
                Paragraph("—", styles["table_cell"]),
                Paragraph("No checks recorded", styles["table_cell"]),
                Paragraph("—", styles["table_cell"]),
                Paragraph("Not verified", styles["table_cell"]),
            ])

        assessment_table = Table(
            assessment_rows,
            colWidths=[39 * mm, 39 * mm, 34 * mm, 25 * mm, 33 * mm],
            repeatRows=1,
        )
        assessment_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
            ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([
            assessment_table,
            Spacer(1, 3 * mm),
            Paragraph(
                "Suspected indicators are unverified evidence, not confirmed "
                "vulnerabilities. Boolean-based SQL injection candidates are "
                "planned for review only; no Boolean test requests were sent.",
                styles["small"],
            ),
        ])

    if pages or discovered_urls or forms or api_endpoints:
        story.append(Paragraph("Page Discovery", styles["section"]))
        if pages:
            story.append(Paragraph("Visited Pages", styles["heading"]))
            data = [[
                Paragraph("URL", styles["table_header"]),
                Paragraph("HTTP", styles["table_header"]),
                Paragraph("Content Type", styles["table_header"]),
                Paragraph("Truncated", styles["table_header"]),
            ]]
            for page in pages:
                data.append([
                    Paragraph(_safe(page.get("url")), styles["table_cell"]),
                    Paragraph(_safe(page.get("status_code")), styles["table_cell"]),
                    Paragraph(_safe(page.get("content_type")), styles["table_cell"]),
                    Paragraph("Yes" if page.get("truncated") else "No",
                              styles["table_cell"]),
                ])
            table = Table(data, colWidths=[95 * mm, 18 * mm, 42 * mm, 15 * mm],
                          repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(table)

        if discovered_urls:
            story.append(Paragraph("Discovered URLs", styles["heading"]))
            for url in discovered_urls:
                story.append(Paragraph(f"• {_safe(url)}", styles["small"]))

        if forms:
            story.append(Paragraph("Forms Observed (Not Submitted)", styles["heading"]))
            data = [[
                Paragraph("Page", styles["table_header"]),
                Paragraph("Method", styles["table_header"]),
                Paragraph("Action", styles["table_header"]),
                Paragraph("Encoding", styles["table_header"]),
            ]]
            for form in forms:
                data.append([
                    Paragraph(_safe(form.get("page")), styles["table_cell"]),
                    Paragraph(_safe(form.get("method")), styles["table_cell"]),
                    Paragraph(_safe(form.get("action")), styles["table_cell"]),
                    Paragraph(_safe(form.get("enctype") or "—"), styles["table_cell"]),
                ])
            table = Table(
                data,
                colWidths=[58 * mm, 20 * mm, 65 * mm, 27 * mm],
                repeatRows=1,
            )
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(table)

            for index, form in enumerate(forms, 1):
                fields = form.get("fields") or []
                story.append(Paragraph(
                    f"Form {index} Fields ({len(fields)})",
                    styles["heading"],
                ))
                if fields:
                    field_data = [[
                        Paragraph("Name", styles["table_header"]),
                        Paragraph("Element / Type", styles["table_header"]),
                        Paragraph("Required", styles["table_header"]),
                        Paragraph("Autocomplete", styles["table_header"]),
                        Paragraph("Options", styles["table_header"]),
                    ]]
                    for field in fields:
                        field_data.append([
                            Paragraph(_safe(field.get("name") or "(unnamed)"),
                                      styles["table_cell"]),
                            Paragraph(
                                _safe(field.get("element") or "—")
                                + " / " + _safe(field.get("type") or "—"),
                                styles["table_cell"],
                            ),
                            Paragraph(
                                "Yes" if field.get("required") else "No",
                                styles["table_cell"],
                            ),
                            Paragraph(_safe(field.get("autocomplete") or "—"),
                                      styles["table_cell"]),
                            Paragraph(
                                _safe(", ".join(map(str, field.get("options") or []))
                                      or "—"),
                                styles["table_cell"],
                            ),
                        ])
                    field_table = Table(
                        field_data,
                        colWidths=[38 * mm, 35 * mm, 20 * mm, 35 * mm, 42 * mm],
                        repeatRows=1,
                    )
                    field_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                        ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ]))
                    story.append(field_table)
                else:
                    story.append(Paragraph(
                        "No form fields were recorded.",
                        styles["small"],
                    ))

        if api_endpoints:
            story.append(Paragraph(
                "Likely API Endpoints (Static JavaScript Analysis)",
                styles["heading"],
            ))
            for endpoint in api_endpoints:
                story.append(Paragraph(f"• {_safe(endpoint)}", styles["small"]))
        elif discovery:
            story.append(Paragraph(
                "Likely API Endpoints",
                styles["heading"],
            ))
            story.append(Paragraph(
                "No likely API endpoints were identified.",
                styles["small"],
            ))

        limits = discovery.get("limits") or {}
        if limits:
            story.append(Paragraph("Discovery Limits", styles["heading"]))
            story.append(_detail_block("Collection Limits", [
                ("Maximum pages", limits.get("max_pages")),
                ("Maximum requests", limits.get("max_requests")),
                ("Maximum URLs", limits.get("max_urls")),
                ("URLs queued", limits.get("urls_queued")),
                ("Requests used", limits.get("requests_used")),
                ("Truncated pages", limits.get("truncated_pages")),
                ("Page limit reached", limits.get("page_limit_reached")),
                ("Request limit reached", limits.get("request_limit_reached")),
            ], styles))

    notes = list(result.get("notes") or [])
    notes.extend(discovery.get("notes") or [])
    notes.extend(discovery.get("errors") or [])
    if result.get("discovery_error"):
        notes.append(result["discovery_error"])

    if notes:
        story.append(Paragraph("Notes and Limitations", styles["section"]))
        for note in notes:
            story.append(Paragraph(f"• {_safe(note)}", styles["small"]))
            story.append(Spacer(1, 2))

    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "<b>Interpretation:</b> Missing headers and cookie attributes are "
        "configuration observations, not proof of exploitable vulnerabilities. "
        "Assess each observation against the application's architecture and "
        "security requirements. This assessment uses read-only requests; "
        "observed forms were not submitted.",
        styles["body"],
    ))

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=25 * mm,
        bottomMargin=18 * mm,
        title=f"Shadow Map GRC Web Security Assessment - {scan['id']}",
        author="Shadow Map GRC",
    )
    doc.build(
        story,
        onFirstPage=_page_chrome,
        onLaterPages=_page_chrome,
    )
    return buffer.getvalue()


def build_threat_intel_pdf(*, scan, result):
    """Build a branded PDF from a saved Threat Intelligence lookup."""
    styles = _make_styles()
    ports = result.get("ports") or []
    hostnames = result.get("hostnames") or []
    tags = result.get("tags") or []
    vulns = result.get("vulns") or []
    found = bool(result.get("found"))

    story = [
        Paragraph("THREAT INTELLIGENCE REPORT", styles["title"]),
        Paragraph(f"Public IP: {_safe(scan['target'])}", styles["subtitle"]),
        Spacer(1, 5 * mm),
        Paragraph("Executive Summary", styles["section"]),
    ]

    summary = [
        ["Lookup status", _safe(scan["status"])],
        ["InternetDB record", "Data returned" if found else "No record found"],
        ["Reported ports", str(len(ports))],
        ["Hostnames", str(len(hostnames))],
        ["Tags", str(len(tags))],
        ["Vulnerability identifiers", str(len(vulns))],
    ]
    table = Table(summary, colWidths=[65 * mm, 105 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PALE_TEAL),
        ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([table, Spacer(1, 5 * mm)])

    story.append(Paragraph("Lookup Details", styles["section"]))
    story.append(_detail_block("Saved Lookup", [
        ("Lookup ID", scan["id"]),
        ("Target", scan["target"]),
        ("Status", scan["status"]),
        ("Started (IST)", format_datetime(scan["started_at"])),
        ("Finished (IST)", format_datetime(scan["finished_at"])),
        ("Duration", f"{scan['duration_seconds']:.2f} seconds"
         if scan["duration_seconds"] is not None else "—"),
        ("Error", scan["error"]),
        ("InternetDB IP", result.get("ip")),
        ("Record found", "Yes" if found else "No"),
    ], styles))

    sections = [
        ("Reported Ports", ports),
        ("Hostnames", hostnames),
        ("Tags", tags),
        ("Reported Vulnerability Identifiers", vulns),
    ]

    for heading, values in sections:
        story.append(Paragraph(heading, styles["section"]))
        if values:
            data = [[Paragraph(heading, styles["table_header"])]]
            for value in values:
                data.append([
                    Paragraph(_safe(value), styles["table_cell"])
                ])
            table = Table(data, colWidths=[170 * mm], repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
                ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.extend([table, Spacer(1, 3 * mm)])
        else:
            story.append(Paragraph(
                "No items were reported in this category.",
                styles["body"],
            ))

    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "<b>Interpretation and limitations:</b> InternetDB is an external "
        "intelligence source. Its data may be incomplete or stale. Reported "
        "ports, tags, hostnames, and vulnerability identifiers are observations "
        "and do not establish that a service is currently exposed or that a "
        "vulnerability is exploitable. Verify relevant information against "
        "authoritative advisories and the asset's actual software and version. "
        "This lookup does not create GRC findings or risks.",
        styles["body"],
    ))

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=25 * mm,
        bottomMargin=18 * mm,
        title=f"Shadow Map GRC Threat Intelligence - {scan['id']}",
        author="Shadow Map GRC",
    )
    doc.build(
        story,
        onFirstPage=_page_chrome,
        onLaterPages=_page_chrome,
    )
    return buffer.getvalue()


def _unified_technical_section(module, result, styles):
    """Return bounded, sanitized technical details for the Unified PDF."""
    if not isinstance(result, dict):
        return []

    story = []

    def add_block(title, fields):
        if fields:
            story.append(_detail_block(title, fields, styles))

    def list_of_dicts(value):
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    def list_of_strings(value, limit=20):
        if not isinstance(value, list):
            return []
        return [
            str(item)[:180]
            for item in value[:limit]
            if isinstance(item, (str, int, float))
        ]

    if module == "nmap":
        scan = result.get("scan")
        if isinstance(scan, dict):
            add_block("Nmap Host Details", [
                ("Host state", scan.get("host_state")),
                ("OS match", scan.get("os_match")),
                ("OS accuracy", scan.get("os_accuracy")),
                ("OS detection", scan.get("os_detection_status")),
                ("MAC address", scan.get("mac_address")),
                ("MAC vendor", scan.get("mac_vendor")),
            ])

        ports = list_of_dicts(result.get("ports"))
        open_ports = [
            port for port in ports
            if str(port.get("state", "")).lower() == "open"
        ]
        add_block("Nmap Port Summary", [
            ("Ports recorded", len(ports)),
            ("Open ports", len(open_ports)),
        ])

        for port in open_ports[:40]:
            add_block(
                f"Open port {port.get('port', 'Unknown')}/{port.get('protocol', '')}",
                [
                    ("State", port.get("state")),
                    ("Service", port.get("service")),
                    ("Product", port.get("product")),
                    ("Version", port.get("version")),
                    ("Reason", port.get("reason")),
                ],
            )

        if len(open_ports) > 40:
            story.append(Paragraph(
                f"{len(open_ports) - 40} additional open-port records omitted.",
                styles["small"],
            ))

    elif module == "web_security":
        headers = list_of_dicts(result.get("headers"))
        add_block("Web Security Overview", [
            ("HTTP status code", result.get("status_code")),
            ("Missing security headers", result.get("missing_headers")),
            ("Security headers assessed", len(headers)),
            ("Cookie records assessed", len(list_of_dicts(result.get("cookies")))),
            ("Verified vulnerabilities", result.get("verified_vulnerabilities", 0)),
        ])

        for header in headers[:20]:
            add_block(
                f"Security Header: {header.get('name') or header.get('header') or 'Unknown'}",
                [
                    ("Present", header.get("present")),
                    ("Assessment", header.get("assessment")),
                    ("Observation", str(header.get("issue") or "")[:220]),
                ],
            )

        cookies = list_of_dicts(result.get("cookies"))
        if cookies:
            add_block("Cookie Security Flags (values excluded)", [
                ("Cookies assessed", len(cookies)),
                ("Secure flag present", sum(bool(c.get("secure")) for c in cookies)),
                ("HttpOnly flag present", sum(bool(c.get("httponly")) for c in cookies)),
                ("SameSite attribute present", sum(bool(c.get("samesite")) for c in cookies)),
            ])

        discovery = result.get("discovery")
        if isinstance(discovery, dict):
            pages = discovery.get("pages")
            urls = discovery.get("discovered_urls")
            endpoints = discovery.get("api_endpoints")
            forms = discovery.get("forms")
            limits = discovery.get("limits")
            add_block("Read-only Discovery Summary", [
                ("Pages discovered", len(pages) if isinstance(pages, list) else 0),
                ("URLs discovered", len(urls) if isinstance(urls, list) else 0),
                ("API endpoints discovered", len(endpoints) if isinstance(endpoints, list) else 0),
                ("Forms discovered", len(forms) if isinstance(forms, list) else 0),
                ("Crawler requests used", limits.get("requests_used") if isinstance(limits, dict) else None),
            ])

        for label, key in (
            ("Reflected-input assessment", "reflected_input_assessment"),
            ("SQL injection assessment", "sql_injection_assessment"),
        ):
            assessment = result.get(key)
            if isinstance(assessment, dict):
                checks = assessment.get("checks")
                add_block(label, [
                    ("Status", assessment.get("status")),
                    ("Checks recorded", len(checks) if isinstance(checks, list) else 0),
                    ("Requests used", assessment.get("requests_used")),
                    ("Verified vulnerabilities", assessment.get("verified_vulnerabilities", 0)),
                ])

        budget = result.get("request_budget")
        if isinstance(budget, dict):
            add_block("Assessment Request Budget", [
                ("Maximum", budget.get("maximum")),
                ("Used", budget.get("used")),
                ("Remaining", budget.get("remaining")),
            ])

    elif module == "threat_intel":
        add_block("Threat Intelligence Overview", [
            ("IP address", result.get("ip")),
            ("Found in InternetDB", result.get("found")),
        ])

        for label, key, limit in (
            ("Reported ports", "ports", 30),
            ("Associated hostnames", "hostnames", 20),
            ("Tags", "tags", 20),
        ):
            values = list_of_strings(result.get(key), limit)
            add_block(label, [
                ("Count", len(result.get(key)) if isinstance(result.get(key), list) else 0),
                ("Values", ", ".join(values) if values else "None recorded"),
            ])

        vulnerabilities = list_of_strings(result.get("vulns"), 100)
        cves = [
            value for value in vulnerabilities
            if value.upper().startswith("CVE-")
        ]
        add_block("CVE References", [
            ("CVE identifiers", ", ".join(cves[:40]) if cves else "None recorded"),
        ])

    elif module == "firewall":
        tcp = result.get("tcp")
        tcp = tcp if isinstance(tcp, dict) else {}
        counts = tcp.get("counts")
        counts = counts if isinstance(counts, dict) else {}
        ports = list_of_dicts(tcp.get("ports"))

        add_block("TCP Reachability Summary", [
            ("Open", counts.get("open", 0)),
            ("Closed", counts.get("closed", 0)),
            ("No response", counts.get("no_response", 0)),
            ("Indeterminate", counts.get("indeterminate", 0)),
        ])

        for port in ports[:40]:
            add_block(
                f"TCP Observation: {port.get('port', 'Unknown')}",
                [
                    ("Address", port.get("address")),
                    ("Protocol", port.get("protocol", "tcp")),
                    ("State", port.get("state")),
                ],
            )

        if len(ports) > 40:
            story.append(Paragraph(
                f"{len(ports) - 40} additional TCP observations omitted.",
                styles["small"],
            ))

        services = result.get("services")
        services = services if isinstance(services, dict) else {}
        service_items = list_of_dicts(services.get("items"))
        for service in service_items[:30]:
            application = service.get("application")
            application_name = (
                application.get("name")
                if isinstance(application, dict) else None
            )
            add_block("Identified Service", [
                ("Address", service.get("address")),
                ("Port", service.get("port")),
                ("Protocol", service.get("protocol")),
                ("Service", service.get("service") or service.get("name") or application_name),
            ])

        https = result.get("https")
        https = https if isinstance(https, dict) else {}
        add_block("HTTP / HTTPS Observation", [
            ("Checked", https.get("checked")),
            ("Scheme", https.get("scheme")),
            ("Port", https.get("port")),
            ("HTTP status", https.get("status_code")),
            ("Application", (
                https.get("application", {}).get("name")
                if isinstance(https.get("application"), dict) else None
            )),
        ])

        tls = result.get("tls")
        tls = tls if isinstance(tls, dict) else {}
        add_block("TLS Inspection", [
            ("Available", tls.get("available")),
            ("Port", tls.get("port")),
            ("TLS version", tls.get("version")),
            ("Cipher", tls.get("cipher")),
        ])

        waf = result.get("waf")
        waf = waf if isinstance(waf, dict) else {}
        add_block("WAF Indicators", [
            ("Indicator detected", waf.get("detected")),
            ("Confidence", waf.get("confidence")),
        ])

        vendors = list_of_dicts(waf.get("vendor_identification"))
        for vendor in vendors[:10]:
            add_block("WAF Fingerprint Indicator", [
                ("Vendor", vendor.get("vendor")),
                ("Confidence", vendor.get("confidence")),
            ])


    elif module == "zap":
        alerts = list_of_dicts(result.get("alerts"))
        risk_counts = {}
        for alert in alerts:
            risk = str(alert.get("risk") or "Unknown").strip()
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        add_block("OWASP ZAP Overview", [
            ("Total alerts", len(alerts)),
            ("Spider scan ID", result.get("spider_scan_id")),
            ("Active scan ID", result.get("active_scan_id")),
            ("Alert retrieval warning", result.get("alerts_error")),
            ("Risk distribution", ", ".join(
                f"{risk}: {count}"
                for risk, count in sorted(risk_counts.items())
            ) if risk_counts else "No alerts recorded"),
        ])

        for index, alert in enumerate(alerts[:50], start=1):
            add_block(
                f"ZAP Alert {index}: {alert.get('name') or alert.get('alert') or 'Unnamed alert'}",
                [
                    ("Risk", alert.get("risk")),
                    ("Confidence", alert.get("confidence")),
                    ("URL", alert.get("url")),
                    ("Method", alert.get("method")),
                    ("Parameter", alert.get("param")),
                    ("Attack", alert.get("attack")),
                    ("Evidence", alert.get("evidence")),
                    ("Description", alert.get("description")),
                    ("Solution", alert.get("solution")),
                    ("Reference", alert.get("reference")),
                    ("Plugin ID", alert.get("pluginId")),
                    ("CWE ID", alert.get("cweid")),
                    ("WASC ID", alert.get("wascid")),
                ],
            )

        if len(alerts) > 50:
            story.append(Paragraph(
                f"{len(alerts) - 50} additional ZAP alerts omitted from this report.",
                styles["small"],
            ))

    return story


def build_unified_scan_pdf(*, run, targets, modules, batches, items):
    """Build one consolidated PDF for a saved Unified Scan run."""
    styles = _make_styles()
    buffer = BytesIO()

    completed = sum(
        str(item["status"]).lower() == "completed" for item in items
    )
    partial = sum(
        str(item["status"]).lower() == "partial" for item in items
    )
    failed = sum(
        str(item["status"]).lower() == "failed" for item in items
    )
    skipped = sum(
        str(item["status"]).lower() == "skipped" for item in items
    )

    story = [
        Paragraph("UNIFIED SECURITY ASSESSMENT", styles["title"]),
        Paragraph(
            f"Assessment run #{_safe(run['id'])}",
            styles["subtitle"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Executive Summary", styles["section"]),
        _detail_block("Run Overview", [
            ("Run ID", run["id"]),
            ("Overall status", run["status"]),
            ("Created (IST)", format_datetime(run["created_at"])),
            ("Finished (IST)", format_datetime(run["finished_at"])),
            ("Targets submitted", len(targets)),
            ("Modules selected", ", ".join(modules)),
            ("Module batches", len(batches)),
            ("Completed targets", completed),
            ("Partial targets", partial),
            ("Failed targets", failed),
            ("Skipped targets", skipped),
        ], styles),
        Paragraph("Submitted Targets", styles["section"]),
    ]

    if targets:
        for target in targets:
            story.append(Paragraph(f"• {_safe(target)}", styles["body"]))
    else:
        story.append(Paragraph("No targets were recorded.", styles["body"]))

    story.append(Paragraph("Module Batch Summary", styles["section"]))
    if batches:
        data = [[
            Paragraph(label, styles["table_header"])
            for label in ("Module", "Profile", "Status", "Total",
                          "Completed", "Partial", "Failed", "Skipped")
        ]]
        for batch in batches:
            data.append([
                Paragraph(_safe(batch["module"]), styles["table_cell"]),
                Paragraph(_safe(batch["profile"]), styles["table_cell"]),
                Paragraph(_safe(batch["status"]), styles["table_cell"]),
                str(batch["total_targets"]),
                str(batch["completed_targets"]),
                str(batch["partial_targets"]),
                str(batch["failed_targets"]),
                str(batch["skipped_targets"]),
            ])

        table = Table(
            data,
            colWidths=[25 * mm, 28 * mm, 22 * mm, 14 * mm,
                       18 * mm, 16 * mm, 16 * mm, 16 * mm],
            repeatRows=1,
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
            ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (3, 1), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No module batches were created.", styles["body"]))

    story.append(Paragraph("Target Assessment Results", styles["section"]))
    if items:
        for item in items:
            module_name = {
                "nmap": "Nmap",
                "web_security": "Web Security",
                "threat_intel": "Threat Intelligence",
                "firewall": "Firewall Detection",
            }.get(item.get("module"), item.get("module", "Assessment"))

            story.append(_detail_block(
                f"{module_name} — {item.get('target') or 'Unknown target'}",
                [
                    ("Batch ID", item.get("batch_id")),
                    ("Target position", item.get("position")),
                    ("Status", item.get("status")),
                    ("Started (IST)", format_datetime(item.get("started_at"))),
                    ("Finished (IST)", format_datetime(item.get("finished_at"))),
                    ("Duration (seconds)", item.get("duration_seconds")),
                    ("Result type", item.get("result_type")),
                    ("Saved result ID", item.get("result_record_id")),
                    ("Error", item.get("error")),
                ],
                styles,
            ))

            # The Web Security result may contain ZAP data. The renderer
            # deliberately reads only its explicitly selected safe fields.
            technical_story = _unified_technical_section(
                item.get("module"),
                item.get("technical_result"),
                styles,
            )
            if technical_story:
                story.extend(technical_story)

            story.append(Spacer(1, 2 * mm))
    else:
        story.append(Paragraph(
            "No target result records were available when this report was generated.",
            styles["body"],
        ))

    story.extend([
        Spacer(1, 4 * mm),
        Paragraph(
            "This report consolidates saved results from the selected Unified "
            "Scan run. Module-specific reports contain additional technical "
            "details. A completed scan does not by itself establish that a "
            "system is secure or compliant. Verify observations and assess "
            "them against the applicable security requirements. Only assess "
            "systems for which authorization has been granted.",
            styles["small"],
        ),
    ])

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=25 * mm,
        bottomMargin=20 * mm,
        title=f"Shadow Map GRC Unified Assessment - {run['id']}",
        author="Shadow Map GRC",
        subject="Consolidated Unified Scan assessment",
    )
    document.build(
        story,
        onFirstPage=_page_chrome,
        onLaterPages=_page_chrome,
    )
    return buffer.getvalue()


def build_firewall_pdf(*, scan, result):
    """Build a branded PDF from a saved Firewall Detection assessment."""
    buffer = BytesIO()
    styles = _make_styles()

    tcp = result.get("tcp") or {}
    services = result.get("services") or {}
    web = result.get("https") or {}
    tls = result.get("tls") or {}
    waf = result.get("waf") or {}

    tcp_items = tcp.get("ports") or []
    service_items = services.get("items") or []
    waf_items = waf.get("vendor_identification") or []
    headers = web.get("headers") or {}
    limitations = result.get("limitations") or []

    counts = tcp.get("counts") or {}
    open_count = counts.get("open", 0)
    closed_count = counts.get("closed", 0)
    no_response_count = counts.get("no_response", 0)
    indeterminate_count = counts.get("indeterminate", 0)

    identified_count = sum(
        1 for item in service_items
        if (item.get("application") or item).get("product")
        or (item.get("application") or item).get("service") != "unknown"
    )

    story = [
        Paragraph("FIREWALL ASSESSMENT", styles["title"]),
        Paragraph(
            f"Target: {_safe(result.get('target') or scan['target'])}",
            styles["subtitle"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Executive Summary", styles["section"]),
    ]

    summary = [
        ["Assessment status", _safe(scan["status"])],
        ["Resolved addresses", str(len(result.get("resolved_addresses") or []))],
        ["TCP ports tested", str(len(tcp_items))],
        ["Open TCP ports", str(open_count)],
        ["Closed TCP ports", str(closed_count)],
        ["No-response TCP ports", str(no_response_count)],
        ["Indeterminate TCP ports", str(indeterminate_count)],
        ["Service observations", str(len(service_items))],
        ["Identified services / products", str(identified_count)],
        ["HTTP(S) response", (
            str(web.get("status_code"))
            if web.get("checked") and web.get("status_code") is not None
            else "Not available"
        )],
        ["TLS available", "Yes" if tls.get("available") else "No"],
        ["WAF indicators observed", "Yes" if waf.get("detected") else "No"],
        ["WAF confidence", _safe(waf.get("confidence") or "unknown")],
    ]

    table = Table(summary, colWidths=[65 * mm, 105 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PALE_TEAL),
        ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([table, Spacer(1, 5 * mm)])

    story.append(Paragraph("Assessment Details", styles["section"]))
    duration = scan["duration_seconds"]
    story.append(_detail_block("Saved Firewall Scan", [
        ("Scan ID", scan["id"]),
        ("Target", result.get("target") or scan["target"]),
        ("Host", result.get("host")),
        ("Status", scan["status"]),
        ("Started (IST)", format_datetime(scan["started_at"])),
        ("Finished (IST)", format_datetime(scan["finished_at"])),
        ("Recorded duration", (
            f"{duration:.2f} seconds" if duration is not None else "—"
        )),
        ("Scanner duration", result.get("duration_seconds")),
        ("Error", scan["error"]),
    ], styles))

    addresses = result.get("resolved_addresses") or []
    story.append(Paragraph("Resolved Addresses", styles["section"]))
    if addresses:
        story.append(Paragraph(
            _safe(", ".join(str(address) for address in addresses)),
            styles["body"],
        ))
    else:
        story.append(Paragraph(
            "No resolved addresses were recorded.", styles["body"]
        ))

    def add_table(title, headings, rows, widths):
        story.append(Paragraph(title, styles["section"]))
        if not rows:
            story.append(Paragraph(
                "No observations were recorded.", styles["body"]
            ))
            return

        data = [[
            Paragraph(_safe(heading), styles["table_header"])
            for heading in headings
        ]]
        for row in rows:
            data.append([
                Paragraph(_safe(value), styles["table_cell"])
                for value in row
            ])

        report_table = Table(
            data,
            colWidths=widths,
            repeatRows=1,
        )
        report_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
            ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([report_table, Spacer(1, 4 * mm)])

    add_table(
        "Network Filtering Observations",
        ["Address", "Port", "State", "Duration", "Reason"],
        [
            [
                item.get("address"),
                item.get("port"),
                item.get("state"),
                item.get("duration_seconds", "—"),
                item.get("reason") or item.get("error") or "—",
            ]
            for item in tcp_items
        ],
        [42 * mm, 17 * mm, 28 * mm, 27 * mm, 56 * mm],
    )

    service_rows = []
    for item in service_items:
        app = item.get("application") or item
        evidence = app.get("evidence") or item.get("evidence") or []
        service_rows.append([
            item.get("address") or app.get("address"),
            item.get("port") or app.get("port"),
            item.get("protocol") or app.get("protocol"),
            app.get("service") or item.get("service") or "unknown",
            app.get("product") or "Not identified",
            app.get("version") or "Not disclosed",
            app.get("confidence") or item.get("confidence") or "unknown",
            "; ".join(str(value) for value in evidence) or "No explicit evidence",
        ])

    add_table(
        "Service & Application Identification",
        [
            "Address", "Port", "Protocol", "Service",
            "Product", "Version", "Confidence", "Evidence",
        ],
        service_rows,
        [25 * mm, 11 * mm, 16 * mm, 18 * mm,
         22 * mm, 17 * mm, 19 * mm, 45 * mm],
    )

    story.append(Paragraph("HTTP(S) Response Observations", styles["section"]))
    story.append(_detail_block("Web Response", [
        ("URL", web.get("url")),
        ("Scheme", web.get("scheme")),
        ("Port", web.get("port")),
        ("Response checked", "Yes" if web.get("checked") else "No"),
        ("HTTP status", web.get("status_code")),
        ("Server header", web.get("server")),
        ("Connected address", web.get("connected_address")),
        ("Redirect followed", "No"),
        ("Application product", (
            (web.get("application") or {}).get("product")
            or "Not identified"
        )),
        ("Application version", (
            (web.get("application") or {}).get("version")
            or "Not disclosed"
        )),
        ("Inspection error", web.get("error")),
    ], styles))

    if headers:
        header_rows = [
            [name, value]
            for name, value in headers.items()
        ]
        add_table(
            "Selected HTTP Response Headers",
            ["Header", "Observed value"],
            header_rows,
            [45 * mm, 129 * mm],
        )

    cookie_summary = web.get("set_cookie")
    if cookie_summary:
        story.append(Paragraph("Cookie Observations", styles["section"]))
        story.append(Paragraph(
            _safe(cookie_summary),
            styles["body"],
        ))

    if web.get("error"):
        story.append(Paragraph(
            f"HTTP(S) inspection note: {_safe(web.get('error'))}",
            styles["small"],
        ))

    story.append(Paragraph("TLS Certificate Observations", styles["section"]))
    if tls.get("available"):
        story.append(_detail_block("Verified TLS Connection", [
            ("TLS version", tls.get("version")),
            ("Port", tls.get("port")),
            ("Connected address", tls.get("connected_address")),
            ("Certificate expiry", tls.get("not_after")),
            ("Subject", tls.get("subject")),
            ("Issuer", tls.get("issuer")),
            ("Subject alternative names", tls.get("subject_alt_names")),
        ], styles))
    else:
        story.append(Paragraph(
            f"TLS certificate details unavailable: "
            f"{_safe(tls.get('error') or 'No verified TLS connection.')}",
            styles["body"],
        ))

    story.append(Paragraph("WAF and Vendor Indicators", styles["section"]))
    story.append(_detail_block("WAF Assessment", [
        ("Indicators detected", "Yes" if waf.get("detected") else "No"),
        ("Confidence", waf.get("confidence") or "unknown"),
        ("Vendor clues", len(waf_items)),
        ("Limitation", waf.get("limitation")),
    ], styles))

    add_table(
        "WAF Vendor Evidence",
        ["Vendor", "Product indicators", "Evidence", "Confidence"],
        [
            [
                item.get("vendor"),
                item.get("product"),
                item.get("evidence"),
                item.get("confidence"),
            ]
            for item in waf_items
        ],
        [30 * mm, 48 * mm, 66 * mm, 30 * mm],
    )

    local_firewall = result.get("local_firewall") or {}
    if local_firewall:
        story.append(Paragraph(
            "Local Machine Firewall Detection",
            styles["section"],
        ))
        story.append(_detail_block("Local Inspection Scope", [
            ("Scope", local_firewall.get("scope")),
            ("Platform", local_firewall.get("platform")),
            ("Operating system", local_firewall.get("operating_system")),
            ("Overall detection status", local_firewall.get("status")),
        ], styles))

        technology_rows = []
        for item in local_firewall.get("technologies") or []:
            technology_rows.append([
                item.get("name"),
                item.get("category"),
                item.get("status"),
                "Yes" if item.get("available") else "No",
                "; ".join(str(value) for value in (item.get("evidence") or [])),
                item.get("error"),
            ])

        add_table(
            "Local Firewall Technologies",
            ["Technology", "Category", "Status", "Available", "Evidence", "Error"],
            technology_rows,
            [28 * mm, 25 * mm, 20 * mm, 18 * mm, 48 * mm, 35 * mm],
        )

        observation_rows = []
        for item in local_firewall.get("service_observations") or []:
            observation_rows.append([
                item.get("source"),
                item.get("name"),
                item.get("status"),
                "; ".join(str(value) for value in (item.get("evidence") or [])),
                item.get("error") or item.get("limitation"),
            ])

        add_table(
            "Local Firewall Service and Configuration Observations",
            ["Source", "Name", "Status", "Evidence", "Inspection note"],
            observation_rows,
            [25 * mm, 35 * mm, 20 * mm, 58 * mm, 36 * mm],
        )

        for note in local_firewall.get("limitations") or []:
            story.append(Paragraph(
                f"• {_safe(note)}",
                styles["small"],
            ))

        story.append(Paragraph(
            "Local firewall inspection is read-only. Installed software, "
            "running services or processes, loaded modules, readable rules, "
            "and configuration evidence do not by themselves prove effective "
            "packet filtering or enforcement.",
            styles["small"],
        ))

    story.append(Paragraph("Interpretation and Limitations", styles["section"]))
    interpretation_items = [
        tcp.get("interpretation"),
        services.get("interpretation"),
        waf.get("limitation"),
    ]
    for note in interpretation_items:
        if note:
            story.append(Paragraph(f"• {_safe(note)}", styles["body"]))

    if limitations:
        for note in limitations:
            story.append(Paragraph(f"• {_safe(note)}", styles["body"]))

    story.extend([
        Spacer(1, 4 * mm),
        Paragraph(
            "This report records remote observations and evidence available "
            "at assessment time. A no-response TCP probe does not prove the "
            "presence of a firewall. Service and product fingerprints are "
            "limited by information disclosed by the target and may be "
            "incomplete or misleading. A completed assessment does not "
            "establish that a system is secure or compliant. Only assess "
            "systems for which authorization has been granted.",
            styles["small"],
        ),
    ])

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=25 * mm,
        bottomMargin=20 * mm,
        title=f"Shadow Map GRC Firewall Assessment - {scan['id']}",
        author="Shadow Map GRC",
        subject="Firewall Detection and service identification assessment",
    )
    document.build(
        story,
        onFirstPage=_page_chrome,
        onLaterPages=_page_chrome,
    )
    return buffer.getvalue()



def build_zap_pdf(*, scan, result):
    """Build a PDF report from one saved OWASP ZAP scan."""
    styles = _make_styles()
    buffer = BytesIO()

    alerts = result.get("alerts", []) if isinstance(result, dict) else []
    if not isinstance(alerts, list):
        alerts = []

    alerts = [alert for alert in alerts if isinstance(alert, dict)]

    risk_counts = {}
    for alert in alerts:
        risk = str(alert.get("risk") or "Unknown").strip()
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    story = [
        Paragraph("OWASP ZAP SECURITY ASSESSMENT", styles["title"]),
        Paragraph(
            f"Saved scan #{_safe(scan['id'])}",
            styles["subtitle"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Scan Summary", styles["section"]),
        _detail_block("Assessment Overview", [
            ("Scan ID", scan["id"]),
            ("Target", scan["target"]),
            ("Status", scan["status"]),
            ("Started", format_datetime(scan["started_at"])),
            ("Finished", format_datetime(scan["finished_at"])),
            ("Duration (seconds)", scan["duration_seconds"]),
            ("Total alerts", len(alerts)),
            ("Spider scan ID", result.get("spider_scan_id")),
            ("Active scan ID", result.get("active_scan_id")),
            ("Scan error", scan["error"]),
            ("Alert retrieval warning", result.get("alerts_error")),
        ], styles),
        Paragraph("Risk Distribution", styles["section"]),
    ]

    if risk_counts:
        for risk, count in sorted(risk_counts.items()):
            story.append(
                Paragraph(
                    f"{_safe(risk)}: {count}",
                    styles["body"],
                )
            )
    else:
        story.append(Paragraph("No alerts were saved.", styles["body"]))

    story.append(Paragraph("Alert Details", styles["section"]))

    if alerts:
        for index, alert in enumerate(alerts, start=1):
            story.append(_detail_block(
                f"Alert {index}: {alert.get('name') or alert.get('alert') or 'Unnamed alert'}",
                [
                    ("Risk", alert.get("risk")),
                    ("Confidence", alert.get("confidence")),
                    ("URL", alert.get("url")),
                    ("Method", alert.get("method")),
                    ("Parameter", alert.get("param")),
                    ("Attack", alert.get("attack")),
                    ("Evidence", alert.get("evidence")),
                    ("Description", alert.get("description")),
                    ("Solution", alert.get("solution")),
                    ("Reference", alert.get("reference")),
                    ("Plugin ID", alert.get("pluginId")),
                    ("CWE ID", alert.get("cweid")),
                    ("WASC ID", alert.get("wascid")),
                ],
                styles,
            ))
            story.append(Spacer(1, 3 * mm))
    else:
        story.append(Paragraph(
            "No alert details are available for this saved scan.",
            styles["body"],
        ))

    story.extend([
        Spacer(1, 4 * mm),
        Paragraph(
            "This report contains saved OWASP ZAP scan observations. "
            "Review findings manually before treating them as confirmed "
            "vulnerabilities. Only assess systems for which authorization "
            "has been granted.",
            styles["small"],
        ),
    ])

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=25 * mm,
        bottomMargin=20 * mm,
        title=f"Shadow Map GRC OWASP ZAP Scan - {scan['id']}",
        author="Shadow Map GRC",
        subject="OWASP ZAP security assessment",
    )
    document.build(
        story,
        onFirstPage=_page_chrome,
        onLaterPages=_page_chrome,
    )
    return buffer.getvalue()


def build_global_scan_history_pdf(*, scans):
    """Build one detailed PDF from explicitly selected scan records."""
    buffer = BytesIO()
    styles = _make_styles()
    story = [
        Paragraph("Global Scan History Report", styles["title"]),
        Paragraph(
            "Consolidated technical report for selected scan records",
            styles["subtitle"],
        ),
    ]

    total = len(scans)
    completed = sum(s.get("status") == "Completed" for s in scans)
    failed = sum(s.get("status") == "Failed" for s in scans)
    skipped = sum(s.get("status") == "Skipped" for s in scans)

    story.append(Paragraph("Executive Summary", styles["section"]))
    story.append(Paragraph(
        _safe(
            f"Selected records: {total} | Completed: {completed} | "
            f"Failed: {failed} | Skipped: {skipped}"
        ),
        styles["body"],
    ))

    story.append(Paragraph("Selected Scan Coverage", styles["section"]))
    coverage = [[
        _paragraph("Scan ID", styles["table_header"]),
        _paragraph("Module", styles["table_header"]),
        _paragraph("Target", styles["table_header"]),
        _paragraph("Status", styles["table_header"]),
        _paragraph("Started", styles["table_header"]),
    ]]
    for scan in scans:
        coverage.append([
            _paragraph(scan.get("scan_id") or "Not assigned", styles["table_cell"]),
            _paragraph(scan.get("module") or "Unknown", styles["table_cell"]),
            _paragraph(scan.get("target"), styles["table_cell"]),
            _paragraph(scan.get("status"), styles["table_cell"]),
            _paragraph(scan.get("started_at"), styles["table_cell"]),
        ])

    table = Table(coverage, colWidths=[25*mm, 31*mm, 55*mm, 25*mm, 38*mm],
                  repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("GRID", (0, 0), (-1, -1), 0.35, LIGHT_GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)

    for index, scan in enumerate(scans, start=1):
        story.append(Paragraph(
            f"{index}. { _safe(scan.get('module') or 'Scan') }",
            styles["section"],
        ))
        story.append(_detail_block("Scan Metadata", [
            ("Scan ID", scan.get("scan_id")),
            ("Record ID", scan.get("record_id")),
            ("Target", scan.get("target")),
            ("Status", scan.get("status")),
            ("Started", scan.get("started_at")),
            ("Finished", scan.get("finished_at")),
            ("Duration (seconds)", scan.get("duration_seconds")),
            ("Error / limitation", scan.get("error")),
        ], styles))

        result = scan.get("result") or {}
        ports = scan.get("ports") or []

        module_name = str(scan.get("module") or "").strip().lower()
        module_key = {
            "nmap": "nmap",
            "web security": "web_security",
            "threat intelligence": "threat_intel",
            "firewall": "firewall",
            "firewall detection": "firewall",
            "owasp zap": "zap",
            "zap": "zap",
        }.get(module_name)

        technical_result = result if isinstance(result, dict) else {}

        # Standalone Nmap records store host details on the scan row and
        # port observations separately. Adapt them to the shared renderer.
        if module_key == "nmap":
            technical_result = dict(technical_result)
            technical_result.setdefault("scan", technical_result.copy())
            technical_result["ports"] = ports

        technical_story = _unified_technical_section(
            module_key,
            technical_result,
            styles,
        ) if module_key else []

        if technical_story:
            story.append(Paragraph(
                "Structured Technical Assessment",
                styles["heading"],
            ))
            story.extend(technical_story)
        else:
            story.append(Paragraph(
                "No structured technical result details were recorded for this module.",
                styles["small"],
            ))

        ports = scan.get("ports") or []
        if ports:
            story.append(Paragraph("Nmap Port Observations", styles["heading"]))
            rows = [[
                _paragraph("Port", styles["table_header"]),
                _paragraph("Protocol", styles["table_header"]),
                _paragraph("State", styles["table_header"]),
                _paragraph("Service", styles["table_header"]),
                _paragraph("Version", styles["table_header"]),
            ]]
            for port in ports:
                rows.append([
                    _paragraph(port.get("port"), styles["table_cell"]),
                    _paragraph(port.get("protocol"), styles["table_cell"]),
                    _paragraph(port.get("state"), styles["table_cell"]),
                    _paragraph(port.get("service"), styles["table_cell"]),
                    _paragraph(port.get("version"), styles["table_cell"]),
                ])
            port_table = Table(rows, colWidths=[18*mm, 22*mm, 22*mm, 35*mm, 77*mm],
                               repeatRows=1)
            port_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("GRID", (0, 0), (-1, -1), 0.3, LIGHT_GREY),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(port_table)

        findings = scan.get("findings") or []
        story.append(Paragraph(
            f"Findings and Evidence ({len(findings)})", styles["heading"]
        ))
        if findings:
            for finding in findings:
                story.append(_detail_block(
                    finding.get("title") or "Finding",
                    [
                        ("Severity", finding.get("suggested_severity")),
                        ("Status", finding.get("status")),
                        ("Description", finding.get("description")),
                        ("Evidence", finding.get("evidence")),
                        ("Recommendation", finding.get("recommendation")),
                        ("ISO Controls", finding.get("iso_controls")),
                        ("Linked Risk ID", finding.get("risk_id")),
                    ],
                    styles,
                ))
        else:
            story.append(Paragraph(
                "No linked draft findings were recorded for this scan.",
                styles["small"],
            ))

        risks = scan.get("risks") or []
        if risks:
            story.append(Paragraph("Linked Risk Register Entries", styles["heading"]))
            for risk in risks:
                story.append(_detail_block(
                    risk.get("title") or "Risk",
                    [
                        ("Risk ID", risk.get("id")),
                        ("Description", risk.get("description")),
                        ("Asset", risk.get("asset")),
                        ("Inherent score", risk.get("inherent_score")),
                        ("Residual score", risk.get("residual_score")),
                        ("Treatment", risk.get("treatment")),
                        ("Status", risk.get("status")),
                    ],
                    styles,
                ))

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=18*mm, leftMargin=18*mm,
        topMargin=22*mm, bottomMargin=20*mm,
        title="Global Scan History Report",
        author="Shadow Map GRC",
    )
    doc.build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
    return buffer.getvalue()
