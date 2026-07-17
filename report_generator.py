# ══════════════════════════════════════════════
# CyberScope — Módulo 5: Reporte PDF
# ══════════════════════════════════════════════

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime

# ── Colores ───────────────────────────────────
DARK_BLUE  = colors.HexColor("#0D1B2A")
CYAN       = colors.HexColor("#00C2FF")
MID_BLUE   = colors.HexColor("#1A3A5C")
LIGHT_GRAY = colors.HexColor("#F4F6F9")
RED        = colors.HexColor("#C0392B")
ORANGE     = colors.HexColor("#E67E22")
GREEN      = colors.HexColor("#27AE60")
WHITE      = colors.white
TEXT_DARK  = colors.HexColor("#1A1A2E")

def generar_reporte(objetivo, puertos_detectados, puntaje_total, nivel_riesgo, hallazgos):

    fecha     = datetime.now().strftime("%Y-%m-%d_%H-%M")
    fecha_leg = datetime.now().strftime("%d/%m/%Y %H:%M")
    filename  = f"reporte_cyberscope_{fecha}.pdf"

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm,   bottomMargin=2*cm
    )

    # ── Estilos ───────────────────────────────
    styles = getSampleStyleSheet()

    TITLE = ParagraphStyle("Title",
        fontSize=22, textColor=WHITE, alignment=TA_CENTER,
        fontName="Helvetica-Bold", leading=28)

    SUB = ParagraphStyle("Sub",
        fontSize=11, textColor=CYAN, alignment=TA_CENTER,
        fontName="Helvetica", leading=16)

    META = ParagraphStyle("Meta",
        fontSize=9, textColor=colors.HexColor("#A0B4C8"),
        alignment=TA_CENTER, fontName="Helvetica")

    SEC = ParagraphStyle("Sec",
        fontSize=12, textColor=WHITE, fontName="Helvetica-Bold", leading=18)

    BODY = ParagraphStyle("Body",
        fontSize=10, textColor=TEXT_DARK, fontName="Helvetica", leading=15)

    story = []

    # ── ENCABEZADO ────────────────────────────
    header_data = [[
        Paragraph("CYBERSCOPE", TITLE),
    ]]
    header_table = Table(header_data, colWidths=[17*cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK_BLUE),
        ("TOPPADDING",    (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(header_table)

    sub_data = [[
        Paragraph("Reporte de Reconocimiento y Evaluación de Seguridad", SUB),
    ]]
    sub_table = Table(sub_data, colWidths=[17*cm])
    sub_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK_BLUE),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 16),
    ]))
    story.append(sub_table)
    story.append(Spacer(1, 0.4*cm))

    # ── INFO DEL ESCANEO ──────────────────────
    def sec_header(titulo):
        t = Table([[Paragraph(titulo, SEC)]], colWidths=[17*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), MID_BLUE),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ]))
        return t

    story.append(sec_header("📋  Información del Escaneo"))
    story.append(Spacer(1, 0.2*cm))

    info_data = [
        ["Objetivo escaneado",  objetivo],
        ["Fecha y hora",        fecha_leg],
        ["Puertos detectados",  str(len(puertos_detectados))],
        ["Herramienta",         "CyberScope v1.0 — python-nmap"],
    ]
    info_table = Table(info_data, colWidths=[5*cm, 12*cm])
    info_table.setStyle(TableStyle([
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",      (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",      (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS",(0,0), (-1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#CCCCCC")),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("TEXTCOLOR",     (0,0), (-1,-1), TEXT_DARK),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.4*cm))

    # ── TABLA DE SERVICIOS ────────────────────
    story.append(sec_header("🔍  Servicios Detectados"))
    story.append(Spacer(1, 0.2*cm))

    serv_data = [["Puerto", "Estado", "Servicio", "Versión"]]
    for p in puertos_detectados:
        serv_data.append([
            str(p["puerto"]),
            p["estado"],
            p["servicio"],
            p["version"] if p["version"] else "—"
        ])

    serv_table = Table(serv_data, colWidths=[3*cm, 3*cm, 5*cm, 6*cm])
    serv_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), DARK_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,0), (-1,-1), 10),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#CCCCCC")),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("TEXTCOLOR",     (0,1), (-1,-1), TEXT_DARK),
    ]))
    story.append(serv_table)
    story.append(Spacer(1, 0.4*cm))

    # ── TABLA DE RIESGOS ──────────────────────
    story.append(sec_header("⚠️  Análisis de Riesgo por Servicio"))
    story.append(Spacer(1, 0.2*cm))

    from risk_scoring import RIESGOS, VERSIONES_VULNERABLES
    riesgo_data = [["Puerto", "Servicio", "Puntos", "Razón"]]

    for p in puertos_detectados:
        servicio = p["servicio"].lower()
        version  = p["version"]

        if servicio in RIESGOS:
            r = RIESGOS[servicio]
            riesgo_data.append([
                str(p["puerto"]), servicio,
                f"+{r['puntos']}", r["razon"]
            ])

        for ver_clave, ver_data in VERSIONES_VULNERABLES.items():
            if ver_clave in str(version):
                riesgo_data.append([
                    str(p["puerto"]), f"{servicio} v{ver_clave}",
                    f"+{ver_data['puntos']}", ver_data["razon"]
                ])

    riesgo_table = Table(riesgo_data, colWidths=[2.5*cm, 4*cm, 2.5*cm, 8*cm])
    riesgo_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), MID_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#CCCCCC")),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("ALIGN",         (0,0), (2,-1), "CENTER"),
        ("ALIGN",         (3,0), (3,-1), "LEFT"),
        ("TEXTCOLOR",     (0,1), (-1,-1), TEXT_DARK),
    ]))
    story.append(riesgo_table)
    story.append(Spacer(1, 0.4*cm))

    # ── RESULTADO FINAL ───────────────────────
    story.append(sec_header("🎯  Resultado Final"))
    story.append(Spacer(1, 0.2*cm))

    if "ALTO" in nivel_riesgo:
        color_riesgo = RED
        emoji = "🔴"
    elif "MEDIO" in nivel_riesgo:
        color_riesgo = ORANGE
        emoji = "🟡"
    else:
        color_riesgo = GREEN
        emoji = "🟢"

    RIESGO_STYLE = ParagraphStyle("RS",
        fontSize=18, textColor=color_riesgo,
        alignment=TA_CENTER, fontName="Helvetica-Bold", leading=26)

    PUNTOS_STYLE = ParagraphStyle("PS",
        fontSize=13, textColor=TEXT_DARK,
        alignment=TA_CENTER, fontName="Helvetica", leading=20)

    resultado_data = [[
        Paragraph(f"{emoji} {nivel_riesgo.replace('🔴','').replace('🟡','').replace('🟢','').strip()}", RIESGO_STYLE),
    ],[
        Paragraph(f"Puntaje total: {puntaje_total} puntos", PUNTOS_STYLE),
    ]]
    resultado_table = Table(resultado_data, colWidths=[17*cm])
    resultado_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), LIGHT_GRAY),
        ("TOPPADDING",    (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#CCCCCC")),
    ]))
    story.append(resultado_table)
    story.append(Spacer(1, 0.4*cm))

    # ── PIE DE PAGINA ─────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=CYAN))
    story.append(Spacer(1, 0.2*cm))
    pie = ParagraphStyle("Pie",
        fontSize=8, textColor=colors.HexColor("#888888"),
        alignment=TA_CENTER, fontName="Helvetica-Oblique")
    story.append(Paragraph(
        f"Reporte generado automáticamente por CyberScope v1.0 · {fecha_leg} · Solo para uso autorizado",
        pie))

    doc.build(story)
    print(f"\n✅ Reporte generado: {filename}\n")
    return filename
