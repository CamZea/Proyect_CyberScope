# ══════════════════════════════════════════════
# CyberScope — Módulo 4: Risk Scoring
# ══════════════════════════════════════════════

from prettytable import PrettyTable

# ── Tabla de riesgos por servicio ─────────────
RIESGOS = {
    "ftp":           {"puntos": 30, "razon": "Protocolo sin cifrado, credenciales expuestas"},
    "telnet":        {"puntos": 40, "razon": "Protocolo obsoleto y sin cifrado"},
    "ssh":           {"puntos": 10, "razon": "Acceso remoto expuesto"},
    "http":          {"puntos": 20, "razon": "Trafico web sin cifrado HTTPS"},
    "https":         {"puntos": 5,  "razon": "Trafico cifrado, riesgo menor"},
    "smb":           {"puntos": 35, "razon": "Protocolo SMB historicamente vulnerable"},
    "microsoft-ds":  {"puntos": 35, "razon": "SMB/Windows networking expuesto"},
    "msrpc":         {"puntos": 20, "razon": "RPC de Windows expuesto"},
    "ms-sql-m":      {"puntos": 40, "razon": "Base de datos SQL Server expuesta"},
    "ms-sql-s":      {"puntos": 40, "razon": "Base de datos SQL Server expuesta"},
    "mysql":         {"puntos": 40, "razon": "Base de datos MySQL expuesta"},
    "rdp":           {"puntos": 35, "razon": "Escritorio remoto expuesto"},
    "dsc":           {"puntos": 15, "razon": "Servicio de configuracion remota"},
}

# ── Riesgos extra por versiones antiguas ──────
VERSIONES_VULNERABLES = {
    "2.4.25": {"puntos": 30, "razon": "Apache 2.4.25 — version antigua con CVEs conocidos"},
    "2.4.18": {"puntos": 35, "razon": "Apache 2.4.18 — version desactualizada"},
    "2.0.8":  {"puntos": 25, "razon": "vsftpd 2.0.8 — version antigua de FTP"},
    "5.0":    {"puntos": 40, "razon": "MySQL 5.0 — version muy antigua"},
    "5.1":    {"puntos": 35, "razon": "MySQL 5.1 — version desactualizada"},
    "7.2":    {"puntos": 20, "razon": "PHP 7.2 — sin soporte oficial"},
}

# ── Clasificacion final ───────────────────────
def clasificar_riesgo(total):
    if total >= 80:
        return "🔴 RIESGO ALTO", "El objetivo presenta multiples vectores de ataque criticos."
    elif total >= 40:
        return "🟡 RIESGO MEDIO", "Existen vulnerabilidades que deben ser corregidas."
    else:
        return "🟢 RIESGO BAJO", "El objetivo tiene una exposicion controlada."

# ── Motor principal ───────────────────────────
def calcular_riesgo(puertos_detectados):
    """
    Recibe lista de dicts con claves: puerto, estado, servicio, version
    Retorna: tabla de hallazgos + puntaje total + clasificacion
    """
    print("\n" + "═"*55)
    print("   CyberScope — Análisis de Riesgo")
    print("═"*55)

    tabla = PrettyTable()
    tabla.field_names = ["Puerto", "Servicio", "Puntos", "Razón"]
    tabla.align["Razón"] = "l"

    total = 0
    hallazgos = []

    for p in puertos_detectados:
        servicio = p.get("servicio", "").lower()
        version  = p.get("version", "")
        puerto   = p.get("puerto")

        # Riesgo por servicio
        if servicio in RIESGOS:
            r = RIESGOS[servicio]
            tabla.add_row([puerto, servicio, f"+{r['puntos']}", r["razon"]])
            total += r["puntos"]
            hallazgos.append(r["razon"])

        # Riesgo extra por version vulnerable
        for ver_clave, ver_data in VERSIONES_VULNERABLES.items():
            if ver_clave in str(version):
                tabla.add_row([puerto, f"{servicio} v{ver_clave}",
                               f"+{ver_data['puntos']}", ver_data["razon"]])
                total += ver_data["puntos"]
                hallazgos.append(ver_data["razon"])

    print(tabla)

    # Resultado final
    nivel, descripcion = clasificar_riesgo(total)
    print("\n" + "─"*55)
    print(f"  Puntaje total de riesgo : {total} puntos")
    print(f"  Clasificación           : {nivel}")
    print(f"  Descripción             : {descripcion}")
    print("─"*55 + "\n")

    return total, nivel, hallazgos


# ── Prueba con datos del scanner ──────────────
if __name__ == "__main__":
    # Simulamos el output del scanner.py
    puertos_detectados = [
        {"puerto": 21,   "estado": "open", "servicio": "ftp",          "version": "2.0.8"},
        {"puerto": 135,  "estado": "open", "servicio": "msrpc",         "version": ""},
        {"puerto": 445,  "estado": "open", "servicio": "microsoft-ds",  "version": ""},
        {"puerto": 1434, "estado": "open", "servicio": "ms-sql-m",      "version": ""},
        {"puerto": 2222, "estado": "open", "servicio": "ssh",           "version": "10.2"},
        {"puerto": 3390, "estado": "open", "servicio": "dsc",           "version": ""},
        {"puerto": 8080, "estado": "open", "servicio": "http",          "version": "2.4.25"},
    ]

    calcular_riesgo(puertos_detectados)