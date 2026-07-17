# ══════════════════════════════════════════════
# CyberScope — main.py
# Flujo completo: Scan → Risk Scoring
# ══════════════════════════════════════════════

import nmap
from prettytable import PrettyTable
from risk_scoring import calcular_riesgo

def scan_target(target):
    print("\n" + "═"*55)
    print("   CyberScope — Network Scanner")
    print("═"*55)
    print(f"\n🔍 Escaneando {target}...\n")

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments='-sV')

    tabla = PrettyTable()
    tabla.field_names = ["Puerto", "Estado", "Servicio", "Versión"]

    puertos_detectados = []

    for host in scanner.all_hosts():
        print(f"  Host   : {host} ({scanner[host].hostname()})")
        print(f"  Estado : {scanner[host].state()}\n")

        for proto in scanner[host].all_protocols():
            puertos = scanner[host][proto].keys()

            for puerto in sorted(puertos):
                datos = scanner[host][proto][puerto]

                version = datos['version'] if datos['version'] else '—'
                tabla.add_row([
                    puerto,
                    datos['state'],
                    datos['name'],
                    version
                ])

                # Guardar para risk scoring
                puertos_detectados.append({
                    "puerto":   puerto,
                    "estado":   datos['state'],
                    "servicio": datos['name'],
                    "version":  datos['version']
                })

    print(tabla)
    return puertos_detectados


if __name__ == "__main__":
    print("\n" + "═"*55)
    print("   CyberScope v1.0 — Plataforma de Reconocimiento")
    print("═"*55)
    print("\nEjemplos de objetivo:")
    print("  → IP local        : 192.168.1.100")
    print("  → Tu red Docker   : 127.0.0.1")
    print("  → Rango de red    : 192.168.1.0/24")
    print("  → Metasploitable  : 192.168.x.x\n")

    objetivo = input("🎯 Ingresa el objetivo a escanear: ").strip()

    if not objetivo:
        objetivo = "127.0.0.1"
        print(f"  (Sin entrada, usando objetivo por defecto: {objetivo})")
        
    # Paso 1: Escanear
    puertos = scan_target(objetivo)

    # Paso 2: Calcular riesgo con datos reales del scan
    print("\n")
    calcular_riesgo(puertos)

    # Al inicio del archivo, agrega este import:
from report_generator import generar_reporte

# Al final del archivo, después de calcular_riesgo(), agrega:
puntaje, nivel, hallazgos = calcular_riesgo(puertos)
generar_reporte("127.0.0.1", puertos, puntaje, nivel, hallazgos)
