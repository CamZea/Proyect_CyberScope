import nmap
from prettytable import PrettyTable

def scan_target(target):
    print(f"\n🔍 Escaneando {target}...\n")
    
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments='-sV')
    
    tabla = PrettyTable()
    tabla.field_names = ["Puerto", "Estado", "Servicio", "Versión"]
    
    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"Estado: {scanner[host].state()}\n")
        
        for proto in scanner[host].all_protocols():
            puertos = scanner[host][proto].keys()
            
            for puerto in sorted(puertos):
                datos = scanner[host][proto][puerto]
                tabla.add_row([
                    puerto,
                    datos['state'],
                    datos['name'],
                    datos['version'] if datos['version'] else '—'
                ])
    
    print(tabla)

if __name__ == "__main__":
    scan_target("127.0.0.1")