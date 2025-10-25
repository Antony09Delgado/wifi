from scapy.all import sniff, IP, TCP, get_if_list, get_if_addr
import yaml
from analyzer import es_sospechoso
from pathlib import Path

# cargarmos configuraciones desde un archivo YAML (ruta robusta relativa a este archivo)
config_path = Path(__file__).resolve().parents[1] / "config" / "config.yaml"
with open(config_path, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

# obtener la lista de IPs vigiladas desde el YAML y normalizar a set para búsquedas rápidas
ips_vigiladas = config.get("ips_vigiladas", [])
if isinstance(ips_vigiladas, str):
    ips_vigiladas = [ips_vigiladas]  # Normalizar y eliminar espacios extra

ips_vigiladas = {str(ip).strip() for ip in ips_vigiladas}

print("IPs vigiladas cargadas:", ips_vigiladas)

# Mostrar interfaces y direcciones IP asociadas (útil para elegir la correcta)
ifaces = get_if_list()
print("Interfaces disponibles:")
for i in ifaces:
    try:
        addr = get_if_addr(i)
    except Exception:
        addr = "<sin IPv4>"
    print(f"  - '{i}'  addr: {addr}")

# Intentar auto-seleccionar la interfaz que comparte /24 con alguna IP vigilada
def same_prefix(a, b, prefix_octets=3):
    try:
        return ".".join(a.split(".")[:prefix_octets]) == ".".join(b.split(".")[:prefix_octets])
    except Exception:
        return False

selected_iface = None
for i in ifaces:
    try:
        addr = get_if_addr(i)
    except Exception:
        continue
    for vip in ips_vigiladas:
        if vip and addr != "0.0.0.0" and same_prefix(addr, vip):
            selected_iface = i
            break
    if selected_iface:
        break

# Si no se encontró, deja None y el usuario debe poner el nombre exacto impreso arriba
IFACE = selected_iface  # cambia aquí si quieres forzar un nombre: p.e. "Wi‑Fi"
print("Interfaz seleccionada automáticamente:", IFACE)

PROMISC = True

def procesar_paquete(pkt):
    # soportar IPv4 y IPv6 para depurar
    ip_origen = None
    ip_destino = None
    if IP in pkt:
        ip_origen = str(pkt[IP].src)
        ip_destino = str(pkt[IP].dst)
    else:
        # si hay IPv6
        try:
            from scapy.layers.inet6 import IPv6
            if IPv6 in pkt:
                ip_origen = str(pkt[IPv6].src)
                ip_destino = str(pkt[IPv6].dst)
        except Exception:
            pass

    # si no hay IPs, salir

    puerto_destino = pkt[TCP].dport if TCP in pkt else None

    # DEBUG: imprime todas las conexiones para ver por qué no se detectan
    #print(f"DBG paquete: {ip_origen} -> {ip_destino} :{puerto_destino}")

    # DEBUG: comprobar membership explícito
    #print(f"DBG membership check: origen in ips_vigiladas? {ip_origen in ips_vigiladas}, destino in ips_vigiladas? {ip_destino in ips_vigiladas}")

    #solo ver si las ip estan involucradas
    if ip_origen in ips_vigiladas or ip_destino in ips_vigiladas:
        datos = {
            "origen": ip_origen,
            "destino": ip_destino,
            "puerto_destino": puerto_destino,
            "payload": str(pkt[TCP].payload) if TCP in pkt else "",
        }

        print("Paquete capturado (IP vigilada):", datos)
        #aqui se llama al analizador
        if es_sospechoso(datos):
            print("""Alerta de seguridad
                  
                  
                  s

                  s
                  s
                  s
                  s
                  s
                  """)

#iniciar la captura de paquetes
print("Iniciando captura de paquetes...")
# Si no ves tráfico, prueba a quitar el filtro o cambiar iface
sniff(filter="", prn=procesar_paquete, store=False, iface=IFACE, promisc=PROMISC)