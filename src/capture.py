from scapy.all import sniff, IP, TCP
import yaml

#cargarmos configuraciones desde un archivo YAML
with open("config/config.yaml", "r")as f:
    config = yaml.safe_load(f)

ips_vigiladas = config["ips_vigiladas"]

def procesar_paquete(pkt):
    if IP in pkt and TCP in pkt:
        ip_origen = pkt[IP].src
        ip_destino = pkt[IP].dst
        puerto_destino = pkt[TCP].dport

        #solo ver si las ip estan involucradas
        if ip_origen in ips_vigiladas or ip_destino in ips_vigiladas:
            datos = {
                "origen": ip_origen,
                "destino": ip_destino,
                "puerto_destino": puerto_destino,
                "payload": str(pkt[TCP].payload),
            }

            print(f"Paquete capturado: {datos}")
            #aqui se llama al analizador
            # analizar_paquete(datos)

#iniciar la captura de paquetes
print("Iniciando captura de paquetes...")
sniff(filter="tcp", prn=procesar_paquete, store=False)