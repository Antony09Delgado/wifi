import re
import yaml
# cargar lista de paginas malas
with open("config/blocklist.txt", "r") as f:
    dominios_prohibidos = [line.strip() for line in f if line.strip()]

#cargamos palabras clave desde un archivo YAML
with open("config/config.yaml", "r")as f:
    config = yaml.safe_load(f)

palabras_clave = config["palabras_clave"]

def es_sospechoso(datos):
    destino = datos.get("destino", "")
    payload = datos.get("payload", "").lower()

    #verificar si el destino esta en la lista de dominios prohibidos
    for dominio in dominios_prohibidos:
        if dominio in destino:
            print(f"Alerta: Acceso a dominio prohibido detectado: {destino}")
            return True
    
    #verificar si el payload contiene palabras clave sospechosas
    for palabra in palabras_clave:
        if re.search(r'\b' + re.escape(palabra.lower()) + r'\b', payload):
            print(f"Alerta: Palabra clave sospechosa detectada en el payload: {palabra}")
            return True
        
    return False

