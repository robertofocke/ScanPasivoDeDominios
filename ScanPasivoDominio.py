import time
import os
import re
import sys
import requests
import random
from ipaddress import ip_network
from bs4 import BeautifulSoup
import ipaddress
from urllib.parse import quote

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
]


DIR_IMAGENES = "imagenes_shodan"
BASE_URL = "https://web.archive.org/web/timemap/json"

URL_REGEX = re.compile(r'https?://[^\s"\']+')

terminos = ["http", "https"]

palabras_clave = []
target = ""
subdomains = []


def get_random_user_agent():
    return random.choice(USER_AGENTS)   
def carga_palabrasclave ():
    global palabras_clave 
    with open("diccionario.txt", "r", encoding="utf-8") as archivo:
        palabras_clave = [linea.strip() for linea in archivo if linea.strip()]

def save_subdomains(subdomain,output_file):
    with open(output_file,"a") as f:
        f.write(subdomain)

def consultar_leaks(dominio: str, limit: int = 10000, timeout: int = 30):
    """
    Consulta el Timemap (JSON) de Wayback Machine para un dominio dado,timeout
    usando matchType=prefix (equivalente a "dominio/*").
 
    Devuelve el objeto Response de requests, o None si hubo un error de red.
    """
    url_objetivo = quote(f"{dominio}/", safe="")
    params = {
        "url": f"{dominio}/",  # requests se encarga de codificar esto
        "matchType": "prefix",
        "collapse": "urlkey",
        "output": "json",
        "fl": "original,mimetype,timestamp,endtimestamp,groupcount,uniqcount",
        "filter": "!statuscode:[45]..",
        "limit": str(limit),
        "_": str(int(time.time() * 1000)),  # cache-buster, como en la request original
    }
 
    try:
        time.sleep(random.randint(3, 8))
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(BASE_URL, params=params, headers=headers)
        time.sleep(random.randint(3, 8))
        datos = response.json()
        if len(datos) <= 1:
            return []
        urls_filtradas = []
        for fila in datos[1:]:
            url_original = fila[0]
            if any(termino.lower() in url_original.lower() for termino in palabras_clave):
                urls_filtradas.append(url_original)
        save_subdomains(str(urls_filtradas),output_leak)
    except requests.RequestException as e:
        print(f"[{dominio}] Error de red: {e}", file=sys.stderr)
        return None

def scanear_Dominio (target_param):
    global subdomains, target  
    target = target_param
    headers = {"User-Agent": get_random_user_agent()}
    req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=target))
    if req.status_code != 200:
        print("[X] Information not available!") 
        exit(1)
    for (key,value) in enumerate(req.json()):
        subdomains.append(value['name_value'])	
    print("\n[!] ---- TARGET: {d} ---- [!] \n".format(d=target))
    subdomains = sorted(set(subdomains))
    for subdomain in subdomains:
        print("[-]  {s}".format(s=subdomain))
        if output is not None:
            save_subdomains(subdomain,output)
            consultar_leaks(subdomain)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: script.py <Dominio>")
        sys.exit(1)
    carga_palabrasclave()
    subdomains = []
    output_leak = str(sys.argv[1]+"_output_leaks.txt")
    output = str(sys.argv[1]+"_output_subdominios.txt")
    scanear_Dominio(str(sys.argv[1]))

