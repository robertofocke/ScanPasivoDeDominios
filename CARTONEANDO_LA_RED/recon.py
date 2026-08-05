"""
recon.py

"""
import os
import random
import re
import socket
import time
import sys
import requests
from bs4 import BeautifulSoup
from googlesearch import search
from ipaddress import ip_network
import ipaddress


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
]
palabras_clave = []
terminos = ["http", "https"]
tecnologia=""
BASE_URL= "https://web.archive.org/web/timemap/json"
DIR_IMAGENES = "imagenes_shodan"
def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)


def buscar_servicio_por_puerto(puerto):
    """Intenta resolver el nombre de servicio asociado a un puerto (tcp o udp)."""
    try:
        puerto_int = int(puerto)
    except (TypeError, ValueError):
        return "Desconocido"
    try:
        return socket.getservbyport(puerto_int, "tcp")
    except OSError:
        pass
    try:
        return socket.getservbyport(puerto_int, "udp")
    except OSError:
        return "Desconocido"


def extraer_puertos_de_html(html: str):
    """Extrae puertos listados en el div#ports de una página de shodan.io/host/<ip>."""
    soup = BeautifulSoup(html, "html.parser")
    div_ports = soup.find("div", id="ports")
    if div_ports is None:
        return []
    puertos = []
    for a in div_ports.find_all("a", href=True):
        valor = a["href"].lstrip("#")
        if not valor.isdigit():
            continue
        puertos.append({"puerto": valor, "servicio": buscar_servicio_por_puerto(valor)})
    return puertos


def buscar_urls_imagenes_shodan(html: str):
    patron = r'href="(https://www\.shodan\.io/host/\d{1,3}(?:\.\d{1,3}){3}/image(?:\?p=\d+)?)"'
    return re.findall(patron, html)

def consulta_a_shodan(ip: str):
    """Trae la página pública de shodan.io/host/<ip>. Devuelve dict con estado y datos."""
    url = f"https://www.shodan.io/host/{ip}"
    time.sleep(random.uniform(2, 3))
    try:    
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(url, headers=headers)
        time.sleep(random.uniform(2, 3))
    except requests.RequestException as e:
        return {"ok": False, "error": str(e), "url": url}
    if response.status_code != 200:
        return {"ok": False, "error": f"HTTP {response.status_code}", "url": url}
    puertos = extraer_puertos_de_html(response.text)
    imagenes = buscar_urls_imagenes_shodan(response.text)
    for url_img in imagenes:
        return {"ok": True, "url": url, "puertos": puertos, "captura": url_img}
    if len(puertos):
        return {"ok": True, "url": url, "puertos": puertos, "captura": None}
    else:
        return {"ok": False, "url": url, "puertos": puertos, "captura": None}

def descargar_imagen(url: str, carpeta: str) -> None:
    """
    Descarga el contenido de una URL y lo guarda en disco.
    """
    try:
        time.sleep(3)
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(url, headers=headers)
        os.makedirs(carpeta, exist_ok=True)
        # Genera un nombre de archivo a partir de la URL
        nombre = re.sub(r"[^a-zA-Z0-9]+", "_", url).strip("_") + ".png"
        ruta = os.path.join(carpeta, nombre)
        with open(ruta, "wb") as f:
            f.write(response.content)
    except requests.RequestException as e:
        ruta=None
    return ruta

def obtener_subdominios(dominio: str):
    """Consulta crt.sh (Certificate Transparency logs) para listar subdominios."""
    url = f"https://crt.sh/?q=%.{dominio}&output=json"
    req = None
    req = requests.get(url)
    while req.status_code != 200:
        try:
            headers = {"User-Agent": get_random_user_agent()}
            req = requests.get(url,headers=headers)
            time.sleep(2)
            if req.status_code == 200:
                break
        except requests.RequestException:
            req = None
    if req is None or req.status_code != 200:
        return []
    try:
        datos = req.json()
    except ValueError:
        return []
    subdominios = set()
    for entrada in datos:
        nombre = entrada.get("name_value", "")
        for linea in nombre.split("\n"):
            linea = linea.strip().lower()
            if linea:
                subdominios.add(linea)
    return sorted(subdominios)


def resolver_ip(subdominio: str):
    try:
        return socket.gethostbyname(subdominio)
    except socket.gaierror:
        return None

def consultar_cymru_ip(ip: str) -> dict:
    """
    Se conecta al puerto 43 de whois.cymru.com, envía una IP y
    devuelve un diccionario con el AS, la IP y el AS Name.
    """
    host = "whois.cymru.com"
    port = 43
    
    # 1. Crear el socket TCP y conectarse
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)  # Tiempo de espera máximo de 5 segundos
        s.connect((host, port))
        
        # 2. Enviar la IP con salto de línea (requerido por el protocolo WHOIS)
        # Agregamos 'begin\n' y 'end\n' para forzar que devuelva las cabeceras estándar
        payload = f"begin\n{ip}\nend\n"
        s.sendall(payload.encode("utf-8"))
        
        # 3. Recibir toda la respuesta del servidor
        respuesta = ""
        while True:
            datos = s.recv(1024).decode("utf-8")
            if not datos:
                break
            respuesta += datos

def consultar_leaks(dominio: str, limit: int = 10000, timeout: int = 30):
    """
    Consulta el Timemap (JSON) de Wayback Machine para un dominio dado,timeout
    usando matchType=prefix (equivalente a "dominio/*").
 
    Devuelve el objeto Response de requests, o None si hubo un error de red.
    """
    print(dominio)
    #url_objetivo = quote(f"{dominio}/", safe="")
    params = {
        "url": f"{dominio}",  # requests se encarga de codificar esto
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
                try:
                    site=requests.get(url_original)
                    if site.status_code == 200:
                        urls_filtradas.append(url_original)
                        if ".php" in str(url_original):
                            tecnologia+="php "
                        if "wp-admin" in str(url_original):
                            tecnologia+="wordpress"
                        if "user/password/sites/" in str(url_original):
                            tecnologia+="drupal"
                        if "components" in str(url_original):
                            tecnologia+="joomla "
                        if "jsp" in str(url_original):
                            tecnologia+="jsp "
                        save_subdomains(str(urls_filtradas),output_leak)
                except ValueError as error:
                    pass 
    except requests.RequestException as e:
        print(f"[{dominio}] Error de red: {e}", file=sys.stderr)
        return None

def escanear_dominio(dominio_objetivo: str, consultar_shodan: bool = True):
    """
    Punto de entrada principal.
    1) Busca subdominios en crt.sh
    2) Resuelve cada uno a IP
    3) (opcional) consulta shodan.io/host/<ip> para cada IP única
    Devuelve un dict listo para serializar a JSON.
    """
    dominio_objetivo = dominio_objetivo.strip().lower()
    dominio_objetivo = re.sub(r"^https?://", "", dominio_objetivo).strip("/")

    subdominios = obtener_subdominios(dominio_objetivo)
    resultados = []
    ips_consultadas = {}  # cache para no repetir consultas a shodan sobre la misma IP

    for sub in subdominios:
        ip = resolver_ip(sub)
        if ip not in ips_consultadas and consultar_shodan:
            ips_consultadas[ip] = consulta_a_shodan(ip)
        elif not consultar_shodan:
            ips_consultadas[ip] = None
        # Se crea una estructura limpia para CADA IP dentro del bucle
        tecnologia=consultar_leaks(sub)
        entrada = {
            "subdominio": sub,
            "ip": ip, 
            "shodan": ips_consultadas[ip], 
            "captura": None, 
            "google": "https://www.google.com/search?q=ite%3Aapi.urlscan.io%2Fresult+host&sca_esv=1e85827d6e1fa685&sxsrf=APpeQntxHA_jTaFj_EJBg2CMzMNqThJikQ%3A1785875749228&source=hp&ei=JU1yao7eC9vL1sQP-LuE8AI&iflsig=ABILxe8AAAAAanJbNaIh2fFIP5Ac4QWJu2kVW7z64qDb&ved=0ahUKEwjOhJPN6YeWAxXbpZUCHfgdAS4Q4dUDCCc&uact=5&oq=ite%3Aapi.urlscan.io%2Fresult+"+str(sub), 
            "weymachine": "https://web.archilve.org/web/*/"+str(sub)+"/*",
            "tecnologia":tecnologia
        }
        print(entrada)
        try: 
            resultados.append(entrada)
        except ValueError as error:
            pass
    return {
        "dominio": dominio_objetivo,
        "total_subdominios_encontrados": len(subdominios),
        "resultados": resultados,}

def ips_del_rango(cidr: str, incluir_red_broadcast: bool = False) -> list[str]:
    red = ip_network(cidr, strict=False)

    if incluir_red_broadcast:
        return [str(ip) for ip in red]
    else:
        return [str(ip) for ip in red.hosts()]

def obtener_urls_rapido(dominio, cantidad_resultados=5):
    query="site:api.urlscan.io/result+text:"+str(dominio)
    urls = []
    try:
        for url in search(query, num_results=cantidad_resultados, lang="es", sleep_interval=random.uniform(3, 4)):
            urls.append(url)
    except (TypeError, ValueError):
        pass
    return urls

def scanear_ip(dominio_objetivo: str, consultar_shodan: bool = True):
    resultados = []
    ips = []
    ips_consultadas = {}
    
    str_limpio = dominio_objetivo.strip()
    
    # 1. Validar si la entrada es una IP directa o un dominio/rango
    try:
        ip_objeto = ipaddress.ip_address(str_limpio)
        ips.append(str(ip_objeto)) 
    except ValueError:
        ips = ips_del_rango(str_limpio)
    
    # 2. Iterar y procesar cada IP de forma independiente
    for ip in ips:
        if ip not in ips_consultadas and consultar_shodan:
            ips_consultadas[ip] = consulta_a_shodan(ip)
        elif not consultar_shodan:
            ips_consultadas[ip] = None

        # Se crea una estructura limpia para CADA IP dentro del bucle
        entrada = {
    
            "ip": ip, 
            "shodan": ips_consultadas[ip], 
            "captura": None, 
            "google": None, 
            "weymachine": None,
            "tecnologia": None
        }
        print(entrada)
        try:
            resultados.append(entrada)
        except ValueError as error:
            pass
    # 3. Consultas globales adicionales (si aplican al objetivo general)
    datos_ip = consultar_cymru_ip(dominio_objetivo)
    return {
        "dominio": dominio_objetivo,
        "total_subdominios_encontrados": None,
        "resultados": resultados,
    }
