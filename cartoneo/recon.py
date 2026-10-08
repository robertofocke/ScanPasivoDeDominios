"""
recon.py
PoC de reconocimiento pasivo: dado un dominio, IP o rango CIDR,
reúne información de exposición desde fuentes públicas
(crt.sh, página host pública de Shodan, Wayback Machine).
No es un scanner de vulnerabilidades: solo lee datos ya publicados.
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
from urllib.parse import urlparse
import ipaddress


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
]
palabras_clave = []
BASE_URL = "https://web.archive.org/web/timemap/json"
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
    """Extrae puertos listados en el div#ports de shodan.io/host/<ip>."""
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
    """
    Trae la página pública de shodan.io/host/<ip>.
    Devuelve SIEMPRE un dict con las mismas claves (ok, url, puertos, captura[, error])
    o None si no se le pasa una IP. Nunca debe llamarse con ip=None.
    """
    if not ip:
        return None
    url = f"https://www.shodan.io/host/{ip}"
    time.sleep(random.uniform(2, 3))
    try:
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(url, headers=headers, timeout=20)
        time.sleep(random.uniform(2, 3))
    except requests.RequestException as e:
        return {"ok": False, "error": str(e), "url": url, "puertos": [], "captura": None}
    if response.status_code != 200:
        return {"ok": False, "error": f"HTTP {response.status_code}", "url": url,
                "puertos": [], "captura": None}

    puertos = extraer_puertos_de_html(response.text)
    imagenes = buscar_urls_imagenes_shodan(response.text)
    captura = imagenes[0] if imagenes else None

    if puertos or captura:
        return {"ok": True, "url": url, "puertos": puertos, "captura": captura}
    return {"ok": False, "url": url, "puertos": [], "captura": None,
            "error": "sin datos públicos en Shodan"}


def descargar_imagen(url: str, carpeta: str):
    """Descarga una URL y la guarda en disco. Devuelve la ruta o None."""
    ruta = None
    try:
        time.sleep(3)
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(url, headers=headers, timeout=20)
        os.makedirs(carpeta, exist_ok=True)
        nombre = re.sub(r"[^a-zA-Z0-9]+", "_", url).strip("_") + ".png"
        ruta = os.path.join(carpeta, nombre)
        with open(ruta, "wb") as f:
            f.write(response.content)
    except requests.RequestException:
        ruta = None
    return ruta


def limpiar_nombre(nombre: str, dominio: str):
    """
    Normaliza un nombre devuelto por crt.sh. Devuelve None si hay que descartarlo.
    - descarta vacíos y correos (SAN con '@')
    - quita el comodín inicial '*.'  ->  *.ccad.unc.edu.ar  =>  ccad.unc.edu.ar
    - descarta cualquier resto con '*' u otros caracteres no válidos de hostname
    - exige que pertenezca al dominio objetivo
    """
    if not nombre:
        return None
    # minúsculas + sin espacios + sin puntos sobrantes a ambos lados
    nombre = nombre.strip().lower().strip(".")
    if "@" in nombre:
        return None
    while nombre.startswith("*."):
        nombre = nombre[2:]
    nombre = nombre.strip(".")        # por si quedó un punto tras quitar el comodín
    if "*" in nombre or not nombre:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", nombre):
        return None
    if not (nombre == dominio or nombre.endswith("." + dominio)):
        return None
    return nombre


def obtener_subdominios(dominio: str, max_intentos=None, pausa: float = 2.0,
                        verbose: bool = True):
    """
    Consulta crt.sh (Certificate Transparency). Devuelve (subdominios, error).

    Fiel al código ORIGINAL y a lo que pediste:
    - SIN timeout en la request: espera lo que haga falta. crt.sh, para dominios
      grandes (p. ej. mercadopago), puede tardar MINUTOS en responder; con un
      timeout cortábamos la respuesta y por eso nunca traía nada.
    - Reintenta hasta recibir una LISTA JSON válida, con 'pausa' segundos entre
      intentos. max_intentos=None => reintenta indefinidamente (como el original).
    - Imprime diagnóstico por consola en CADA intento, así se ve qué devuelve
      crt.sh (HTTP, content-type, tamaño) en vez de ver siempre "no hay nada".
    """
    url = f"https://crt.sh/?q=%.{dominio}&output=json"
    datos = None
    ultimo_motivo = "crt.sh no respondió"
    intentos = 0

    while max_intentos is None or intentos < max_intentos:
        intentos += 1
        try:
            headers = {"User-Agent": get_random_user_agent()}
            # SIN timeout a propósito: esperamos lo que haga falta.
            req = requests.get(url, headers=headers)
        except requests.RequestException as e:
            ultimo_motivo = f"error de red contra crt.sh: {e}"
            if verbose:
                print(f"[crt.sh][{dominio}] intento {intentos}: {ultimo_motivo}",
                      file=sys.stderr)
            time.sleep(pausa)
            continue

        ctype = req.headers.get("content-type", "")
        cuerpo = req.text.strip()
        if verbose:
            print(f"[crt.sh][{dominio}] intento {intentos}: HTTP {req.status_code}, "
                  f"content-type={ctype!r}, {len(cuerpo)} bytes", file=sys.stderr)

        if req.status_code != 200:
            ultimo_motivo = f"crt.sh respondió HTTP {req.status_code}"
            # 429/503 = saturado o rate-limit: conviene esperar bastante más.
            time.sleep(pausa * 5 if req.status_code in (429, 502, 503) else pausa)
            continue

        if not cuerpo:               # 200 pero vacío: típico de crt.sh saturado
            ultimo_motivo = "crt.sh devolvió un cuerpo vacío"
            time.sleep(pausa)
            continue

        try:
            datos = req.json()
        except ValueError:
            ultimo_motivo = "crt.sh no devolvió JSON (HTML/interstitial)"
            if verbose:
                print(f"[crt.sh][{dominio}] primeros 200 chars: {cuerpo[:200]!r}",
                      file=sys.stderr)
            datos = None
            time.sleep(pausa)
            continue

        # crt.sh a veces responde 200 con un dict de error en vez de una lista.
        if not isinstance(datos, list):
            ultimo_motivo = "crt.sh no devolvió una lista (respuesta inesperada)"
            datos = None
            time.sleep(pausa)
            continue

        break  # llegamos acá solo con una lista JSON válida

    if datos is None:
        return [], f"{ultimo_motivo} (tras {intentos} intentos)"

    subdominios = set()
    for entrada in datos:
        if not isinstance(entrada, dict):
            continue
        nombre = entrada.get("name_value", "") or ""
        for linea in nombre.split("\n"):
            limpio = limpiar_nombre(linea, dominio)
            if limpio:
                subdominios.add(limpio)
    if verbose:
        print(f"[crt.sh][{dominio}] OK: {len(subdominios)} subdominios "
              f"tras {intentos} intento(s)", file=sys.stderr)
    return sorted(subdominios), None


def extraer_host(url: str) -> str:
    """Devuelve solo el host de una URL (sin esquema, puerto, usuario ni path)."""
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    try:
        neto = urlparse(url).netloc
    except ValueError:
        return ""
    # saca user@ y :puerto
    return neto.split("@")[-1].split(":")[0].strip().lower()


def subdominios_de_wayback(dominio: str, limit: int = 50000, verbose: bool = True):
    """
    Saca subdominios (hosts) ÚNICOS vistos por Wayback Machine para el dominio.

    Wayback devuelve una fila por URL archivada, así que el MISMO host aparece
    miles de veces (una por cada path). Acá nos quedamos solo con el host de
    cada URL y lo deduplicamos, para no repetir subdominios.

    Devuelve un set de hosts ya normalizados y pertenecientes al dominio.
    """
    params = {
        "url": dominio,
        "matchType": "domain",       # equivale a *.dominio
        "collapse": "urlkey",
        "output": "json",
        "fl": "original",
        "limit": str(limit),
        "_": str(int(time.time() * 1000)),
    }
    try:
        time.sleep(random.randint(3, 8))          # pausa de cortesía (como el original)
        headers = {"User-Agent": get_random_user_agent()}
        resp = requests.get(BASE_URL, params=params, headers=headers)
        time.sleep(random.randint(3, 8))
        datos = resp.json()
    except (requests.RequestException, ValueError) as e:
        if verbose:
            print(f"[wayback][{dominio}] error: {e}", file=sys.stderr)
        return set()

    if not isinstance(datos, list) or len(datos) <= 1:
        return set()

    hosts = set()
    for fila in datos[1:]:                         # datos[0] es la cabecera
        url_original = fila[0] if fila else ""
        limpio = limpiar_nombre(extraer_host(url_original), dominio)
        if limpio:
            hosts.add(limpio)
    if verbose:
        print(f"[wayback][{dominio}] {len(hosts)} subdominios únicos "
              f"(de {len(datos) - 1} URLs archivadas)", file=sys.stderr)
    return hosts


def resolver_ip(subdominio: str):
    """Resuelve un hostname a IPv4. Devuelve None si es comodín o no resuelve."""
    if not subdominio or "*" in subdominio:
        return None
    try:
        return socket.gethostbyname(subdominio)
    except (socket.gaierror, UnicodeError, OSError):
        return None


def consultar_cymru_ip(ip: str) -> dict:
    """
    Consulta whois.cymru.com (puerto 43) y devuelve {asn, ip, as_name}.
    """
    host, port = "whois.cymru.com", 43
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(f"begin\n{ip}\nend\n".encode("utf-8"))
            respuesta = ""
            while True:
                datos = s.recv(1024).decode("utf-8", errors="ignore")
                if not datos:
                    break
                respuesta += datos
    except OSError as e:
        return {"ok": False, "error": str(e)}

    lineas = [l for l in respuesta.splitlines()
              if "|" in l and "AS Name" not in l and not l.lower().startswith("bulk")]
    if not lineas:
        return {"ok": False, "raw": respuesta.strip()}
    campos = [c.strip() for c in lineas[0].split("|")]
    if len(campos) >= 3:
        return {"ok": True, "asn": campos[0], "ip": campos[1], "as_name": campos[-1]}
    return {"ok": False, "raw": respuesta.strip()}


def consultar_leaks(dominio, limit: int = 10000):
    """
    Wayback Machine Timemap (JSON). Devuelve un string con las tecnologías
    detectadas por patrones de URL, o None. OPCIONAL: es lento por los sleeps
    de cortesía, por eso está desactivado por defecto en escanear_dominio().
    """
    params = {
        "url": dominio,
        "matchType": "prefix",
        "collapse": "urlkey",
        "output": "json",
        "fl": "original,mimetype,timestamp,endtimestamp,groupcount,uniqcount",
        "filter": "!statuscode:[45]..",
        "limit": str(limit),
        "_": str(int(time.time() * 1000)),
    }
    try:
        time.sleep(random.randint(3, 8))          # pausa original (antes)
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(BASE_URL, params=params, headers=headers, timeout=30)
        time.sleep(random.randint(3, 8))          # pausa original (después)
        datos = response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[{dominio}] Error leaks: {e}", file=sys.stderr)
        return None

    if not isinstance(datos, list) or len(datos) <= 1:
        return None

    tech = set()
    for fila in datos[1:]:
        url_original = (fila[0] if fila else "").lower()
        if palabras_clave and not any(p.lower() in url_original for p in palabras_clave):
            continue
        if ".php" in url_original:
            tech.add("php")
        if "wp-admin" in url_original or "wp-content" in url_original:
            tech.add("wordpress")
        if "user/password" in url_original or "/sites/default/" in url_original:
            tech.add("drupal")
        if "/components/" in url_original:
            tech.add("joomla")
        if ".jsp" in url_original:
            tech.add("jsp")
    return " ".join(sorted(tech)) or None


def escanear_dominio(dominio_objetivo: str, consultar_shodan: bool = True,
                     consultar_leaks_flag: bool = False, usar_wayback: bool = True):
    """
    Punto de entrada para dominios.
    1) Subdominios en crt.sh + (opcional) Wayback Machine, UNIDOS y SIN repetidos.
    2) Resuelve cada uno a IP; los que no resuelven quedan con ip=None
       y NO se consultan en Shodan.
    3) (opcional) Shodan host público por cada IP única.

    usar_wayback=True suma los subdominios vistos por Wayback (deduplicados por
    host). Ponelo en False si querés ir más rápido y usar solo crt.sh.
    """
    dominio_objetivo = dominio_objetivo.strip().lower()
    dominio_objetivo = re.sub(r"^https?://", "", dominio_objetivo).strip("/")

    # --- Fuentes de subdominios, unificadas en un set (sin repetidos) ---
    subs_crt, error_crt = obtener_subdominios(dominio_objetivo)
    conjunto = set(subs_crt)
    if usar_wayback:
        conjunto |= subdominios_de_wayback(dominio_objetivo)
    subdominios = sorted(conjunto)

    resultados = []
    ips_consultadas = {}  # cache por IP para no repetir la consulta a Shodan
    total = len(subdominios)

    for i, sub in enumerate(subdominios, start=1):
        ip = resolver_ip(sub)
        print(f"[{dominio_objetivo}] {i}/{total}  {sub} -> {ip}", file=sys.stderr)

        if ip is None:
            shodan = None
        else:
            if ip not in ips_consultadas:
                ips_consultadas[ip] = consulta_a_shodan(ip) if consultar_shodan else None
            shodan = ips_consultadas[ip]

        tecnologia = consultar_leaks(sub) if consultar_leaks_flag else None

        entrada = {
            "subdominio": sub,
            "ip": ip,
            "shodan": shodan,
            "captura": None,
            "google": "https://www.google.com/search?q=site%3Aapi.urlscan.io%2Fresult+" + sub,
            "weymachine": "https://web.archive.org/web/*/" + sub + "/*",
            "tecnologia": tecnologia,
        }
        resultados.append(entrada)

    return {
        "dominio": dominio_objetivo,
        "total_subdominios_encontrados": len(subdominios),
        "resultados": resultados,
        # Si crt.sh falló, la UI muestra esto en vez de "no se encontraron subdominios"
        "advertencia": error_crt,
    }


def ips_del_rango(cidr: str, incluir_red_broadcast: bool = False):
    red = ip_network(cidr, strict=False)
    if incluir_red_broadcast:
        return [str(ip) for ip in red]
    return [str(ip) for ip in red.hosts()]


def obtener_urls_rapido(dominio, cantidad_resultados: int = 5):
    query = "site:api.urlscan.io/result+text:" + str(dominio)
    urls = []
    try:
        for url in search(query, num_results=cantidad_resultados, lang="es",
                          sleep_interval=random.uniform(3, 4)):
            urls.append(url)
    except (TypeError, ValueError):
        pass
    return urls


def scanear_ip(objetivo: str, consultar_shodan: bool = True):
    """Punto de entrada para IP suelta o rango CIDR."""
    objetivo = objetivo.strip()
    ips = []
    try:
        ip_objeto = ipaddress.ip_address(objetivo)
        ips.append(str(ip_objeto))
    except ValueError:
        try:
            ips = ips_del_rango(objetivo)
        except ValueError:
            return {
                "error": f"'{objetivo}' no es una IP, un rango CIDR ni un dominio válido.",
                "dominio": objetivo,
                "resultados": [],
            }

    resultados = []
    ips_consultadas = {}
    for ip in ips:
        if ip not in ips_consultadas:
            ips_consultadas[ip] = consulta_a_shodan(ip) if consultar_shodan else None
        entrada = {
            "subdominio": None,
            "ip": ip,
            "shodan": ips_consultadas[ip],
            "captura": None,
            "google": None,
            "weymachine": None,
            "tecnologia": None,
        }
        resultados.append(entrada)

    return {
        "dominio": objetivo,
        "total_subdominios_encontrados": None,
        "resultados": resultados,
    }
