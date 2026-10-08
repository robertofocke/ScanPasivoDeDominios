from flask import Flask, jsonify, render_template, request
import re
import sys
import traceback
from recon import escanear_dominio, scanear_ip

app = Flask(__name__)

# Permite subdominios y TLD de hasta 24 caracteres
PATRON_DOMINIO = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$"
)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    objetivo = (data.get("target") or "").strip()   # <-- se limpia SIEMPRE el target
    if not objetivo:
        return jsonify({"error": "Falta el campo 'target'."}), 400

    try:
        if PATRON_DOMINIO.fullmatch(objetivo):
            resultado = escanear_dominio(objetivo)
        else:
            resultado = scanear_ip(objetivo)
    except Exception as e:
        # Nunca dejamos que Flask devuelva la página HTML de error:
        # el frontend espera SIEMPRE JSON.
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": f"Fallo interno procesando '{objetivo}': {e}"}), 500

    # scanear_ip puede devolver un error controlado (CIDR/entrada inválida)
    if isinstance(resultado, dict) and resultado.get("error"):
        return jsonify(resultado), 400

    return jsonify(resultado)


if __name__ == "__main__":
    # host="0.0.0.0" solo si necesitás acceder desde otra máquina en tu red
    app.run(debug=True, port=5000)
