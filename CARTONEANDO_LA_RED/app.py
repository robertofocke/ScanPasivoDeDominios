from flask import Flask, jsonify, render_template, request
import re
from recon import escanear_dominio
from recon import scanear_ip

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    # Permite subdominios y extensiones de hasta 24 caracteres
    PATRON_DOMINIO = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")
    data = request.get_json(silent=True) or {}
    objetivo = data.get("target") or "".strip()
    if not objetivo:
        return jsonify({"error": "Falta el campo 'target'."}), 400

    if PATRON_DOMINIO.fullmatch(objetivo) is not None:
        resultado = escanear_dominio(objetivo)
    else:
        resultado = scanear_ip(objetivo)
   
    return jsonify(resultado)


if __name__ == "__main__":
    # host=0.0.0.0 solo si necesitás acceder desde otra máquina en tu red
    app.run(debug=True, port=5000)
