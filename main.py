from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import requests
import datetime
import re

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import JWTManager
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required

app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "Clave-secreta-123"
jtw = JWTManager(app)


def load_file_config():
    with open("config.json") as f:
        return json.load(f)


@app.before_request
def before_request_callback():
    url = limpiar_url(request.path)
    excluded_routes = ["/login"]
    if url in excluded_routes:
        print("Ruta Excluida del middleware", url)
    else:
        if verify_jwt_in_request():
            usuario = get_jwt_identity()
            rol = usuario["rol"]
            if rol is not None:
                if not validar_permiso(url, request.method.upper(), rol["_id"]):
                    return jsonify({"message": "Permission denied"}), 401
            else:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401


def limpiar_url(url):
    partes = url.split("/")
    for p in partes:
        if re.search("\\d", p):
            url = url.replace(p, "?")

    return url


def validar_permiso(url, metodo, id_rol):
    config_data = load_file_config()
    url_seguridad = config_data["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + id_rol
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": url,
        "metodo": metodo
    }
    response = requests.post(url_seguridad, headers=headers, json=body)
    return response.status_code == 200


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/usuarios/validate"
    headers = {"Content-Type": "application/json; charset=utf-8"}
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Usuario o contraseña incorrecta"}), response.status_code


# Servicios para PARTIDOS

@app.route("/partidos", methods=["GET"])
def listar_partidos():
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/partidos"
    response = requests.get(url)
    return jsonify(response.json())


@app.route("/partido/<string:id>", methods=["GET"])
def mostrar_partido(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/partido/" + id
    response = requests.get(url)
    return jsonify(response.json())


@app.route("/partido", methods=["POST"])
def crear_partido():
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/partido"
    info_partido = request.get_json()
    response = requests.post(url, json=info_partido)
    return jsonify(response.json())


@app.route("/partido/<string:id>", methods=["PUT"])
def actualizar_partido(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/partido/" + id
    info_partido = request.get_json()
    response = requests.put(url, json=info_partido)
    return jsonify(response.json())


@app.route("/partido/<string:id>", methods=["DELETE"])
def eliminar_partido(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/partido/" + id
    response = requests.delete(url)
    return jsonify(response.json())


# Servicios para MESAS
@app.route("/mesas", methods=["GET"])
def listar_mesas():
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/mesas"
    response = requests.get(url)
    return jsonify(response.json())


@app.route("/mesa/<string:id>", methods=["GET"])
def mostrar_mesa(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/mesa/" + id
    response = requests.get(url)
    return jsonify(response.json())


@app.route("/mesa", methods=["POST"])
def crear_mesa():
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/mesa"
    info_mesa = request.get_json()
    response = requests.post(url, json=info_mesa)
    return jsonify(response.json())


@app.route("/mesa/<string:id>", methods=["PUT"])
def actualizar_mesa(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/mesa/" + id
    info_mesa = request.get_json()
    response = requests.put(url, json=info_mesa)
    return jsonify(response.json())


@app.route("/mesa/<string:id>", methods=["DELETE"])
def eliminar_mesa(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/mesa/" + id
    response = requests.delete(url)
    return jsonify(response.json())


# Servicios para CANDIDATOS
@app.route("/candidatos", methods=["GET"])
def listar_candidatos():
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/candidatos"
    response = requests.get(url)
    return jsonify(response.json())


@app.route("/candidato/<string:id>", methods=["GET"])
def mostrar_candidato(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/candidato/" + id
    response = requests.get(url)
    return jsonify(response.json())


@app.route("/candidato", methods=["POST"])
def crear_candidato():
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/candidato"
    info_candidato = request.get_json()
    response = requests.post(url, json=info_candidato)
    return jsonify(response.json())


@app.route("/candidato/<string:id>", methods=["PUT"])
def actualizar_candidato(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/candidato/" + id
    info_candidato = request.get_json()
    response = requests.put(url, json=info_candidato)
    return jsonify(response.json())


@app.route("/candidato/<string:id>", methods=["DELETE"])
def eliminar_candidato(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/candidato/" + id
    response = requests.delete(url)
    return jsonify(response.json())


# Servicios para RESULTADOS
@app.route("/resultados", methods=["GET"])
def listar_resultados():
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/resultados"
    response = requests.get(url)
    return jsonify(response.json())


@app.route("/resultado/<string:id>", methods=["GET"])
def mostrar_resultado(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/resultado/" + id
    response = requests.get(url)
    return jsonify(response.json())


@app.route("/resultado", methods=["POST"])
def crear_resultado():
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/resultado"
    info_resultado = request.get_json()
    response = requests.post(url, json=info_resultado)
    return jsonify(response.json())


@app.route("/resultado/<string:id>", methods=["PUT"])
def actualizar_resultado(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/resultado/" + id
    info_resultado = request.get_json()
    response = requests.put(url, json=info_resultado)
    return jsonify(response.json())


@app.route("/resultado/<string:id>", methods=["DELETE"])
def eliminar_resultado(id):
    config_data = load_file_config()
    url = config_data["url-backend-registraduria"] + "/resultado/" + id
    response = requests.delete(url)
    return jsonify(response.json())


# Servicios para USUARIOS

@app.route("/usuarios", methods=["GET"])
def listar_usuarios():
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/usuarios"
    response = requests.get(url)
    return jsonify(response.json()), 200


@app.route("/usuarios/<string:id>", methods=["GET"])
def mostrar_usuario(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/usuarios/" + id
    response = requests.get(url)
    return jsonify(response.json()), 200


@app.route("/usuarios", methods=["POST"])
def crear_usuario():
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/usuarios"
    info_usuario = request.get_json()
    response = requests.post(url, json=info_usuario)
    return jsonify(response.json()), 200


@app.route("/usuarios/<string:id>", methods=["PUT"])
def actualizar_usuario(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/usuarios/" + id
    info_usuario = request.get_json()
    response = requests.put(url, json=info_usuario)
    return jsonify(response.json()), 200


@app.route("/usuarios/<string:id>", methods=["DELETE"])
def eliminar_usuario(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/usuarios/" + id
    response = requests.delete(url)
    return jsonify(response.json()), 200


# Servicios para ROLES

@app.route("/roles", methods=["GET"])
def listar_roles():
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/roles"
    response = requests.get(url)
    return jsonify(response.json()), 200


@app.route("/roles/<string:id>", methods=["GET"])
def mostrar_rol(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/roles/" + id
    response = requests.get(url)
    return jsonify(response.json()), 200


@app.route("/roles", methods=["POST"])
def crear_rol():
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/roles"
    info_rol = request.get_json()
    response = requests.post(url, json=info_rol)
    return jsonify(response.json()), 200


@app.route("/roles/<string:id>", methods=["PUT"])
def actualizar_rol(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/roles/" + id
    info_rol = request.get_json()
    response = requests.put(url, json=info_rol)
    return jsonify(response.json()), 200


@app.route("/roles/<string:id>", methods=["DELETE"])
def eliminar_rol(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/roles/" + id
    response = requests.delete(url)
    return jsonify(response.json()), 200

# Servicios para PERMISOS

@app.route("/permisos", methods=["GET"])
def listar_permisos():
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos"
    response = requests.get(url)
    return jsonify(response.json()), 200


@app.route("/permisos/<string:id>", methods=["GET"])
def mostrar_permiso(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos/" + id
    response = requests.get(url)
    return jsonify(response.json()), 200


@app.route("/permisos", methods=["POST"])
def crear_permiso():
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos"
    info_permiso = request.get_json()
    response = requests.post(url, json=info_permiso)
    return jsonify(response.json()), 200


@app.route("/permisos/<string:id>", methods=["PUT"])
def actualizar_permiso(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos/" + id
    info_permiso = request.get_json()
    response = requests.put(url, json=info_permiso)
    return jsonify(response.json()), 200


@app.route("/permisos/<string:id>", methods=["DELETE"])
def eliminar_permiso(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos/" + id
    response = requests.delete(url)
    return jsonify(response.json()), 200

# Servicios para PERMISOS-ROLES

@app.route("/permisos-roles", methods=["GET"])
def listar_permisos_roles():
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos-roles"
    response = requests.get(url)
    return jsonify(response.json()), 200


@app.route("/permisos-roles/<string:id>", methods=["GET"])
def mostrar_permiso_rol(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos-roles/" + id
    response = requests.get(url)
    return jsonify(response.json()), 200


@app.route("/permisos-roles", methods=["POST"])
def crear_permiso_rol():
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos-roles"
    info_permiso_rol = request.get_json()
    response = requests.post(url, json=info_permiso_rol)
    return jsonify(response.json()), 200


@app.route("/permisos-roles/<string:id>", methods=["PUT"])
def actualizar_permiso_rol(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos-roles/" + id
    info_permiso_rol = request.get_json()
    response = requests.put(url, json=info_permiso_rol)
    return jsonify(response.json()), 200


@app.route("/permisos-roles/<string:id>", methods=["DELETE"])
def eliminar_permiso_rol(id):
    config_data = load_file_config()
    url = config_data["url-backend-security"] + "/permisos-roles/" + id
    response = requests.delete(url)
    return jsonify(response.json()), 200


if __name__ == '__main__':
    data_config = load_file_config()
    print(f"Server running: http://{data_config['url-backend']}:{data_config['port']}")
    serve(app, host=data_config["url-backend"], port=data_config["port"])
