"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

api = Blueprint('api', __name__)
app = Flask(__name__)
bcrypt = Bcrypt(app)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

# Registro: endpoint que reciba un nombre de usuario y clave, y lo registre en la base de datos
@api.route('/signup', methods=['POST'])
def singup():
    email=request.json.get("email")
    password=request.json.get("password")
    password_encryptado = bcrypt.generate_password_hash(password, rounds=None).decode("utf-8")
    newUser=User(email=email,password=password_encryptado,is_active=True)
    db.session.add(newUser)
    db.session.commit()
    response_body = {
        "message": "Usuario creado exitosamente"
    }

    return jsonify(response_body), 201
# Login: endpoint que reciba un nombre de usuario y clave, lo verifique en la base de datos y genere el token
@api.route('/login', methods=['POST'])
def login():
    email=request.json.get("email")
    password=request.json.get("password")
    newUser=User.query.filter_by(email=email).first()
    # Verificamos si el usuario existe, buscandolo por el correo
    if not newUser:
        return "Usuario o Password no encontrado", 401
    # Se valida si la clave que se recibio en la peticion es valida
    clave_valida=bcrypt.check_password_hash(newUser.password, password)
    if not clave_valida:
        raise APIException("Clave invalida", status_code=401)
    # Se genera un token y se retorna como respuesta
    token=create_access_token(email)
    return jsonify({"token":token}), 200


# Validar: endpoint que reciba un token y retorna si este es valido o no
