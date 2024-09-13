"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200






@api.route('/user', methods=['POST']) # Cuando alguien envia datos 
def add_user():
    body = request.json # Yo los recibo

    email = body.get("email",None)    # extraigo los datos del diccionario
    password = body.get("password",None)

    if email is None or password is None:     # valido lo que tenga que validad 
        return jsonify('You need the password and email', 400)
    else:
        user = User(email=email, password=password) # crea al usuario
        try:
            db.session.add(user)    # lo aniade a bd
            db.session.commit() 
            return jsonify({"message": "User created"}),201  # El entpoint response con un mensaje y su codigo de usuario creado
        
        except Exception as error:
            print(error.args)
            db.session.rollback()
            return jsonify({"message:"f"error : {error}"}), 500
        


@api.route("/users", methods=["GET"]) # consulta datos
@jwt_required() # decorador para proteger el entpoint  (para consultar se tiene que usar el token generado)
def get_all_users():
    user = User.query.get(get_jwt_identity()) 
    if(user.email == "elelyslugo@gmail.com"):
        user_all = User.query.all() # CONSULTA
        user_all = list(map(lambda item: item.serialize(),user_all)) 
        return jsonify(user_all),200
    else: 
        return jsonify({"Message": "No estas autorizado para ver esta informacion"}),401


@api.route("/login",methods=["POST"])
def login():
    body = request.json

    email  = body.get('email', None)
    password = body.get('password', None)

    if email is None or password is None: 
        return jsonify('You need the password and email', 400)
    
    else:
        user = User()
        user = user.query.filter_by(email=email).one_or_none()

        if user is None:
            return (jsonify({"message":"bad credentials"})), 400
        else:
            if user.password == password:
                token = create_access_token(identity=user.id)
                return jsonify({"token": token}),200
            else:
                return jsonify({"message": "bad access"}),400
