from typing import Any
from typing import Optional
import jwt
from flask import Flask  
from flask import render_template
from flask import json
from flask import jsonify
from flask import request
from flask import g
from flask import Response

from flask_jwt_extended.config import config
from flask_jwt_extended.internal_utils import get_jwt_manager
from flask_jwt_extended.typing import ExpiresDelta
from flask_jwt_extended.typing import Fresh
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

                                                                                                                                       
app = Flask(__name__)

# Configuration du module JWT
app.config["JWT_SECRET_KEY"] = "Ma_clé_secrete"
jwt = JWTManager(app)

@app.route('/')
def hello_world():
    return render_template('formulaire.html')

# Création d'une route qui vérifie l'utilisateur et retourne un Jeton JWT si ok.
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", None)
    password = request.form.get("password", None)
    role = request.form.get("role", "user")  # Récupération du rôle, par défaut "user"
    
    if not username or not password:
        return jsonify({"msg": "Nom d'utilisateur et mot de passe requis"}), 400

    access_token = create_access_token(identity=username, additional_claims={"role": role}, expires_delta=False)
    
    response = make_response(jsonify({"msg": "Connexion réussie"}))
    response.set_cookie("access_token", access_token, httponly=True)
    return response

# Route protégée par un jeton valide
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Middleware pour vérifier le rôle de l'utilisateur
def role_required(required_role):
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") != required_role:
                return jsonify({"msg": "Accès interdit : rôle insuffisant"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# Route accessible uniquement aux administrateurs
@app.route("/admin", methods=["GET"])
@role_required("admin")
def admin():
    return jsonify({"msg": "Bienvenue sur la page admin"}), 200

if __name__ == "__main__":
    app.run(debug=True)
