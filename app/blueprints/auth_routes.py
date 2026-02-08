from flask import Blueprint, jsonify, request

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['POST'])
def login():
    # TODO: Implement user authentication
    return jsonify({"message": "Login (TODO)"}), 200

@auth_bp.route('/register', methods=['POST'])
def register():
    # TODO: Implement user registration
    return jsonify({"message": "Register (TODO)"}), 201
