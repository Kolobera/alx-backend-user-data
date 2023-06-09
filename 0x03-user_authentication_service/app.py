#!/usr/bin/env python3
"""App Module"""
from flask import Flask, jsonify, request, abort, make_response, redirect
from auth import Auth


AUTH = Auth()
app = Flask(__name__)


@app.route('/', strict_slashes=False)
def index():
    """returns message"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """register user"""
    email = request.form.get("email")
    password = request.form.get('password')
    if email is None or password is None:
        return None
    try:
        AUTH.register_user(email=email, password=password)
        return jsonify({"email": f"{email}",
                        "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """log the user in by:
        - creating a new session
        - send the session Id on the response as an HTTP header
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if email is None or password is None:
        return None
    if AUTH.valid_login(email, password):
        SID = AUTH.create_session(email)
        if not SID:
            abort(401)
        res = make_response(
            jsonify({"email": email, "message": "logged in"}), 200)
        res.set_cookie("session_id", SID)
        return res
    else:
        abort(401)


@app.route('/sessions', methods=['DELETE'])
def logout():
    """Log out method
    """
    sidCocks = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(sidCocks)
    if user is None:
        abort(403)
    else:
        AUTH.destroy_session(user.id)
        return redirect("/")


@app.route('/profile', methods=['GET'])
def profile():
    """gets user profile
    """
    SID = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(SID)
    if user is None:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    """resets password and get token
    """
    email = request.form.get('email')
    if email is None:
        abort(403)
    try:
        token = AUTH.get_reset_password_token(email)
    except Exception as e:
        abort(403)
    return jsonify({"email": email, "reset_token": token}), 200


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """updates password
    """
    email = request.form.get('email')
    token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    if email is None or token is None or new_password is None:
        abort(403)
    try:
        AUTH.update_password(token, new_password)
        return jsonify({"email": email, "message": "Password updated"})
    except Exception as e:
        abort(403)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000')
