"""
API interface for Innometrics backend
"""
import json
from http import HTTPStatus

import bcrypt
import flask
from flask import Flask, make_response, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user

from api.activity import add_activity
from api.constants import *
from config import config
from db.models import User
from logger import logger
from utils import execute_function_in_parallel

app = Flask(__name__)
flask_config = config['FLASK']
app.secret_key = flask_config['SECRET_KEY']

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    """
    Load a user from DB
    :param user_id: an id of the user
    :return: User instance or None if not found
    """
    return User.objects(id=user_id).first()


def _hash_password(password: str) -> str:
    """
    Hash a password
    :param password: a password
    :return: hashed password
    """

    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def _check_password(plain_pass: str, encoded_pass: str) -> bool:
    """
    Check if two passwords are the same
    :param plain_pass: a first unhashed password
    :param encoded_pass: a hashed password to check with
    :return: True if they are same, False otherwise
    """

    return bcrypt.checkpw(plain_pass.encode(), encoded_pass.encode())


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login a user
    :return: flask.response
    """
    try:
        email = flask.request.form.get(EMAIL_KEY, type=str)
        password = flask.request.form.get(PASSWORD_KEY, type=str)

        if not (email and password):
            return make_response(jsonify({MESSAGE_KEY: 'Not enough data provides'}), HTTPStatus.BAD_REQUEST)

        existing_user = User.objects(email=email).first()
        if not existing_user:
            return make_response(jsonify({MESSAGE_KEY: 'User not found'}), HTTPStatus.BAD_REQUEST)
        if _check_password(password, existing_user.password):
            login_user(existing_user)
            return make_response(jsonify({MESSAGE_KEY: 'Success'}), HTTPStatus.OK)
        return make_response(jsonify({MESSAGE_KEY: 'Failed to authenticate'}), HTTPStatus.BAD_REQUEST)
    except Exception as e:
        logger.exception(f'Failed to login user. Error {e}')
        return make_response(jsonify({MESSAGE_KEY: 'Something bad happened'}), HTTPStatus.INTERNAL_SERVER_ERROR)


@app.route('/user', methods=['POST'])
def user_register():
    """
    Register a new user
    :return: flask.response
    """
    try:
        email = flask.request.form.get(EMAIL_KEY, type=str)
        password = flask.request.form.get(PASSWORD_KEY, type=str)
        name = flask.request.form.get(NAME_KEY, type=str)
        surname = flask.request.form.get(SURNAME_KEY, type=str)

        if not (email and password and name and surname):
            return make_response(jsonify({MESSAGE_KEY: 'Not enough data provides'}), HTTPStatus.BAD_REQUEST)

        existing_user = User.objects(email=email).first()
        if existing_user:
            return make_response(jsonify({MESSAGE_KEY: 'User already exists'}), HTTPStatus.BAD_REQUEST)

        user = User(email=email, password=_hash_password(password), name=name, surname=surname)
        if not user:
            return make_response(jsonify({MESSAGE_KEY: 'Failed to create user'}), HTTPStatus.INTERNAL_SERVER_ERROR)

        user.save()
        return make_response(jsonify({MESSAGE_KEY: 'Success'}), HTTPStatus.OK)
    except Exception as e:
        logger.exception(f'Failed to register user. Error {e}')
        return make_response(jsonify({MESSAGE_KEY: 'Something bad happened'}), HTTPStatus.INTERNAL_SERVER_ERROR)


@app.route('/user', methods=['DELETE'])
@login_required
def user_delete():
    """
    Delete a user
    :return: flask.response
    """
    try:
        current_user.delete()
    except Exception as e:
        logger.exception(f'Failed to delete user. Error {e}')
        return make_response(jsonify({MESSAGE_KEY: 'Failed to delete user'}), HTTPStatus.INTERNAL_SERVER_ERROR)

    return make_response(jsonify({MESSAGE_KEY: 'Success'}), HTTPStatus.OK)


@app.route("/logout")
@login_required
def logout():
    try:
        logout_user()
    except Exception as e:
        logger.exception(f'Failed to log out user. Error {e}')
    return make_response(jsonify({MESSAGE_KEY: 'Success'}), HTTPStatus.OK)


@app.route('/activity', methods=['POST'])
@login_required
def activity_add():
    """
    Add an activity
    :return: flask.response
    """
    activity_data = flask.request.form.get(ACTIVITY_KEY, type=str)

    try:
        activity_data = json.loads(activity_data)
    except Exception:
        return make_response(jsonify({MESSAGE_KEY: 'Wrong format'}), HTTPStatus.BAD_REQUEST)
    if ACTIVITIES_KEY in activity_data:
        #  Add multiple activities
        result = execute_function_in_parallel(add_activity, [(activity, current_user)
                                                             for activity in activity_data.get(ACTIVITIES_KEY, [])])
    else:
        result = add_activity(activity_data, current_user)
    if not result:
        return make_response(jsonify({MESSAGE_KEY: 'Failed to create activity'}),
                             HTTPStatus.INTERNAL_SERVER_ERROR)
    return make_response(jsonify({MESSAGE_KEY: 'Success'}), HTTPStatus.OK)


if __name__ == '__main__':
    app.run(port=flask_config['PORT'], threaded=True)
