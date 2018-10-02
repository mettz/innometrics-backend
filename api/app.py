"""
API interface for Innometrics backend
"""
import json
from http import HTTPStatus

import bcrypt
import flask
from apispec.ext.flask import FlaskPlugin
from apispec.ext.marshmallow import MarshmallowPlugin
from flask import Flask, make_response, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from apispec import APISpec

from api.activity import add_activity, delete_activity, find_activities
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

spec = APISpec(
    title='Innometrics backend API',
    version='1.0.0',
    plugins=(
        FlaskPlugin(),
        MarshmallowPlugin(),
    ),
    consumes=['multipart/form-data', 'application/x-www-form-urlencoded']
)


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
    ---
    get:
        summary: Login endpoint.
        description: Login a user with email.
        parameters:
            -   in: formData
                name: email
                description: an email of the user
                required: true
                type: string
            -   in: formData
                name: password
                required: true
                description: a password of the user
                type: string
        responses:
            400:
                description: Parameters are not correct
            404:
                description: User was not found
            401:
                description: Credentials provided are incorrect
    """
    try:
        email = flask.request.form.get(EMAIL_KEY, type=str)
        password = flask.request.form.get(PASSWORD_KEY, type=str)

        if not (email and password):
            return make_response(jsonify({MESSAGE_KEY: 'Not enough data provided'}), HTTPStatus.BAD_REQUEST)

        existing_user = User.objects(email=email).first()
        if not existing_user:
            return make_response(jsonify({MESSAGE_KEY: 'User not found'}), HTTPStatus.NOT_FOUND)
        if _check_password(password, existing_user.password):
            login_user(existing_user)
            return make_response(jsonify({MESSAGE_KEY: 'Success'}), HTTPStatus.OK)
        return make_response(jsonify({MESSAGE_KEY: 'Failed to authenticate'}), HTTPStatus.UNAUTHORIZED)
    except Exception as e:
        logger.exception(f'Failed to login user. Error {e}')
        return make_response(jsonify({MESSAGE_KEY: 'Something bad happened'}), HTTPStatus.INTERNAL_SERVER_ERROR)


@app.route('/user', methods=['POST'])
def user_register():
    """
    Register a user
    ---
    post:
        summary: User registration endpoint.
        description: Register a new user.
        parameters:
            -   in: formData
                name: email
                description: an email of the user
                required: true
                type: string
            -   in: formData
                name: name
                description: a name of the user
                required: true
                type: string
            -   in: formData
                name: surname
                description: a surname of the user
                required: true
                type: string
            -   in: formData
                name: password
                required: true
                description: a password of the user
                type: string
        responses:
            400:
                description: Parameters are not correct
            409:
                description: User with the email already exists
    """
    try:
        email = flask.request.form.get(EMAIL_KEY, type=str)
        password = flask.request.form.get(PASSWORD_KEY, type=str)
        name = flask.request.form.get(NAME_KEY, type=str)
        surname = flask.request.form.get(SURNAME_KEY, type=str)

        if not (email and password and name and surname):
            return make_response(jsonify({MESSAGE_KEY: 'Not enough data provided'}), HTTPStatus.BAD_REQUEST)

        existing_user = User.objects(email=email).first()
        if existing_user:
            return make_response(jsonify({MESSAGE_KEY: 'User already exists'}), HTTPStatus.CONFLICT)

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
    ---
    delete:
        summary: User deletion endpoint.
        description: Delete a user from DB.
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
    """
    Logout a user
    ---
    post:
       summary: User logout endpoint.
       description: Logout a user.
    """
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
    ---
    post:
        summary: Add an activity.
        description: Add an activity or multiple activities to the current user.
        parameters:
            -   name: activity_data
                in: formData
                required: true
                description: json containing all specified parameters
                type: json
            -   name: activities
                in: activity_data
                required: false
                type: list
                description: List containing activity_data
            -   name: start_time
                in: activity_data
                required: true
                type: datetime
                description: a start time of the activity
            -   name: end_time
                in: activity_data
                required: true
                type: datetime
                description: an end time of the activity
            -   name: executable_name
                in: activity_data
                required: true
                type: string
                description: a name of the current executable
            -   name: browser_url
                in: activity_data
                required: false
                type: string
                description: a url opened during the activity
            -   name: browser_title
                in: activity_data
                required: false
                type: string
                description: a title of the browsing window
            -   name: ip_address
                in: activity_data
                required: true
                type: string
                description: an ip address of the user
            -   name: mac_address
                in: activity_data
                required: true
                type: string
                description: an mac address of the user
        responses:
            400:
                description: Parameters are not correct
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

    return make_response(jsonify({MESSAGE_KEY: 'Success', ACTIVITY_ID_KEY: str(result.id)}), HTTPStatus.OK)


@app.route('/activity', methods=['DELETE'])
@login_required
def activity_delete():
    """
    Delete an activity
    ---
    delete:
        summary: Delete an activity.
        description: Delete a specific activity from current user's history.
        parameters:
            -   name: activity_id
                in: formData
                required: true
                type: integer
                description: an id of the activity
        responses:
            400:
                description: Parameters are not correct
            404:
                description: Activity with this id was not found
    """
    activity_id = flask.request.form.get(ACTIVITY_ID_KEY, type=str)

    if not activity_id:
        return make_response((jsonify({MESSAGE_KEY: 'Empty data'}, HTTPStatus.BAD_REQUEST)))

    result = delete_activity(activity_id)
    if result == 0:
        return make_response(jsonify({MESSAGE_KEY: 'Activity with this id was not found'}),
                             HTTPStatus.NOT_FOUND)
    if not result:
        return make_response(jsonify({MESSAGE_KEY: 'Failed to delete activity'}),
                             HTTPStatus.INTERNAL_SERVER_ERROR)

    return make_response(jsonify({MESSAGE_KEY: 'Success'}), HTTPStatus.OK)


@app.route('/activity', methods=['GET'])
@login_required
def activity_find():
    """
    Find activities
    ---
    delete:
        summary: Find activities.
        description: Find activities of current user.
        parameters:
            -   name: offset
                in: formData
                required: true
                type: integer
                description: a number of activities to skip
            -   name: amount_to_return
                in: formData
                required: true
                type: integer
                description: amount of activities to return, max is 1000
        responses:
            404:
                description: Activities were not found
    """
    offset = flask.request.form.get(OFFSET_KEY, type=int, default=0)
    amount_to_return = max(flask.request.form.get(AMOUNT_TO_RETURN_KEY, type=int, default=100), 1000)

    activities = find_activities(current_user.id, offset=offset, items_to_return=amount_to_return)
    if activities is None:
        return make_response(jsonify({MESSAGE_KEY: 'Failed to fetch activities'}),
                             HTTPStatus.INTERNAL_SERVER_ERROR)

    if not activities:
        return make_response(jsonify({MESSAGE_KEY: 'Activities of current user were not found'}),
                             HTTPStatus.NOT_FOUND)
    activities_list = [{k: str(v) for k, v in activity.to_mongo().items()} for activity in activities]

    return make_response(jsonify({MESSAGE_KEY: 'Success', ACTIVITIES_KEY: activities_list}), HTTPStatus.OK)


with app.test_request_context():
    views = [login, activity_add, activity_delete, activity_find, logout, user_delete, user_register]
    for view in views:
        spec.add_path(view=view)

if __name__ == '__main__':

    app.run(port=flask_config['PORT'], threaded=True)
