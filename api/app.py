"""
API interface for Innometrics backend
"""
from configparser import ConfigParser
from http import HTTPStatus

import os
from flask import Flask, make_response, jsonify
from flask_mongoengine import MongoEngine
from flask_security import Security, MongoEngineUserDatastore, login_required
from api.constants import INNOMETRICS_PATH, MESSAGE_KEY
from db.models import User, Role

config = ConfigParser()
config.read(os.path.join(INNOMETRICS_PATH, 'config.ini'))

app = Flask(__name__)
flask_config = config['FLASK']
mongo_config = config['MONGO']

app.config['DEBUG'] = flask_config['DEBUG']
app.config['SECRET_KEY'] = flask_config['SECRET_KEY']
app.config['SECURITY_PASSWORD_SALT'] = flask_config['SECURITY_PASSWORD_SALT']

app.config['MONGODB_DB'] = mongo_config['MONGODB_DB']
app.config['MONGODB_HOST'] = mongo_config['MONGODB_HOST']
app.config['MONGODB_PORT'] = int(mongo_config['MONGODB_PORT'])

# Create database connection object
db = MongoEngine(app)

user_datastore = MongoEngineUserDatastore(db, User, Role)
security = Security(app, user_datastore)


@login_required
def test_login():
    return make_response(jsonify({MESSAGE_KEY: 'Success'}), HTTPStatus.OK)


if __name__ == '__main__':
    app.run(port=flask_config['PORT'], threaded=True)
