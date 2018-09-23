"""
Read config from file
"""
from configparser import ConfigParser

import os

from api.constants import INNOMETRICS_PATH

config = ConfigParser()
config.read(os.path.join(INNOMETRICS_PATH, 'config.ini'))
