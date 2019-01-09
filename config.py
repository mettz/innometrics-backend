"""
Read config from file
"""
from configparser import ConfigParser

import os

from api.constants import INNOMETRICS_PATH, INNOMETRICS_PRODUCTION

config = ConfigParser()
config_file_name = 'config_production.ini' if INNOMETRICS_PRODUCTION else 'config.ini'
config.read(os.path.join(INNOMETRICS_PATH, 'config.ini'))
