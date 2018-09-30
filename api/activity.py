"""
Manage user activities
"""
from typing import Dict, Union

from api.constants import *
from db.models import User, Activity
from logger import logger


def add_activity(activity: Dict, user: User) -> Union[int, None, Activity]:
    """
    Create new activity
    :param user: activity's user
    :param activity: an dict containing activity attributes
    :return: Acitiviy if successful, None if failed, 0 if data is empty
    """

    start_time = activity.get(START_TIME_KEY)
    end_time = activity.get(END_TIME_KEY)
    executable_name = activity.get(EXECUTABLE_KEY)
    browser_url = activity.get(BROWSER_URL_KEY)
    browser_title = activity.get(BROWSER_URL_KEY)
    ip_address = activity.get(IP_ADDRESS_KEY)
    mac_address = activity.get(MAC_ADDRESS_KEY)

    data = {
        START_TIME_KEY: start_time,
        EXECUTABLE_KEY: executable_name,
        END_TIME_KEY: end_time,
        BROWSER_URL_KEY: browser_url,
        BROWSER_TITLE_KEY: browser_title,
        IP_ADDRESS_KEY: ip_address,
        MAC_ADDRESS_KEY: mac_address,
    }
    for value in data.values():
        if not value:
            return 0
    try:
        activity = Activity(user=user, **data)
        activity.save()
        return activity
    except Exception as e:
        logger.exception(f'Failed to create Activity. Error: {e}')

    return None
