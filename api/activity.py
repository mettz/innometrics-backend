"""
Manage user activities
"""
from typing import Dict, Union, Optional, List

from datetime import datetime
from dateutil import parser

from api.constants import *
from db.models import Activity
from logger import logger


def add_activity(activity: Dict, user: str) -> Union[int, None, str]:
    """
    Create new activity
    :param user: activity's user reference in DB
    :param activity: an dict containing activity attributes
    :return: Acitivity id if successful, None if failed, 0 if data is empty
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
        if value is None:
            return 0
    try:
        data[START_TIME_KEY] = parser.parse(start_time)
        data[END_TIME_KEY] = parser.parse(end_time)
    except Exception as e:
        #  Maybe timestamp
        try:
            start_time = start_time[:10]
            end_time = end_time[:10]
            data[START_TIME_KEY] = datetime.fromtimestamp(int(start_time))
            data[END_TIME_KEY] = datetime.fromtimestamp(int(end_time))
        except Exception as e:
            #  Can't recognise this datetime
            return 0

    try:
        activity = Activity(user=user, **data)
        activity.save()
        return str(activity.id)
    except Exception as e:
        logger.exception(f'Failed to create Activity. Error: {e}')

    return None


def delete_activity(activity_id: str) -> Optional[int]:
    """
    Delete an activity
    :param activity_id: an id of the activity
    :return: 1 if successful, None if failed, 0 if data is empty
    """
    if not activity_id:
        return 0
    activity = Activity.objects(id=activity_id).first()
    if not activity:
        return None

    try:
        activity.delete()
    except Exception as e:
        logger.exception(f'Failed to delete Activity. Error: {e}')

    return 1


def find_activities(user_id: str, start_time: datetime = None, end_time: datetime = None,
                    items_to_return: int = 100, offset: int = 0) -> Union[int, None, List[Activity]]:
    """
    Find activities of a user
    :param offset: an amount of activities to skip
    :param items_to_return: an amount of activities to return
    :param end_time: a filter for start time of activities
    :param start_time: a filter for end time of activities
    :param user_id: an id of the user
    :return: 1 if successful, None if failed, 0 if data is empty
    """
    if not user_id:
        return 0

    params = {
        USER_KEY: user_id,
    }
    if start_time:
        params[f'{START_TIME_KEY}_gte'] = start_time
    if end_time:
        params[f'{END_TIME_KEY}_lt'] = end_time

    try:
        activities = Activity.objects(**params).skip(offset).limit(items_to_return)
    except Exception as e:
        logger.exception(f'Failed to fetch Activities. Error: {e}')
        return None

    if not activities:
        return []

    return activities
