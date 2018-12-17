"""
Manage user activities
"""
from typing import Dict, Union, Optional, List

from datetime import datetime
from dateutil import parser
from mongoengine.errors import InvalidQueryError, LookUpError as LookUpErrorMongo

from api.constants import *
from db.models import Activity
from logger import logger


def add_activity(activity: Dict, user: str) -> Union[int, None, str]:
    """
    Create new activity
    :param user: activity's user reference in DB
    :param activity: an dict containing activity attributes
    :return: Activity id if successful, None if failed, 0 if data is empty
    """

    ALL_FIELDS = [START_TIME_KEY, END_TIME_KEY, EXECUTABLE_KEY, BROWSER_TITLE_KEY, BROWSER_URL_KEY,
                  IP_ADDRESS_KEY, MAC_ADDRESS_KEY, IDLE_ACTIVITY_KEY, ACTIVITY_TYPE_KEY]
    COMPULSORY_FIELDS = [START_TIME_KEY, END_TIME_KEY, EXECUTABLE_KEY]
    data = {}
    for field in ALL_FIELDS:
        data[field] = activity.get(field)

    start_time = activity.get(START_TIME_KEY)
    end_time = activity.get(END_TIME_KEY)

    for key, value in data.copy().items():
        if value is None and key in COMPULSORY_FIELDS:
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
                    items_to_return: int = 100, offset: int = 0,
                    filters: Dict = {}) -> Union[int, None, List[Activity]]:
    """
    Find activities of a user
    :param filters: a dict with filter for data
    :param offset: an amount of activities to skip
    :param items_to_return: an amount of activities to return
    :param end_time: a filter for start time of activities
    :param start_time: a filter for end time of activities
    :param user_id: an id of the user
    :return: 1 if successful, None if failed, 0 if data is empty, -1 if request is bad
    """
    if not user_id:
        return 0

    params = {
        USER_KEY: user_id,
        **filters,
    }

    if start_time:
        params[f'{START_TIME_KEY}__gte'] = start_time
    if end_time:
        params[f'{END_TIME_KEY}__lt'] = end_time

    try:
        activities = Activity.objects(**params).skip(offset).limit(items_to_return)
        if not activities:
            return []

        return activities
    except InvalidQueryError:
        return -1
    except (Exception, InvalidQueryError, LookUpErrorMongo) as e:
        logger.exception(f'Failed to fetch Activities. Error: {e}')
        return None

