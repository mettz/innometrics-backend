from typing import Optional, Union, List

from api.activity import find_activities
from db.models import Project, User, Activity
from logger import logger


def create_new_project(name: str, creator: str) -> Optional[str]:
    """
    Create a new project
    :param name: a name of the project
    :param creator: a creator of the project
    :return: an id of the project
    """

    if not (name and creator):
        return None
    try:
        project = Project(name=name, managers=[creator])
        project.save()
        return str(project.id)
    except Exception as e:
        logger.exception(f'Failed to create Project. Error: {e}')

    return None


def invite_user(project_id: str, user_email: str, invitor: str, manager: bool = False) -> Optional[bool]:
    """
    Invite a user to the project
    :param manager: if a person invited for manager role
    :param invitor: an user reference to invitor
    :param project_id: an id of the project
    :param user_email: a user's email
    :return:
    """
    if not (project_id and user_email and invitor):
        return None

    project = Project.objects(id=project_id).first()
    if not project:
        return None

    if invitor not in project.managers:
        return None

    user = User.objects(email=user_email).first()
    if not user:
        return None

    if manager:
        if user.to_dbref() not in project.invited_managers:
            project.invited_managers.append(user.to_dbref())
    else:
        if user.to_dbref() not in project.invited_users:
            project.invited_users.append(user.to_dbref())

    project.save()

    return True


def accept_invitation(project_id: str, user: str) -> Optional[bool]:
    """
    Accept invitation to the project
    :param project_id: an id of the project were a user was invited
    :param user: a reference to the user
    :return:
    """
    if not (project_id or user):
        return None

    project = Project.objects(id=project_id).first()
    if not project:
        return None

    user_indeed_was_invited = False
    if user in project.invited_users and user not in project.users:
        project.users.append(user)
        user_indeed_was_invited = True

    if user in project.invited_managers and user not in project.managers:
        project.managers.append(user)
        user_indeed_was_invited = True

    project.save()
    return user_indeed_was_invited


def get_project_activities(project_id: str, user: str, **filters) -> Union[int, None, List[Activity]]:
    """
    Return activities of all users in a project
    :param project_id: an id of the project
    :param user: a reference to the user asking, should have a manager role
    :param filters: filters for find_activities method
    :return:
    """
    if not (project_id or user):
        return None

    project = Project.objects(id=project_id).first()
    if not project:
        return None

    if user not in project.managers:
        return None

    if not project.users:
        return []
    else:
        return find_activities(user_ids=project.users, **filters)


