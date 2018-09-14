"""
DB models for Mongo
"""
from flask_login import UserMixin
from flask_security import RoleMixin
from mongoengine import StringField, ListField, ReferenceField, DateTimeField, BooleanField, Document


class Role(Document, RoleMixin):
    name = StringField(max_length=80, unique=True)
    description = StringField(max_length=255)


class User(Document, UserMixin):
    email = StringField(max_length=255)
    password = StringField(max_length=255)
    active = BooleanField(default=True)
    confirmed_at = DateTimeField()
    roles = ListField(ReferenceField(Role), default=[])



