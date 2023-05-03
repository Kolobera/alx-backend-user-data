#!/usr/bin/env python3
""" Module for Session authentication
"""
from .auth import Auth
from models.user_session import UserSession
from uuid import uuid4


class SessionAuth(Auth):
    """SessionAuth class"""
    pass
