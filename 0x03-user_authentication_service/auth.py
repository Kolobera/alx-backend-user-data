#!/usr/bin/env python3
"""Authentication Module"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Returns a salted, hashed password, which is a byte string"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialization"""
        self._db = DB()
    
    def register_user(self, email: str, password: str) -> User:
        """hash the password with _hash_password, save the user 
        to the database using self._db and return the User object."""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email=email, hashed_password=hashed_password)
        if user is not None:
            raise ValueError(f"User {email} already exists")
