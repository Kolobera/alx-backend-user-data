#!/usr/bin/env python3
""" Module for API authentication
"""
from flask import request
from typing import List, TypeVar
from auth import Auth


class BasicAuth(Auth):
    """ BasicAuth class
    """
    pass