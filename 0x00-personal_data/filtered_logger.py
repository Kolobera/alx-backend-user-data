#!/usr/bin/env python3
"""Filtered logger"""
import re
from typing import List
import logging


def filter_datum(fields: List[str], redaction: str,
                    message: str, separator: str) -> str:
        """Returns the log message obfuscated"""
        for field in fields:
            message = re.sub(f'{field}=.+?{separator}',
                                f'{field}={redaction}{separator}', message)
        return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str] = None):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filters values in incoming log records using filter_datum"""
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)
