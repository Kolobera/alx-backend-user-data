#!/usr/bin/env python3
"""Filtered logger"""
import re
from typing import List


def filter_datum(fields: List[str], redaction: str,
                    message: str, separator: str) -> str:
        """Returns the log message obfuscated"""
        m_dict = {el.split("=")[0]:el.split("=")[1] for el in message.split(separator) if el != ""}
        for field in fields:
            message = re.sub(m_dict[field], redaction, message)
        return message
