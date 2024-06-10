from logging import Filter
import re
from typing import List


class SingletonMeta(type):
    """
    A metaclass for implementing the Singleton pattern.
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class InfoOrLowerFilter(Filter):
    """Filter class that filters log messages based on level number.

   Args:
       levelno (int): The maximum level number to include in the filter.

   Methods:
       filter(record): Filters a log record based on level number.
   """

    def __init__(self, levelno: int):
        super().__init__()
        self.levelno = levelno

    def filter(self, record) -> bool:
        """Filters a log record based on level number.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True if the record's level number is less than or equal to
            self.levelno, False otherwise.
       """
        return record.levelno <= self.levelno


def filter_dictionary(data: dict, fields: List[str]) -> dict:
    """
    A function that filters the `data` dictionary, leaving only the specified fields from the `fields` list.

    :param data: The dictionary you want to filter.
    :param fields: List of keys to be left behind. Supports nested keys using dot notation (e.g., 'user.name').
    :return: A filtered dictionary with values only for the specified keys.
    """
    filtered = {}
    for field in fields:
        nested_fields = field.split('.')
        value = data
        for nested_field in nested_fields:
            value = value.get(nested_field)
            if value is None:
                break
        if value is not None:
            # Create nested dictionaries if necessary
            current_dict = filtered
            for nested_field in nested_fields[:-1]:
                current_dict = current_dict.setdefault(nested_field, {})
            # Set the value for the last nested key
            current_dict[nested_fields[-1]] = value
    return filtered


def validate_dict(data: dict, keys: dict) -> bool:
    """
    A function that checks whether the `data` dictionary contains all keys and corresponding types from `keys`.

    :param data: A dictionary to check.
    :param keys: Dictionary of keys and corresponding types.
    :return: True if the dictionary contains all keys and corresponding types, and False otherwise.
    """
    for key, value_type in keys.items():
        if key not in data:
            # print(f"Missing key: {key}")
            return False
        if not isinstance(data[key], value_type):
            # print(f"Invalid type for key {key}. Expected {value_type}, got {type(user_data[key])}")
            return False
    return True


def mask_string(input_string: str) -> str:
    """
    Masks the specified string with asterisks.

    Parameters:
        input_string (str): The input string to be masked.

    Returns:
        str: The masked string with asterisks.

    Example:
        >>> mask_string('password123')
        >>> '***********'
    """
    return '*' * len(input_string)


def is_valid_email(text: str) -> bool:
    """
        Email validity check.

        Args:
            text (str): The email address to check.

        Returns:
            bool: True if the email address is valid, False otherwise.
    """
    if len(text) >= 100:
        return False

    return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', text) is not None
