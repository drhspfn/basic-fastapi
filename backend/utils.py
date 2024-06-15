from datetime import timedelta
import json
from logging import Filter
import re
from typing import List, Union

SPECIAL_CHARACTERC = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?"

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


def mask_string(input_string: str, visible_percent: float = 0.2) -> str:
    """
    Masks the specified string with asterisks, leaving a specified percentage of the characters
    at the beginning and at the end visible.

    Parameters:
    ---------
        input_string (str): The input string to be masked.
        visible_percent (float, optional): The percentage of characters to leave unmasked. Defaults to 0.2.

    Returns:
    ---------
        str: The masked string with asterisks.

    Example:
    ---------
        >>> mask_string('password123')
        'pa******23'
    """

    total_length = len(input_string)
    visible_length_each_side = max(1, int(total_length * visible_percent / 2))
    
    start = input_string[:visible_length_each_side]
    end = input_string[-visible_length_each_side:]
    middle = '*' * (total_length - 2 * visible_length_each_side)
    return f"{start}{middle}{end}"


def is_valid_email(text: str) -> bool:
    """
    Email validity check.

    Args:
    ---------
        text (str): The email address to check.

    Returns:
    ---------
        bool: True if the email address is valid, False otherwise.
    """
    if len(text) >= 100:
        return False

    return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', text) is not None

def parse_time_string(time_str: str) -> timedelta:
    """
    Parses a string representing a time duration and converts it into a timedelta object.

    The input string can include the following units:
    - 'd': days
    - 'h': hours
    - 'm': minutes
    - 's': seconds
    - 'w': weeks

    Args:
    ---------
        time_str (str): The input string representing the time duration.

    Returns:
    ---------
        timedelta: A timedelta object representing the parsed time duration.

    Example:
    ---------
        >>> parse_time_string('1d2h3m4s')
        timedelta(days=1, seconds=7384)
        >>> parse_time_string('2w3d4h5m6s')
        timedelta(days=17, seconds=14706)
    """
    try:
        total_seconds = 0
        current_number = ''
        for char in time_str:
            if char.isdigit():
                current_number += char
            else:
                if char == 'd':
                    total_seconds += int(current_number) * 86400 
                elif char == 'h':
                    total_seconds += int(current_number) * 3600
                elif char == 'm':
                    total_seconds += int(current_number) * 60
                elif char == 's':
                    total_seconds += int(current_number)
                elif char == 'w':
                    total_seconds += int(current_number) * 604800

                current_number = ''

        return timedelta(seconds=total_seconds)
    except ValueError:
        raise Exception(f'Invalid date format: {time_str}. Valid format are: 1w1d2h30m40s')
    

def load_json(data: Union[str, bytes]) -> dict:
    """
    Loads JSON data from a string or bytes.

    This function takes a JSON data as a string or bytes, parses it into a Python dictionary,
    and returns the dictionary. If the input data is not a valid JSON string or bytes,
    the function returns None.

    Args:
    ---------
        data (Union[str, bytes]): The JSON data as a string or bytes.

    Returns:
    ---------
        dict: The JSON data as a dictionary. If the input data is not a valid JSON string or bytes,
        the function returns None.

    Raises:
    ---------
        json.decoder.JSONDecodeError: If the input data is not a valid JSON string or bytes.
        TypeError: If the input data is neither a string nor bytes.

    Example:
    ---------
        >>> load_json('{"name": "John", "age": 30}')
        {'name': 'John', 'age': 30}
        >>> load_json(b'{"name": "John", "age": 30}')
        {'name': 'John', 'age': 30}
        >>> load_json('invalid_json')
        None
        >>> load_json(12345)
        None
    """

    try:
        data = json.loads(data)
        if isinstance(data, str): 
            data = json.loads(data)
        return data
    except (json.decoder.JSONDecodeError, TypeError):
        return None
    
def check_password_strength(password: str) -> bool:
    """
    Checks the strength of the given password.

    Args:
        password (`str`): The password to check.

    Returns:
        `bool`: True if the password is strong, False otherwise.
   """
    if len(password) < 6:
        return False

    if not any(char.isupper() for char in password) or not any(char.islower() for char in password):
        return False

    if not any(char.isdigit() for char in password):
        return False

    if not any(char in SPECIAL_CHARACTERC for char in password):
        return False

    if len(set(password)) < len(password) / 2:
        return False

    return True
