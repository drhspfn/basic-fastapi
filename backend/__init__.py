from datetime import datetime, timezone
import json
import time
import os
import logging
from signal import SIGTERM
from typing import List, Literal, Tuple, Union
from configparser import ConfigParser

from backend.classes.models import RegistrationForm
from .classes.error import *
# from .classes.user import User
from .classes.sql import User
from .utils import SingletonMeta, InfoOrLowerFilter, check_password_strength, load_json, parse_time_string
from .modules.usercontroller import UserController
# from .modules.mongomanager import MongoManager
from .modules.sqlmanager import SQLManager
# from .modules.cache import Cache
from .modules.worker import Worker
from sqlalchemy.ext.asyncio import AsyncSession
__author__ = "drhspfn"
__email__ = "jenya.gsta@gmail.com"

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import bcrypt
import base64
from jose import jwt

from sqlalchemy import select


class Backend(metaclass=SingletonMeta):
    def __init__(self) -> None:
        self.__root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))
        try:
            ### ================================================================= ###
            ###
            self.worker = Worker(15)

            ### ================================================================= ###
            # Paths
            self.path_config = os.path.join(self.__root, "config.ini")
            self.logs_dir = os.path.join(self.__root, "logs")
            self.uvicorn_log_cfg = os.path.join(
                self.__root, "backend", "data", "uvicorn_logging.conf")
            # print((self.__root, self.uvicorn_log_cfg))
            if not os.path.exists(self.path_config):
                raise FileNotFoundError(
                    f"Config file not found: {self.path_config}")

            ### ================================================================= ###
            # Configuration
            self.config = ConfigParser()
            self.config.read(self.path_config)
            self.__debug = self.config.getboolean("server", "debug")
            self.__is_utc = self.config.getboolean("server", "utc_time")
            log_dir = self.config.get('server', 'log_path')
            if log_dir != "":
                if os.path.isabs(log_dir):
                    self.logs_dir = log_dir
                else:
                    self.logs_dir = os.path.abspath(
                        os.path.join(self.__root, log_dir))

            self._mongo_host = self.config.get("database", "host")
            self._mongo_port = self.config.getint("database", "port")
            self._mongo_username = self.config.get("database", "username")
            self._mongo_password = self.config.get("database", "password")
            self._mongo_database = self.config.get("database", "database")
            self._mongo_min_pool = self.config.getint("database", "min_pool")
            self._mongo_max_pool = self.config.getint("database", "max_pool")

            self.__cors_origins = self.config.get("cors", "origins")
            if self.__cors_origins != "":
                self.__cors_origins = [origin.strip()
                                       for origin in self.__cors_origins.split(",")]
            self.__cors_methods = self.config.get("cors", "methods")
            if self.__cors_methods != "*":
                self.__cors_methods = ", ".join(
                    [method.strip() for method in self.__cors_methods.split(",")])
            self.__secret = self.config.get("server", "secret_key")

            self.access_token_lifetime = self.config.get(
                "server", "token_access_expires")
            if self.access_token_lifetime == "":
                raise ValueError(
                    "The [server] [token_access_expires] field cannot be empty...")
            self.access_token_lifetime = parse_time_string(
                self.access_token_lifetime)

            self.refresh_token_lifetime = self.config.get(
                "server", "token_access_expires")
            if self.refresh_token_lifetime == "":
                raise ValueError(
                    "The [server] [token_refresh_expires] field cannot be empty...")
            self.refresh_token_lifetime = parse_time_string(
                self.refresh_token_lifetime)
            ### ================================================================= ###
            # Logging
            self._logger: logging.Logger = None
            self.__start_time = self.datenow
            self.init_logger()

            ### ================================================================= ###
            # MongoDB
            self.log("[STARTUP] Database Initialization...")
            self.database = SQLManager(
                host=self._mongo_host,
                port=self._mongo_port,
                username=self._mongo_username,
                password=self._mongo_password,
                database=self._mongo_database,
            )
            self.log("[STARTUP] Database Initialization. Successful!")
            # self.database = MongoManager(
            #     host=self._mongo_host,
            #     port=self._mongo_port,
            #     username=self._mongo_username,
            #     password=self._mongo_password,
            #     database=self._mongo_database,
            #     min_pool_size=self._mongo_min_pool,
            #     max_pool_size=self._mongo_max_pool
            # )

            ### ================================================================= ###
            # User Controller
            self.user_controller = UserController(backend=self)

            ### ================================================================= ###
            # Tokens
            self._blacklisted_tokens = {}
            self.__cipher_key = self.__secret.ljust(32)[:32].encode()
            self.__cipher = Cipher(algorithms.AES(
                self.__cipher_key), modes.ECB(), backend=default_backend())

            self.__private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.__public_key = self.__private_key.public_key()
            self.__public_key_bytes = self.__public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            self.__private_key_bytes = self.__private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.log('[STARTUP] Token system initialized.')
        except Exception as e:
            self._error_shutdown(e)

    @property
    def debug_mode(self) -> bool:
        return self.__debug

    @property
    def cors_origins(self) -> List[str]:
        return self.__cors_origins

    @property
    def cors_methods(self) -> str:
        return self.__cors_methods

    @property
    def public_key(self) -> bytes:
        return self.__public_key_bytes

    @property
    def logger(self) -> logging.Logger:
        if self._logger is None:
            self._logger = logging.getLogger(__name__)
        return self._logger

    def fromtimestamp(self, timestamp: float, in_utc:bool=False) -> datetime:
        if self.__is_utc is True or in_utc is True:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        else:
            return datetime.fromtimestamp(timestamp)

    def log(self, msg: object, *args: object, level: Union[int, str] = logging.INFO):
        """
        Logs a message with the specified level.

        This method logs a message with the given level and arguments. If the level is provided as a string,
        it is converted to its corresponding integer value using the logging._nameToLevel dictionary.

        Parameters:
            msg (object): The message to be logged. It can be a string or any other object that can be converted to a string.
            *args (object): Additional arguments to be formatted into the message.
            level (int | str, optional): The log level. It can be an integer value or a string representation of the log level. The default value is `logging.INFO`.

        Returns:
            None
        """
        if isinstance(level, str):
            level = logging._nameToLevel.get(level, logging.INFO)
        self._logger.log(level, msg, *args)

    def _error_shutdown(self, error: Exception, startup: bool = True) -> None:
        """
        This method handles the server shutdown process in case of an error.

        Parameters:
            error (Exception): The exception that caused the server to crash.
            startup (bool, optional): A flag indicating whether the server is in startup mode. Default is `True`.

        Returns:
            None

        This method logs the error details, sends a shutdown signal to the server process, and waits for 2 seconds before exiting.
        If the server is in startup mode, it logs a failure message and suggests checking the error log.
        Otherwise, it logs a crash message and suggests checking the error log.
        """

        self._logger.exception(error)
        if startup is True:
            self.log("Failed to initialize: %s", str(
                error), level=logging.CRITICAL)
            self.log("The server's startup failed. Check `error.log`.",
                     level=logging.CRITICAL)
        else:
            self.log("Server crash: %s", str(error), level=logging.CRITICAL)
            self.log("The server went down. Check `error.log`.",
                     level=logging.CRITICAL)
        time.sleep(2)
        os.kill(os.getpid(), SIGTERM)

    def init_logger(self, reload: bool = False):
        """
        Initializes the logger for the server.

        This method sets up the logging configuration based on the server's debug mode and UTC time settings.
        It creates separate log files for different log levels (info, debug, error) and writes logs to the console.

        Parameters:
            reload (bool, optional): A flag indicating whether to reload the logger. If True, the existing logger will be replaced. Default is `False`.

        Returns:
            None
        """

        if self._logger is None or reload is True:
            # Initialize the logger
            self._logger = logging.getLogger(__name__)

            # Set the logging level based on debug mode
            if self.__debug:
                self._logger.setLevel(logging.DEBUG)
            else:
                self._logger.setLevel(logging.INFO)

            # Define log formatters
            formatter = logging.Formatter(
                '%(levelname)-9s:     %(asctime)s | %(message)s',
                datefmt='%H:%M:%S'
            )
            if self.__debug:
                debug_no_level_formatter = logging.Formatter(
                    '%(asctime)s | %(message)s',
                    datefmt='%H:%M:%S'
                )

            # Create the logs directory if it doesn't exist
            self.log_path = os.path.join(
                self.logs_dir, self.__start_time.strftime('%Y-%m-%d'))
            os.makedirs(self.log_path, exist_ok=True)

            # Set up console handler
            console_handler = logging.StreamHandler()

            file_handler_info = logging.FileHandler(
                f'{self.log_path}/info.log', encoding='utf-8')
            file_handler_info.setLevel(logging.INFO)
            file_handler_info.setFormatter(formatter)
            file_handler_info.addFilter(InfoOrLowerFilter(logging.WARNING))

            file_handler_error = logging.FileHandler(
                f'{self.log_path}/error.log', encoding='utf-8')
            file_handler_error.setLevel(logging.ERROR)
            file_handler_error.setFormatter(formatter)

            if self.__debug:
                file_handler_debug = logging.FileHandler(
                    f'{self.log_path}/debug.log', encoding='utf-8')
                file_handler_debug.setLevel(logging.DEBUG)
                file_handler_debug.setFormatter(debug_no_level_formatter)
                file_handler_debug.addFilter(InfoOrLowerFilter(logging.DEBUG))

            file_handler_access = logging.FileHandler(
                f'{self.log_path}/access.log', encoding='utf-8')
            file_handler_access.setLevel(logging.INFO)
            file_handler_access.setFormatter(formatter)

            self._uvicorn_access = logging.getLogger('uvicorn.access')
            self._uvicorn_access.setLevel(logging.INFO)

            self._uvicorn_logger = logging.getLogger('uvicorn.error')
            self._uvicorn_logger.setLevel(logging.INFO)

            self._uvicorn_logger.addHandler(console_handler)
            self._uvicorn_logger.addHandler(file_handler_info)
            self._uvicorn_logger.addHandler(file_handler_error)
            self._uvicorn_access.addHandler(file_handler_error)
            self._uvicorn_access.addHandler(file_handler_access)
            # self._uvicorn_access.addHandler(console_handler) # Uncomment if you want to output access log to console
            self._logger.addHandler(file_handler_info)
            self._logger.addHandler(console_handler)
            self._logger.addHandler(file_handler_error)
            if self.__debug:
                self._logger.addHandler(file_handler_debug)

            console_handler.setFormatter(formatter)

    ### ================================================================= ###
    ### ================================================================= ###
    ### ================================================================= ###
    # Access keys
    def generate_token(self, payload: dict) -> str:
        """
        Generates a JWT token with the provided payload.

        Parameters:
        -----------
        payload (dict): A dictionary containing the data to be encoded in the JWT token.
                        It should contain a 'type' key, which will be set to 'unknown' if not provided.

        Returns:
        -----------
            str: The generated JWT token as a string.

        Note:
        -----------
            The JWT token is generated using the HS256 algorithm with the server's secret key.
        """
        if not 'type' in payload:
            payload['type'] = "unknown"

        return jwt.encode(payload, self.__secret, algorithm="HS256")

    def generate_access(self, user: User) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        """
        Generates access and refresh tokens for a given user.

        Parameters:
        ------------
            user (User): The user object for whom the tokens are being generated.

        Returns:
        ------------
            Tuple[str, str]: A tuple containing the access token and refresh token.

        Note:
        -----------
            The access token is used for authenticating API requests and has a limited lifetime.
            The refresh token is used to generate new access tokens when the current access token expires.
            The tokens are generated using the provided user's email, username, and ID.
            The tokens are encoded using a secret key and have an expiration time based on the server's configuration.
        """

        time_now = self.datenow
        access_payload = {
            'email': user.email,
            'sub': user.username,
            'id': user.id,
            'type': 'access',
            'exp': time_now + self.access_token_lifetime
        }
        refresh_payload = {
            'email': user.email,
            'sub': user.username,
            'id': user.id,
            'type': 'refresh',
            'exp': time_now + self.access_token_lifetime
        }
        access_token = (self.generate_token(
            access_payload), access_payload["exp"])
        refresh_token = (self.generate_token(
            refresh_payload), refresh_payload["exp"])
        return access_token, refresh_token

    def _check_token(self, token: str) -> bool:
        """
        Check if the token is blocked/revoked.

        This method checks if a given token is present in the list of blacklisted tokens.
        Blacklisted tokens are tokens that have been revoked or blocked for some reason.

        Parameters:
        -----------
            token (str): The token to be checked.

        Returns:
        -----------
            bool: True if the token is blacklisted, False otherwise.

        Note:
        -----------
            This method should be called before processing any request that uses the given token.
            If the token is blacklisted, the request should be rejected or handled accordingly.
        """
        return token in self._blacklisted_tokens

    def decode_token(self, token: str, token_type: Literal['access', 'refresh', 'activate', None] = 'access') -> dict:
        """
        Decodes a JWT token and verifies its type and expiration.

        Parameters:
        -----------
            token (str): The JWT token to be decoded.
            token_type (Literal['access', 'refresh', 'activate', None], optional): The expected type of the token. Default is 'access'.

        Returns:
        -----------
            dict: A dictionary containing the decoded token data.

        Raises:
        -----------
            TokenRevoked: If the token is found in the list of blacklisted tokens.
            TokenExpired: If the token has expired.
            InvalidAccessToken: If the token type is 'access' and does not match the expected type.
            InvalidRefreshToken: If the token type is 'refresh' and does not match the expected type.
            InvalidActivateToken: If the token type is 'activate' and does not match the expected type.
            InternalServerError: If the token type is not recognized.
        """

        def raise_token(ttype: str) -> Exception:
            if ttype == "access":
                raise InvalidAccessToken()
            elif ttype == "refresh":
                raise InvalidRefreshToken()
            elif ttype == "activate":
                raise InvalidActivateToken()
            else:
                raise InternalServerError()

        try:
            if self._check_token(token):
                raise TokenRevoked()

            token_data = jwt.decode(token, self.__secret, algorithms=["HS256"])
            if not token_data or (token_type is not None and ((not 'type' in token_data) or (token_data['type'] != token_type))):
                raise_token(token_type)

            return token_data
        except ExpiredSignatureError:
            raise TokenExpired()
        except JWTError:
            raise_token(token_type)

    ### ================================================================= ###
    ### ================================================================= ###
    ### ================================================================= ###

    def encrypt(self, data: str) -> Union[str, None]:
        """
        Encryption function using a secret key

        Args:
            data (str): Data to be encrypted

        Returns:
            Union[str, None]: Base64 encoded and URL safe encrypted string or None if an error occurred
        """
        try:
            encryptor = self.__cipher.encryptor()
            data = data + " " * (16 - len(data) % 16)
            encrypted_data = encryptor.update(
                data.encode()) + encryptor.finalize()
            base64_data = base64.b64encode(encrypted_data).decode()
            return base64_data.replace('/', '_')
        except Exception as e:
            self.log('[ENCRYPT]: %s', str(e), logtype=logging.CRITICAL)
            return None

    def decrypt(self, data: str) -> Union[str, None]:
        """
        Decrypts a given encrypted data string using the secret key.

        Parameters:
        -----------
            data (str): The encrypted data as a base64 string. The string should be URL safe, with underscores (_) replaced by slashes (/).

        Returns:
        -----------
            Union[str, None]: The decrypted data as a string. If decryption fails, the function returns None.

        Note:
        -----------
            The decryption process involves decoding the base64 string, decrypting the data using the secret key, and then decoding the decrypted data from bytes to a string.
            If any error occurs during the decryption process, the function returns None.
        """
        try:
            data = data.replace('_', '/')
            encrypted_data = base64.b64decode(data)
            decryptor = self.__cipher.decryptor()
            decrypted_data = decryptor.update(
                encrypted_data) + decryptor.finalize()
            return decrypted_data.decode().rstrip()
        except:
            return None

    def encrypt_public(self, message: Union[str, dict]) -> str:
        """
        Encrypts a message with the public key using the RSA-OAEP-SHA256 algorithm.

        Args:
        -----------
            message (str): The message to be encrypted. It should be a string.

        Returns:
        -----------
            str: The encrypted message as a base64-encoded string.

        Note:
        -----------
            This method assumes that the public key of the server is available and properly configured.

            This method uses the public key of the server to encrypt the given message.
            The encryption process uses the RSA-OAEP-SHA256 algorithm with the MGF1-SHA256 mask function.
            The encrypted message is then base64-encoded and returned as a string.
        """
        if isinstance(message, dict):
            message = json.dumps(message)

        encrypted_message = self.__public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_message).decode('utf-8')

    def decrypt_public(self, message: str) -> Union[str, None]:
        """
        Decrypts a message encrypted with a public key.

        Args:
        -----------
            message (str): The encrypted message as a base64-encoded string.

        Returns:
        -----------
            Union[str, None]: Decrypted message as a string. If decryption fails, return None.

        Note:
        -----------
            This method uses the private key of the server to decrypt the given message.
            The decryption process uses the RSA-OAEP-SHA256 algorithm with the MGF1-SHA256 mask function.
            The decrypted message is then
        """
        try:
            encrypted_message = base64.b64decode(message)
            encrypted_message = self.__private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_message.decode('utf-8')
        except Exception as e:
            self.log(f'[Security] [D-P] -> {str(e)}', logtype=logging.ERROR)
            return None

    def decrypt_body_json_data(self, encrypted_data: bytes) -> Union[dict, None]:
        """
        Decrypts the login data provided in bytes format.

        This function takes the encrypted login data as input, decrypts it using the server's private key,
        and then parses the decrypted data into a dictionary.

        Args:
        -----------
            encrypted_data (bytes): The encrypted login data. This should be a bytes object.

        Returns:
        -----------
            Union[dict, None]: The decrypted login data as a dictionary. If decryption or parsing fails, this function returns None.

        Note:
        -----------
            This function assumes that the server's private key is properly configured and accessible.
            It also assumes that the encrypted data is in the correct format and can be decrypted successfully.
        """
        if isinstance(encrypted_data, bytes):
            encrypted_data = encrypted_data.decode('utf-8')

        encrypted_data = self.decrypt_public(encrypted_data)
        encrypted_data = load_json(str(encrypted_data))
        return encrypted_data
    ### ================================================================= ###
    ### ================================================================= ###
    ### ================================================================= ###

    async def _check_password(self, input_password: str, hashed_password: str):
        return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password.encode('utf-8'))

    async def _check_login(self, session: AsyncSession,
                           email: str = None, username: str = None) -> bool:
        stmt = select(User).where(
            (User.username == username) | (User.email == email)
        )
        result = await session.execute(stmt)
        result: User = result.scalars().first()
        if result:
            if result.username == username:
                raise UserAlreadyExists(username=username)
            elif result.email == email:
                raise UserAlreadyExists(email=email)

        return False

    def _generate_salt(self) -> str:
        return bcrypt.gensalt().decode('utf-8')

    def _hash_password(self, password: str) -> str:
        salt = self._generate_salt()
        hashed_password = bcrypt.hashpw(password.encode(
            'utf-8'), salt.encode('utf-8')).decode('utf-8')
        return hashed_password

    async def register_user(self, data: 'RegistrationForm',
                            session: AsyncSession) -> User:
        if not check_password_strength(data.password):
            raise WeakPasswordError()

        await self._check_login(email=data.email,
                                username=data.username,
                                session=session)

        hashed_password = self._hash_password(data.password)
        user = await self.user_controller.add_user(email=data.email,
                                                   password=hashed_password,
                                                   username=data.username,
                                                   session=session)

        return user

    async def authenticate_user(self, login: str, password: str, session: AsyncSession):
        if password is None or login is None:
            return None

        user = await self.user_controller.get_by(login=login, session=session)
        if user:
            if await self._check_password(input_password=password,
                                          hashed_password=user.password):
                time_now = self.datenow

                if (user.access_token and time_now > self.fromtimestamp(user.access_token_expires)) \
                        or (not user.access_token or not user.refresh_token):
                    tokens = self.generate_access(user)
                    user.access_token = tokens[0][0]
                    user.access_token_expires = tokens[0][1]

                    if (user.refresh_token and time_now) > self.fromtimestamp(user.refresh_token_expires):
                        user.refresh_token = tokens[1][0]
                        user.refresh_token_expires = tokens[1][1]

                    session.add(user)
                    await session.commit()
                return user

        return None
    ### ================================================================= ###
    ### ================================================================= ###
    ### ================================================================= ###

    @property
    def datenow(self) -> datetime:
        """
        Returns the current date and time based on the server's UTC time setting.

        If the server's UTC time setting is True, the returned datetime object will have the timezone set to UTC. Otherwise, will have the timezone set to the local timezone.

        Parameters:
            None

        Returns:
            datetime: The current date and time based on the server's UTC time setting.
        """
        date = datetime.now()
        if self.__is_utc is True:
            date = date.replace(tzinfo=timezone.utc)
        return date
