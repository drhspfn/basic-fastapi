from datetime import datetime, timezone
import time
import os
import logging
from signal import SIGTERM
from typing import Union
from backend.modules.usercontroller import UserController
from .utils import SingletonMeta, InfoOrLowerFilter
from configparser import ConfigParser
from .modules.mongomanager import MongoManager
from .modules.sqlmanager import SQLManager
from .modules.cache import Cache
from .modules.worker import Worker

__author__ = "drhspfn"
__email__ = "jenya.gsta@gmail.com"


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
            self.uvicorn_log_cfg = os.path.join(self.__root,"backend", "data", "uvicorn_logging.conf")
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
        except Exception as e:
            self._error_shutdown(e)

    @property
    def debug_mode(self) -> bool:
        return self.__debug
 
    @property
    def logger(self) -> logging.Logger:
        if self._logger is None:
            self._logger = logging.getLogger(__name__)
        return self._logger

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
