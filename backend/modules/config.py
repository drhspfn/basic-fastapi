from configparser import ConfigParser
from datetime import datetime
from os import path
from typing import List

from backend.utils import parse_time_string


class DatabaseSettings:
    def __init__(self) -> None:
        self.host: str
        self.port: int
        self.username: str
        self.password: str
        self.database: str
        self.min_pool: int
        self.max_pool: int


class CorsSettings:
    def __init__(self) -> None:
        self.origins: List[str]
        self.methods: str


class ConfigLoader:

    def __init__(self, root: str, config_path: str):
        self.__root = root
        self.config_path = config_path
        self.config = ConfigParser()

        self.debug: bool
        self.is_utc: bool
        self.logs_dir = path.join(self.__root, "logs")
        self.database: DatabaseSettings = DatabaseSettings()
        self.cors: CorsSettings = CorsSettings()
        self.secret_key: str
        self.access_token_lifetime: datetime
        self.refresh_token_lifetime: datetime
        
        self.read()

    def read(self):
        self.config.read(self.config_path)

        self.debug = self.config.getboolean("server", "debug")
        self.is_utc = self.config.getboolean("server", "utc_time")
        log_dir = self.config.get('server', 'log_path')
        if log_dir != "":
            if path.isabs(log_dir):
                self.logs_dir = log_dir
            else:
                self.logs_dir = path.abspath(
                    path.join(self.__root, log_dir))

        self.database.host = self.config.get("database", "host")
        self.database.port = self.config.getint("database", "port")
        self.database.username = self.config.get("database", "username")
        self.database.password = self.config.get("database", "password")
        self.database.database = self.config.get("database", "database")
        self.database.min_pool = self.config.getint("database", "min_pool")
        self.database.max_pool = self.config.getint("database", "max_pool")

        self.cors.origins = self.config.get("cors", "origins")
        if self.cors.origins != "":
            self.cors.origins = [origin.strip()
                                 for origin in self.cors.origins.split(",")]

        self.cors.methods = self.config.get("cors", "methods")
        if self.cors.methods != "*":
            self.cors.methods = ", ".join(
                [method.strip() for method in self.cors.methods.split(",")])

        self.secret_key = self.config.get("server", "secret_key")

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
