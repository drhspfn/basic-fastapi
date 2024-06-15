from typing import Any, List
from fastapi.exceptions import HTTPException
from jose.jwt import ExpiredSignatureError, JWTError
from fastapi.exceptions import RequestValidationError


def format_code(code: int) -> str:
    return f"{code:03}"


class Argument:
    def __init__(self, location: str, key: str, atype: str | type, required: bool) -> None:
        self.location = location
        self.key = key
        self.type = atype
        self.required = required

    @property
    def json(self):
        return {
            'loc': self.location,
            'key': self.key,
            'type': self.type if isinstance(self.type, str) else self.type.__name__,
            'is_required': self.required
        }


class BasicError(HTTPException):
    def __init__(self, error_code: int, status_code: int, name: str, detail: Any = None, **kwargs) -> None:
        detail = {
            "ok": False,
            "error": {
                "code": format_code(error_code),
                "status": status_code,
                "name": name,
                "detail": detail,
                **kwargs
            }

        }
        super().__init__(status_code, detail)


class NotFound(BasicError):
    def __init__(self, detail: Any = None) -> None:
        super().__init__(1, 404, self.__class__.__name__, detail)


class InvalidAccessToken(BasicError):
    def __init__(self):
        super().__init__(3, 401, self.__class__.__name__, "Invalid access token")


class InvalidRefreshToken(BasicError):
    def __init__(self):
        super().__init__(4, 401, self.__class__.__name__, "Invalid refresh token")


class InvalidActivateToken(BasicError):          # 205
    def __init__(self):
        super().__init__(5, 401, self.__class__.__name__, "Invalid activate token")


class TokenExpired(BasicError):
    def __init__(self):
        super().__init__(6, 401, self.__class__.__name__, "Token has expired")


class RefreshTokenExpired(BasicError):
    def __init__(self):
        super().__init__(7, 401, self.__class__.__name__, "Refresh token has expired")


class TokenRevoked(BasicError):
    def __init__(self):
        super().__init__(8, 401, self.__class__.__name__,
                         "This token has been revoked/blocked.")


class InternalServerError(BasicError):
    def __init__(self, **kwargs):
        # method:str,url:str
        super().__init__(9, 500, self.__class__.__name__,
                         "An unexpected error occurred on the server.", **kwargs)


class MissingRequestBody(BasicError):
    def __init__(self, message="Request body is missing or empty"):
        super().__init__(10, 502, self.__class__.__name__, message)


class ArgumentError(RequestValidationError):
    def __init__(self, arguments: List[Argument]):
        errors = [argument.json for argument in arguments]
        super().__init__(errors)

# class ArgumentError(BasicError):
#     def __init__(self, arguments: List[Argument]):
#         self.required = []
#         self.optional = []
#         for argument in arguments:
#             if argument.required:
#                 self.required.append(argument.json)
#             else:
#                 self.optional.append(argument.json)

#         super().__init__(11, 502, self.__class__.__name__,
#                          "Error when passing arguments", required=self.required, optional=self.optional)


class AuthorizationFailed(BasicError):
    def __init__(self, login: str):
        self.login = login
        super().__init__(12, 401, self.__class__.__name__,
                         "Authorization failed, wrong login or password", login=login)


class WeakPasswordError(BasicError):             # 204
    def __init__(self):
        super().__init__(13, 400, self.__class__.__name__,
                         "Password must be at least 6 characters long and contain at least 1 digit, 1 uppercase letter, 1 lowercase letter, and 1 special character.")


class UserAlreadyExists(BasicError):             # 201
    def __init__(self, email: str = None, username: str = None):
        if email is not None:
            data = {'email': email}
        elif username is not None:
            data = {'username': username}
        super().__init__(14, 400, self.__class__.__name__,
                         "The user already exists", **data)
