from typing import Any
from fastapi.exceptions import HTTPException


class BasicError(HTTPException):
    def __init__(self, error_code: int, status_code: int, detail: Any = None) -> None:
        detail = {
            "ok": False,
            "code": error_code,
            "status": status_code,
            "error": detail
        }
        super().__init__(status_code, detail)


class NotFound(BasicError):
    def __init__(self, detail: Any = None) -> None:
        super().__init__(1, 404, detail)
