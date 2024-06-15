from typing import Optional
from fastapi import FastAPI, Request, APIRouter, Depends
from fastapi.responses import JSONResponse
from backend import Backend
import time
from starlette.responses import Response
from fastapi.exceptions import HTTPException, RequestValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from backend.classes.arguments import *
from backend.classes.error import *
from backend.classes.models import LoginForm, RegistrationForm
from backend.classes.user import User

from pydantic import ValidationError

backend = Backend()

#### ============================================================================= ####
#### ============================================================================= ####
#### ============================================================================= ####
#### ============================================================================= ####


async def startup_callback():
    try:
        await backend.database.init_tables()
        # backend.log("[STARTUP] Database Initialization...")
        # await backend.database.connect()
        # backend.log("[STARTUP] Database Initialization. Successful!")
        # backend.log('sfasdsadd', level='DEBUG')
    except Exception as e:
        backend._error_shutdown(e)


async def shutdown_callback():
    try:
        ...
    except Exception as e:
        backend._error_shutdown(e)

app = FastAPI(
    title="Basic FastAPI",
    version="0.1.0",
    on_startup=[startup_callback],
    on_shutdown=[shutdown_callback]
)
apiv1_router = APIRouter(prefix="/api/v1")


@app.middleware("http")
async def custom_cors(request: Request, call_next):
    """
    Custom middleware to handle CORS (Cross-Origin Resource Sharing) for the FastAPI application.

    Parameters:
        request (Request): The FastAPI Request object representing the incoming request.
        call_next (callable): A coroutine function that will be called to process the request.

    Returns:
        response (Response): The FastAPI Response object representing the outgoing response.
    """
    start = time.time()

    # If the request method is OPTIONS, return an empty response with appropriate CORS headers
    if request.method == "OPTIONS":
        response = Response()
    else:
        # Call the next middleware or endpoint handler
        response = await call_next(request)

    # Get the Origin header from the request
    origin = request.headers.get('Origin')

    # If the request method is GET, allow any origin
    if request.method.lower() == "get":
        response.headers["Access-Control-Allow-Origin"] = "*"
    # If the request method is not GET and the Origin header is in the list of allowed origins, allow that origin
    elif origin in backend.cors_origins:
        response.headers["Access-Control-Allow-Origin"] = origin

    # Set other CORS headers
    response.headers["Access-Control-Allow-Methods"] = backend.cors_methods
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Max-Age"] = "3600"

    # Add a custom header to the response to measure processing time
    response.headers["X-Process-Time"] = str(time.time() - start)

    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": exc.body},
    )


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    backend._logger.exception(exc)
    backend.log('Global exception handler: %s', str(exc), level='ERROR')
    return JSONResponse(
        status_code=500,
        content={
            'ok': False,
            "error": "An unexpected error occurred."
        },
    )
#### ============================================================================= ####
#### ============================================================================= ####
#### ============================================================================= ####
#### ============================================================================= ####


@app.get("/")
async def root(request: Request, session: AsyncSession = Depends(backend.database.get_session)):
    return JSONResponse({
        "message": "Welcome to Basic FastAPI!",
        "remote": f'{request.client.host}:{request.client.port}'
    })


@apiv1_router.post("/user/login", tags=["User"], summary="User's login")
async def get_user_login(request: Request,
                         session: AsyncSession = Depends(backend.database.get_session)):
    body_data: bytes = await request.body()
    if not body_data:
        raise MissingRequestBody()

    decrypted_data = backend.decrypt_body_json_data(body_data)
    if not decrypted_data:
        raise MissingRequestBody(
            "The request body is incorrectly formed and/or encrypted")

    login_data = LoginForm(**decrypted_data)

    authorized = await backend.authenticate_user(login=login_data.login,
                                                 password=login_data.password,
                                                 session=session)

    if not authorized:
        raise AuthorizationFailed(login_data.login)

    response = JSONResponse({'ok': True,
                             "data": authorized.to_json(True)
                             }, status_code=200)
    response.set_cookie(
        key="access_token",
        value=authorized.access_token,
        samesite='none',
        httponly=True,
        secure=True,
        expires=backend.fromtimestamp(authorized.access_token_expires, True)
    )
    response.set_cookie(
        key="refresh_token",
        value=authorized.refresh_token,
        samesite='none',
        httponly=True,
        secure=True,
        expires=backend.fromtimestamp(authorized.refresh_token_expires, True)
    )
    return response


@apiv1_router.post("/user/register", tags=["User"], summary="User's register")
async def get_user_register(request: Request,
                            username: str, email: str, password: str,
                            session: AsyncSession = Depends(backend.database.get_session)):
    body_data: bytes = await request.body()
    if not body_data:
        raise MissingRequestBody()

    decrypted_data = backend.decrypt_body_json_data(body_data)
    if not decrypted_data:
        raise MissingRequestBody(
            "The request body is incorrectly formed and/or encrypted")

    register_data = RegistrationForm(**decrypted_data)
    register = await backend.register_user(data=register_data, session=session)
    response = JSONResponse({'ok': True,
                             "data": register.to_json(True),
                             }, status_code=200)
    response.set_cookie(
        key="access_token",
        value=register.access_token,
        samesite='none',
        httponly=True,
        secure=True,
        expires=backend.fromtimestamp(register.access_token_expires, True)
    )
    response.set_cookie(
        key="refresh_token",
        value=register.refresh_token,
        samesite='none',
        httponly=True,
        secure=True,
        expires=backend.fromtimestamp(register.refresh_token_expires, True)
    )
    return response


app.include_router(apiv1_router)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True,
                log_config=backend.uvicorn_log_cfg)
