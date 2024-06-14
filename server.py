from typing import Optional
from fastapi import FastAPI, Request, APIRouter, Depends
from fastapi.responses import JSONResponse
from backend import Backend
import time
from starlette.responses import Response
from fastapi.exceptions import HTTPException, RequestValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from backend.classes.error import NotFound

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
    start = time.time()
    if request.method == "OPTIONS":
        response = Response()
    else:
        response = await call_next(request)

    origin = request.headers.get('Origin')
    if request.method.lower() == "get":
        response.headers["Access-Control-Allow-Origin"] = "*"
    elif origin in backend.cors_origins:
        response.headers["Access-Control-Allow-Origin"] = origin

    response.headers["Access-Control-Allow-Methods"] = backend.cors_methods
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Max-Age"] = "3600"
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


@apiv1_router.get("/user/get")
async def get_users(request: Request,
                    user_id: Optional[int] = None, login: Optional[str] = None,
                    session: AsyncSession = Depends(backend.database.get_session)):
    start = time.time()
    user = await backend.user_controller.get_by(uid=user_id, login=login, session=session)
    if user is None:
        raise NotFound("User not found")

    return JSONResponse({
        'ok': True,
        'time': time.time() - start,
        'data': user.to_json()
    })

app.include_router(apiv1_router)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True,
                log_config=backend.uvicorn_log_cfg)
