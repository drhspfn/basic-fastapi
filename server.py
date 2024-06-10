from fastapi import FastAPI, Request, APIRouter
from fastapi.responses import JSONResponse
from backend import Backend
import time

from fastapi.exceptions import HTTPException, RequestValidationError

from backend.classes.error import NotFound


backend = Backend()

#### ============================================================================= ####
#### ============================================================================= ####
#### ============================================================================= ####
#### ============================================================================= ####


async def startup_callback():
    try:
        backend.log("[STARTUP] Database Initialization...")
        await backend.database.connect()
        backend.log("[STARTUP] Database Initialization. Successful!")
        backend.log('sfasdsadd', level='DEBUG')
    except Exception as e:
        backend._error_shutdown(e)

async def shutdown_callback():
    try:
        ...
    except Exception as e:
        backend._error_shutdown(e)

app = FastAPI(
    title="Project OpenMusic",
    version="0.1.0",
    on_startup=[startup_callback],
    on_shutdown=[shutdown_callback]
)
apiv1_router = APIRouter(prefix="/api/v1")


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
async def root():
    return JSONResponse({"message": "Welcome to Project OpenMusic!"})


@apiv1_router.get("/users")
async def get_users():
    user_id = 1
    start = time.time()
    user = await backend.user_controller.get_by_id(user_id)
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
