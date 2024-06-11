from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine


class SQLManager:
    def __init__(self, host: str, port: int, username: str, password: str,database:str) -> None:
        self._connected = False
        if username and password:
            self.uri = f"mysql+aiomysql://{username}:{password}@{host}/{database}"
        else:
            self.uri = f"mysql+aiomysql://{host}/{database}"

        self.engine = create_async_engine(self.uri)


    async def close(self):
        await self.engine.dispose()

    async def get_session(self) -> AsyncSession: # type: ignore
        async_session = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
        async with async_session() as session:
            yield session