from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy import MetaData
from .config import DatabaseSettings

class SQLManager:
    def __init__(self, db_settings:DatabaseSettings) -> None:
        self._connected = False
        if db_settings.username and db_settings.password:
            self.uri = f"mysql+aiomysql://{db_settings.username}:{db_settings.password}@{db_settings.host}/{db_settings.database}"
        else:
            self.uri = f"mysql+aiomysql://{db_settings.host}/{db_settings.database}"

        self.engine = create_async_engine(self.uri)
    
    async def init_tables(self):
        async with self.engine.connect() as conn:
            await conn.run_sync(self._load_metadata)

    def _load_metadata(self, sync_conn):
        self.metadata = MetaData()
        self.metadata.reflect(bind=sync_conn)
        # self.track_table = Table('tracks', self.metadata, autoload_with=sync_conn)

    async def close(self):
        await self.engine.dispose()

    async def get_session(self) -> AsyncSession: # type: ignore
        async_session = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
        async with async_session() as session:
            yield session

    async def get_session_directly(self) -> AsyncSession:
        async_session = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
        return async_session()