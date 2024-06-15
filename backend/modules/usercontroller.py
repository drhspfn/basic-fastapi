from typing import TYPE_CHECKING, List, Optional
from .cache import Cache
# from ..classes.user import User
from ..classes.sql import User
# from ..classes.user import User
from ..utils import filter_dictionary, is_valid_email
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload



if TYPE_CHECKING:
    from backend import Backend


class UserController:
    def __init__(self, backend: 'Backend'):
        self.users = Cache(5, on_delete=self._save)
        self.__backend = backend

    async def _save(self, id: int, user: 'User', *args, **kwargs) -> bool:
        """
        Saves the user data to the database. This method is called when a user object is deleted from the cache.

        Parameters:
            id (int): The id of the user.
            user (User): The user object to save.
            *args, **kwargs: Additional arguments and keyword arguments that may be passed to the method.

        Returns:
            bool: True if saving was successful, False otherwise.

        This method calls the update method of the UserController class to save the user data to the database.
        """
        session = await self.__backend.database.get_session_directly()
        result =  await self.update(user=user, session=session)
        await session.close()
        return result
    
    async def get_by_id(self, user_id:int, session:AsyncSession) -> 'User':
        """
        Retrieves a user from the database based on their unique identifier (user_id).
        It utilizes the get_by method to perform the actual retrieval, which checks
        both the cache and the database.

        Parameters:
            user_id (int): The unique identifier of the user to be retrieved.

        Returns:
            User: The user object if found in the database or cache.
            None: If no user is found in the database or cache.

        Raises:
            Exception: If any error occurs during the database query or cache retrieval.
        """
        return await self.get_by(uid=user_id, session=session)

    async def get_by(self,session:AsyncSession, login: str = None, uid: int = None) -> 'User':
        """
        Retrieves a user from the database based on either the login or uid.
        If the user is found in the cache, it returns the cached user.
        If not found in the cache, it queries the database and caches the user.

        Parameters:
            login (str): The login of the user. If provided, it will be used to query the database.
            uid (int): The unique identifier of the user. If provided, it will be used to query the database.

        Returns:
            User: The user object if found in the database or cache.
            None: If no user is found in the database or cache.

        Raises:
            Exception: If any error occurs during the database query or cache retrieval.
        """
        cache_key = None

        if login is not None:
            query_key = "email" if is_valid_email(login) else "username"
            stmt = select(User).filter_by(**{query_key: login})
            #cache_key = login      # Maybe you want to cache by login as well.
        elif uid is not None:
            cache_key = uid
            stmt = select(User).filter_by(id=uid)
        else:
            return None
        
        if cache_key is not None:
            user_from_cache = await self.users.get(cache_key)
            if user_from_cache:
                print('returned user drom cache #1')
                return user_from_cache

        
        result = await session.execute(stmt)
        user:User = result.scalar_one_or_none()
        if user:
            user_from_cache = await self.users.get(user.id)
            if user_from_cache:
                print('returned user drom cache #2')
                return user_from_cache

            await self.users.set(user.id, user)
            print('added user to cache')

        return user


    async def update(self, user: User, session: AsyncSession, fields: Optional[List[str]] = None) -> bool:
        """
        Updates user data in the database.

        Args:
            user (User): The user object to update.
            fields (Optional[List[str]]): A list of fields to update. Defaults to None.
                If provided, only the specified fields will be updated.
                If not provided, all fields of the user object will be updated.
            session (AsyncSession): The async session to use for the update operation.

        Returns:
            bool: True if saving was successful, False otherwise.

        Raises:
            Exception: If any error occurs during the update operation.
        """
        try:
            db_user = await session.get(User, user.id)

            if not db_user:
                return False

            user_data = user.to_dict()

            if fields:
                for field in fields:
                    if field in user_data:
                        setattr(db_user, field, user_data[field])
            else:
                for key, value in user_data.items():
                    setattr(db_user, key, value)

            await session.commit()
            return True
        except Exception as e:
            await session.rollback()
            raise e
    '''
    # Variation of an update for MongoDB
    async def update(self, user: User, fields: List[str] = None):
        """
        Updates user data in the database.

        Args:
            user (User): The user object to update.
            fields (Optional[List[str]]): A list of fields to update. Defaults to None.
                If provided, only the specified fields will be updated.
                If not provided, all fields of the user object will be updated.

        Returns:
            bool: True if saving was successful, False otherwise.
                The method returns True if the update operation was successful in the database.
                Otherwise, it returns False.

        Raises:
            Exception: If any error occurs during the update operation.

        Note:
            This method uses the __backend.database.update_in_collection method to update the user data in the database.
            The update_data is constructed based on the provided user object and fields.
            The method returns the result of the update operation.
        """
        user_data = user.to_dict()

        update_data = {"$set": {}}
        if fields:
            update_data["$set"] = filter_dictionary(user_data, fields)
        else:
            update_data["$set"] = user_data

        return await self.__backend.database.update_in_collection(collection_name="users",
                                                                query={
                                                                    '_id': user.id},
                                                                update_data=update_data)
        
        '''


    async def add_user(self, email:str, password:str, username:str, session:AsyncSession) -> User:
        """
        Adds a new user to the database.

        Parameters:
            email (str): The email of the new user.
            password (str): The password of the new user.
            username (str): The username of the new user.
            session (AsyncSession): The SQLAlchemy AsyncSession object for database operations.

        Returns:
            User: The newly created User object.

        This method creates a new User object with the provided email, password, and username.
        It initializes the access token, refresh token, access token expiration, and refresh token expiration to empty strings and zeros respectively.
        The new user is then added to the database using the provided AsyncSession object.
        After the user is added to the database, the method generates access and refresh tokens using the __backend.generate_access method.
        The generated tokens are then assigned to the user object.
        Finally, the updated user object is added to the database and committed.
        The newly created user object is then returned.
        """
        user = User(username=username, email=email, password=password)
        user.access_token = ""
        user.refresh_token = ""
        user.access_token_expires = 0
        user.refresh_token_expires = 0
        session.add(user)
        await session.commit()

        tokens = self.__backend.generate_access(user)
        user.access_token = tokens[0][0]
        user.access_token_expires = tokens[0][1]
        user.refresh_token = tokens[1][0]
        user.refresh_token_expires = tokens[1][1]
        session.add(user)
        await session.commit()
        return user
