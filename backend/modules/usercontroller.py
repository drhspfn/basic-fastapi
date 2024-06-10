from typing import TYPE_CHECKING, List
from .cache import Cache
from ..classes.user import User
from ..utils import filter_dictionary, is_valid_email

if TYPE_CHECKING:
    from backend import Backend


class UserController:
    def __init__(self, backend: 'Backend'):
        self.users = Cache(100 * 60, on_delete=self._save)
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
        return await self.update(user=user)

    async def get_by_id(self, user_id) -> 'User':
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
        return await self.get_by(uid=user_id)

    async def get_by(self, login: str = None, uid: int = None) -> 'User':
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
        query = {}
        cache_key = None

        if login is not None:
            query_key = "email" if is_valid_email(login) else "username"
            query = {query_key: login}
        elif uid is not None:
            cache_key = uid
            query = {'_id': uid}

        if cache_key is not None:
            user_from_cache = await self.users.get(cache_key)
            if user_from_cache:
                return user_from_cache

        data = await self.__backend.database.find(
            collection_name='users',
            query=query,
            limit=1
        )

        if data:
            user_id = data[0]['_id']
            user_from_cache = await self.users.get(user_id)
            if user_from_cache:
                return user_from_cache
            user = User.from_dict(data[0])
            return user

        return None


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
