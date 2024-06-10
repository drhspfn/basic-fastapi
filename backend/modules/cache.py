import time
from typing import Any, Callable, Dict, List, Optional, Tuple, AsyncIterator
import asyncio


class Cache:
    def __init__(
        self,
        timeout: int = 60,
        max_size: int = None,
        on_delete: Optional[Callable] = None
    ):
        self._cache: Dict[str, Any] = {}
        self._timeout: int = timeout
        self._max_size: int = max_size
        self._on_delete: Optional[Callable] = on_delete
        self._lock: asyncio.Lock = asyncio.Lock()

    async def get(self, key: str) -> Any:
        """
        Retrieve a value from the cache based on the given key.

        If the key exists in the cache and has not expired, the corresponding value is returned.
        If the key exists but has expired, it is deleted from the cache and None is returned.
        If the key does not exist in the cache, None is returned.

        Parameters:
            key (str): The key to retrieve the value for. If the key is not a string, it is converted to a string.

        Returns:
            Any: The value associated with the key, or None if the key does not exist or has expired.
        """

        if not isinstance(key, str): key = str(key)

        async with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self._timeout:
                    return value
                else:
                    await self._delete_with_callback(key)
            return None

    async def set(self, key: str, value: Any) -> None:
        """
        Set a value in the cache with the given key.

        If the key already exists in the cache, its value and timestamp will be updated.
        If the cache has reached its maximum size, the oldest entries will be removed to make space for new entries.

        Parameters:
            key (str): The key to store the value under. If the key is not a string, it will be converted to a string.
            value (Any): The value to store in the cache.

        Returns:
            None
        """
        if not isinstance(key, str): key = str(key)

        async with self._lock:
            self._cache[key] = (value, time.time())
            if self._max_size is not None and len(self._cache) > self._max_size:
                await self._cleanup()

    async def delete(self, key: str) -> None:
        """
        Delete a key-value pair from the cache.

        This method acquires a lock to ensure thread-safety while deleting the key.
        If the key exists in the cache, it is removed and the associated callback (if any) is called.
        If the key does not exist, no action is taken.

        Parameters:
            key (str): The key to delete from the cache. If the key is not a string, it will be converted to a string.

        Returns:
            None
        """
        if not isinstance(key, str): key = str(key)
        async with self._lock:
            await self._delete_with_callback(key)

    async def keys(self) -> AsyncIterator[str]:
        """
        Asynchronously yields each key in the cache.

        This method acquires a lock to ensure thread-safety while iterating over the keys.
        It iterates over the keys in the cache dictionary and yields each key one by one.

        Parameters:
            None

        Returns:
            AsyncIterator[str]: An asynchronous iterator that yields each key in the cache.
        """

        async with self._lock:
            for key in self._cache.keys():
                yield key

    async def values(self) -> AsyncIterator[Any]:
        """
        Asynchronously yields each value in the cache.

        This method acquires a lock to ensure thread-safety while iterating over the values.
        It iterates over the values in the cache dictionary and yields each value one by one.

        Parameters:
            None

        Returns:
            AsyncIterator[Any]: An asynchronous iterator that yields each value in the cache.
        """

        async with self._lock:
            for _, value in self._cache.items():
                yield value

    async def items(self) -> AsyncIterator[Tuple[str, Any]]:
        """
        Asynchronously yields each key-value pair in the cache.

        This method acquires a lock to ensure thread-safety while iterating over the items.
        It iterates over the items in the cache dictionary and yields each item (key-value pair) one by one.

        Yields:
            Tuple[str, Any]: A tuple containing the key and value.

        Note:
            This method is an asynchronous generator function. It should be used with an async for loop to iterate over the items.
            For example:
            ```
            async for key, value in cache.items():
                print(f"Key: {key}, Value: {value}")
            ```
        """

        async with self._lock:
            for key, value in self._cache.items():
                yield key, value

    async def _delete_with_callback(self, key: str) -> None:
        """
        Private method to delete a key-value pair from the cache and call the on_delete callback if provided.

        Parameters:
            key (str): The key of the item to delete.

        Returns:
            None

        Raises:
            KeyError: If the key is not found in the cache.

        Note:
            This method is intended to be called internally by other methods of the Cache class.
            It acquires a lock to ensure thread-safety.
        """
        try:
            value = self._cache[key][0]
            del self._cache[key]
            if self._on_delete:
                await self._on_delete(key, value)
        except KeyError:
            pass

    async def _cleanup(self) -> None:
        """
        Private method to clean up expired entries from the cache.

        This method is called when the cache reaches its maximum size or when a new entry is added.
        It identifies the expired entries based on the timeout value and removes them from the cache.

        Parameters:
            None

        Returns:
            None

        Note:
            This method is intended to be called internally by other methods of the Cache class.
            It acquires a lock to ensure thread-safety.
        """
        
        async with self._lock:
            current_time = time.time()
            keys_to_remove = [
                key
                for key, (value, timestamp) in self._cache.items()
                if current_time - timestamp >= self._timeout
            ]
            for key in keys_to_remove:
                await self._delete_with_callback(key)
