from typing import Any, Dict, List, Union
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.results import InsertOneResult, InsertManyResult, UpdateResult
from motor.core import AgnosticCollection
from pymongo.results import DeleteResult

class MongoManager:
    def __init__(self, host: str, port: int, username: str, password: str,database:str,
                 max_pool_size: int = 20, min_pool_size: int = 5):
        self._connected = False
        if username and password:
            self.uri = f"mongodb://{username}:{password}@{host}:{port}/"
        else:
            self.uri = f"mongodb://{host}:{port}/"
            
        self.client = AsyncIOMotorClient(
            self.uri,
            maxPoolSize=max_pool_size,
            minPoolSize=min_pool_size
        )
        self.mongodb = self.client[database]

    async def close(self):
        if self.client:
            self.client.close()

    async def connect(self):
        try:
            await self.mongodb.command("ping")
            self._connected = True
        except Exception as e:
            self._connected = False
            raise Exception("MongoDB Connect Error: " + str(e))
        

    async def find(self, collection_name: str, query: Dict[str, Any], projection: Dict[str, Any] = None, limit: int = None) -> List[Dict[str, Any]]:
        """
        This method is used to find documents in a specified collection based on a given query.

        Parameters:
            collection_name (str): The name of the collection in which to search for documents.
            query (Dict[str, Any]): The query to filter documents.
            projection (Dict[str, Any], optional): The fields to include or exclude in the result. Defaults to None, which includes all fields.
            limit (int, optional): The maximum number of documents to return. Defaults to None, which returns all matching documents.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries representing the found documents.

        Raises:
            Exception: If an error occurs during the database operation.
        """
        async with await self.client.start_session() as session:
            collection = self.mongodb[collection_name]
            result = await collection.find(query, projection, session=session).to_list(limit)   
            return result
        
    async def update_in_collection(self, collection_name: str, query: dict,
                                   update_data: dict, make_set: bool = True,
                                   as_bool:bool=True) -> Union[bool, UpdateResult]:
        """
        Updates documents in the specified collection based on the provided query.

        Args:
            collection_name (str): The name of the collection to update documents in.
            query (dict): The query to filter documents for update.
            update_data (dict): The data to update documents with.
            make_set (bool, optional): Whether to use the $set operator for updating.
                                    Defaults to True.

        Returns:
            bool: True if at least one document was modified, False otherwise.
        """
        try:
            if not '$set' in update_data and make_set:
                update_data = {'$set': update_data}

            async with await self.client.start_session() as session:
                collection = self.mongodb[collection_name]
                result = await collection.update_one(query, update_data, session=session)
                if as_bool:
                    return result.modified_count > 0
                else:
                    return result

        except Exception as e:
            print('[MONGO-ERROR]: ', str(e))
            return False
        
    async def insert_many_documents(self, collection_name: str, documents: List[Dict[str, Any]]) -> InsertManyResult:
        """
        Inserts multiple documents into the specified collection using the connection pool.

        Args:
            collection_name (str): The name of the collection to insert documents into.
            documents (List[Dict[str, Any]]): The list of documents to insert.

        Returns:
            InsertManyResult: The result of the insertion operation.
        """
        async with await self.client.start_session() as session:
            collection = self.mongodb[collection_name]
            result = await collection.insert_many(documents, session=session)
        return result
    
    async def insert_document_with_sequential_id(self, collection_name: str, document: Dict[str, Any]) -> InsertOneResult:
        """
        Inserts a document into the specified collection using the connection pool with a sequential _id.

        Args:
            collection_name (str): The name of the collection to insert the document into.
            document (Dict[str, Any]): The document to insert.

        Returns:
            InsertOneResult: The result of the insertion operation.
        """
        try:
            async with await self.client.start_session() as session:
                collection = self.mongodb[collection_name]
                document['_id'] = await self.get_next_sequence_value(collection, session=session)
                result = await collection.insert_one(document, session=session)
                return result

        except Exception as e:
            print('[MONGO-ERROR]: ', str(e))
            return None
        
    async def get_next_sequence_value(self, base_object: AgnosticCollection, session) -> int:
        """
        Retrieves the next sequence value from the specified AgnosticCollection.

        Args:
            base_object (AgnosticCollection): The AgnosticCollection object from which to retrieve the sequence value.

        Returns:
            int: The next sequence value.
        """
        try:
            result = await base_object.find_one_and_update(
                {'_id': base_object.name},
                {'$inc': {'sequence_value': 1}},
                upsert=True,
                return_document=True,
                session=session
            )
            return result['sequence_value']

        except Exception as e:
            print('[MONGO-ERROR]: ', str(e))
            return 0
        
    async def insert_document(self, collection_name: str, document: Dict[str, Any]) -> InsertOneResult:
        """
        Inserts a document into the specified collection using the connection pool.

        Args:
            collection_name (str): The name of the collection to insert the document into.
            document (Dict[str, Any]): The document to insert.

        Returns:
            InsertOneResult: The result of the insertion operation.
        """
        async with await self.client.start_session() as session:
            collection = self.mongodb[collection_name]
            result = await collection.insert_one(document, session=session)
            return result
        

    async def execute_aggregation(self, collection_name: str, pipeline: List[Dict[str, Any]], limit: int = None) -> List[Dict[str, Any]]:
        """
        Executes an aggregation pipeline on the specified collection using the connection pool.

        Args:
            collection_name (str): The name of the collection to execute the aggregation on.
            pipeline (List[Dict[str, Any]]): The aggregation pipeline to execute.

        Returns:
            List[Dict[str, Any]]: The result of the aggregation.
        """
        async with await self.client.start_session() as session:
            collection = self.mongodb[collection_name]
            result = collection.aggregate(pipeline, session=session)
            if limit != -1:
                result = await result.to_list(limit)
            return result
        
    
    async def delete_many_documents(self, collection_name: str, query: Dict[str, Any]) -> DeleteResult:
        """
        Deletes multiple documents from the specified collection using the connection pool.

        Args:
            collection_name (str): The name of the collection to delete documents from.
            query (Dict[str, Any]): The query to filter documents for deletion.

        Returns:
            DeleteResult: The result of the delete operation.
        """
        async with await self.client.start_session() as session:
            collection = self.mongodb[collection_name]
            result = await collection.delete_many(query, session=session)
            return result


    async def delete_one_document(self, collection_name: str, query: Dict[str, Any]) -> DeleteResult:
        """
        Deletes a single document from the specified collection using the connection pool.

        Args:
            collection_name (str): The name of the collection to delete a document from.
            query (Dict[str, Any]): The query to filter the document for deletion.

        Returns:
            DeleteResult: The result of the delete operation.
        """
        async with await self.client.start_session() as session:
            collection = self.mongodb[collection_name]
            result = await collection.delete_one(query, session=session)
            return result