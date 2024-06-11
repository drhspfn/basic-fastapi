from sqlalchemy import Column, Integer, String, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from backend.utils import mask_string

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(30), nullable=False, unique=True)
    password = Column(String, nullable=False)
    email = Column(String(150), nullable=False, unique=True)
    email_confirmed = Column(Boolean, default=False)

    # def __init__(self, username, password, email, email_confirmed=False):
    #     self.username = username
    #     self.password = password
    #     self.email = email
    #     self.email_confirmed = email_confirmed
    def to_dict(self, mask:bool=False) -> dict:
        """
        Convert the User object into a dictionary.

        This method is used to represent the User object as a dictionary, which can be easily serialized or sent over a network.

        Parameters:
            mask (bool): Whether to mask sensitive data

        Returns:
            dict: A dictionary containing the user's id, username, password, email, and email_confirmed.

        Raises:
            None
        """
        return {
            "id": self.id,
            "username": self.username,
            "password": mask_string(self.password) if mask else self.password,
            "email": self.email,
            "email_confirmed": self.email_confirmed,
        }

    def to_json(self, mask:bool=False) -> dict:
        """
        Convert the User object into a dictionary for JSON serialization.

        This method converts the User object into a dictionary, suitable for JSON serialization.

        Parameters:
            mask (bool): Whether to mask sensitive data

        Returns:
            dict: A dictionary containing the user's information, suitable for JSON serialization.

        Raises:
            None

        Example:
            >>> user = User(1, 'john', 'password', 'john@example.com', True, datetime.now())
            >>> json_data = user.to_json()
            >>> print(json_data)
            {
                "id": 1,
                "username": "john",
                "password": "password",
                "email": "john@example.com",
                "email_confirmed": True,
                "last_login": "2022-01-01T12:00:00"
            }
        """
        data = self.to_dict(mask = mask)
        # Example
        # data['last_login'] = self.last_login.isoformat()
        return data

    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}', email_confirmed={self.email_confirmed})>"
