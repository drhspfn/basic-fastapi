from ..utils import validate_dict, mask_string


USER_VALIDATE = {
    "id": int,
    "username": str,
    "password": str,
    "email": str,
    "email_confirmed": bool,
}



### If use MongoDB, replace `id` to `_id`
class User:
    def __init__(self) -> None:
        self.id: int
        self.username: str
        self.password: str
        self.email: str
        self.email_confirmed: bool

    # @property             # MongoDB moment...
    # def id(self) -> int:
    #     return self.id

    @staticmethod
    def from_dict(data: dict) -> 'User':
        """
        Create a User object from a dictionary.

        Parameters:
            data (dict): A dictionary containing user data. The dictionary must have the following keys:
                        'id' (int), 'username' (str), 'password' (str), 'email' (str), 'email_confirmed' (bool).

        Returns:
            User: A User object created from the given dictionary.

        Raises:
            ValueError: If the given dictionary does not contain valid user data.
        """
        if not validate_dict(data, USER_VALIDATE):
            raise ValueError("Invalid data")

        user = User()
        user.id = data['id']
        user.username = data['username']
        user.password = data['password']
        user.email = data['email']
        user.email_confirmed = data['email_confirmed']
        return user

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
