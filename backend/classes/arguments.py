from .error import Argument

# The plan is to switch completely to validators from 'pydantic'

LOGIN_LOGIN =  Argument('body', 'login', 'str', True)
LOGIN_PASSWORD =  Argument('body', 'password', 'str', True)
LOGIN_USERNAME =  Argument('body', 'username', 'str', True)
LOGIN_USERID =  Argument('body', 'user_id', 'int', False)
LOGIN_EMAIL =  Argument('body', 'email', 'str', True)