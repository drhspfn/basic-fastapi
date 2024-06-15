# from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Dict


class RegistrationForm(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    
    @field_validator('username')
    def validate_username(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

    @field_validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v


class LoginForm(BaseModel):
    login:str = Field(..., min_length=1, max_length=150)
    password: str = Field(..., min_length=6)
