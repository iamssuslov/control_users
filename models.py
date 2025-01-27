from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer, String
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserModel(BaseModel):
    username: str
    email: EmailStr
    password: str
    user_type: str = 'user'


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String(512), nullable=False)
    user_type = Column(String, nullable=False, default='user')


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)
