import os
import jwt
from fastapi import FastAPI, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.exceptions import HTTPException
from models import UserModel, User, get_password_hash, verify_password, Base, Token
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, select
from datetime import datetime, timedelta, timezone
from jwt.exceptions import InvalidTokenError
from typing import Annotated
from models import TokenData

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
engine = create_engine('sqlite:///database.db')
Session = sessionmaker(bind=engine)
db = Session()

Base.metadata.create_all(bind=engine)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user


@app.get('/')
async def index():
    return JSONResponse(content={"message": "Управление пользователями"}, status_code=200)


@app.post('/register')
async def register(user: UserModel):
    user_in_db = db.execute(select(User).where(User.username == user.username)).scalar_one_or_none()
    if user_in_db:
        return JSONResponse(content={"message": f"Пользователь {user_in_db.username} уже создан"}, status_code=400)
    user_in_db = User(
        username=user.username,
        email=user.email,
        password=get_password_hash(user.password),
        user_type=user.user_type
    )
    db.add(user_in_db)
    db.commit()
    return JSONResponse(content={"message": f"Пользователь {user.username} зарегистрирован"}, status_code=201)


@app.post("/login")
async def login(data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_in_db = db.execute(select(User).where(User.username == data.username)).scalar_one_or_none()
    if not user_in_db or not verify_password(data.password, user_in_db.password):
        return JSONResponse(content={"message": "Неправильный логин или пароль"}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_in_db.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get('/me', response_model=UserModel)
async def me(user: Annotated[User, Depends(get_current_user)]):
    return user


@app.put('/users/{user_id}')
async def edit_user(user_id: int, user: Annotated[User, Depends(get_current_user)], modify_user: UserModel):
    if user.id != user_id:
        return JSONResponse(content={"message": "Попытка изменения чужого пользователя"}, status_code=403)
    user.username = modify_user.username
    user.email = modify_user.email
    user.password = get_password_hash(modify_user.password)
    db.commit()
    return JSONResponse(content={"message": f"Пользователь {user.username} изменён"}, status_code=202)


@app.delete('/users/{user_id}')
async def delete_user(user_id: int, user: Annotated[User, Depends(get_current_user)]):
    if user.id != user_id:
        return JSONResponse(content={"message": "Попытка удаления чужого пользователя"}, status_code=403)
    db.delete(user)
    db.commit()
    return JSONResponse(content={"message":f"Пользователь {user.username} удалён"}, status_code=200)


@app.get('/users')
async def get_all_users(user: Annotated[User, Depends(get_current_user)]):
    if user.user_type != 'admin':
        return JSONResponse(content={"message": "Доступ запрещён"}, status_code=403)
    users = db.query(User).all()
    return users


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='localhost')
