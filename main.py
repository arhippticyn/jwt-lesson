from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from models import *
from db import Users, get_db
import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone

ALGORITM = 'HS256'
SECRET_KEY = '09d25e094faa6ca2556c818166b7a9563b93f7099f6f8f4caa6cf63b88e8d3e7'
ACCESS_TOKEN_EXPIRES = 30

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(hashed,password):
    return pwd_context.verify(password, hashed)

@app.post('/register', response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    user_db = db.query(Users).filter(Users.username == user.username).first()

    if user_db:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='User already register')
    
    if not user_db: 
        user_db = Users(username=user.username, email=user.email, password=hash_password(user.password))
        db.add(user_db)
        db.commit()
        db.refresh(user_db)

    return user_db

@app.post('/token')
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user_db = db.query(Users).filter(Users.username == form_data.username).first()

    if not user_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not found')
    
    if not verify_password(user_db.password, form_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='username or passsword not true')
    
    payload = {
        'sub': user_db.username,
        'exp': datetime.now(timezone.utc) + timedelta(ACCESS_TOKEN_EXPIRES)
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITM)

    return {'access_token': access_token, 'type': 'bearer'}