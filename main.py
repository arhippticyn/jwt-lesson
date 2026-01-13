from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from models import UserCreate, UserResponse
from db import Users, get_db
import jwt
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
import os
from dotenv import load_dotenv

load_dotenv()

ALGORITM = 'HS256'
SECRET_KEY = '09d25e094faa6ca2556c818166b7a9563b93f7099f6f8f4caa6cf63b88e8d3e7'
ACCESS_TOKEN_EXPIRES = 30
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')


app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY
)

oauth = OAuth()

oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

oauth.register(
    name='github',
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'}
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(hashed, password):
    return pwd_context.verify(password, hashed)

@app.post('/register', response_model=UserResponse)
async def register(userCreates: UserCreate, db: Session = Depends(get_db)):
    user = db.query(Users).filter(Users.username == userCreates.username or Users.email == userCreates.email).first()

    if user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='User is already register')
    
    if not user:
        user = Users(username=userCreates.username, email=userCreates.email, password=hash_password(userCreates.password))
        print("USERS TABLE:", Users.__table__)
        print("DB URL:", db.bind.url)
        db.add(user)
        db.commit()
        db.refresh(user)

    return user

@app.post('/token')
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Users).filter(Users.username == form_data.username).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='User is not found')
    
    if not verify_password(user.password, form_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Username or password dont correct')
    
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='User is not found')
    
    payload = {
        'sub': user.username,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRES)
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITM)

    return {'access_token': access_token, 'type': 'bearer'}

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    creditials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITM])
        username = payload.get('sub')

        if username is None:
            raise creditials_exception
        
    except InvalidTokenError:
        raise creditials_exception
    
    user = db.query(Users).filter(Users.username == username).first()

    if user is None:
        raise creditials_exception
    
    return user

@app.get('/user', response_model=UserResponse)
async def read_user(user: Users = Depends(get_current_user)):
    return user

@app.get('/auth/google')
async def google_login(request: Request):
    redirect_uri = 'http://127.0.0.1:8000/auth/google/callback'
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get('/auth/github')
async def github_login(request: Request):
    redirect_uri = 'http://127.0.0.1:8000/auth/github/callback'
    return await oauth.github.authorize_redirect(request, redirect_uri)

@app.get('/auth/google/callback')
async def google_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    user_info = token['userinfo']

    email = user_info['email']
    username = user_info['email'].split('@')[0]

    user = db.query(Users).filter(Users.email == email).first()


    if not user:
        user = Users(username=username, email=email, password=None)
        db.add(user)
        db.commit()
        db.refresh(user)

    payload = {
        'sub': user.username,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRES)
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITM)

    return {'access_token': access_token, 'type': 'bearer'}

@app.get('/auth/github/callback')
async def github_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.github.authorize_access_token(request)
    resp = await oauth.github.get('user', token=token)
    profile = resp.json()

    email_resp = await oauth.github.get('user/emails', token=token)
    emails = email_resp.json()
    email = next(
    (e["email"] for e in emails if e.get("verified")),
    None
    )


    username = profile['login']

    if email is None:
      raise HTTPException(
        status_code=400,
        detail="GitHub account has no verified email"
    )


    user = db.query(Users).filter(Users.email == email).first()



    if not user:
        user = Users(username=username, email=email, password=None)
        try:
            db.add(user)
            print("EMAIL:", email)
            print("USERNAME:", username)
            print("USER FOUND:", user)
            db.commit()
            print("COMMITTED")
            db.refresh(user)
            print("USER ID:", user.id)

        except Exception as e:
            db.rollback()
            print("DB ERROR:", e)
            raise

    payload = {
        'sub': user.username,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRES)
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITM)

    return {'access_token': access_token, 'type': 'bearer'}