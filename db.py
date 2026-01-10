import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, String
from sqlalchemy.orm import sessionmaker, declarative_base, mapped_column, Mapped

load_dotenv()

DB_URL = os.getenv('DB_URL')

engine = create_engine(DB_URL)

SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()


class Users(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50))
    email: Mapped[str] = mapped_column(String(200), unique=True)
    password: Mapped[str | None] = mapped_column()
    google_id: Mapped[str] = mapped_column(nullable=True)
    github_id: Mapped[str] = mapped_column(nullable=True)

def get_db():
    db = SessionLocal()
    try: 
        yield db
    
    finally:
        db.close()