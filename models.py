from pydantic import BaseModel, EmailStr, Field

class LoginUser(BaseModel):
    username: str
    password: str 
    
class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=8, max_length=50)
    email: EmailStr

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    username: str

    class Config:
        from_attributes=True