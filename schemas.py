from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
  email: str
  password: str


class UserLogin(BaseModel):
  email: str
  password: str


class Token(BaseModel):
  access_token: str
  token_type: str


class TwoFactorSetup(BaseModel):
  secret: str
  otpauth_url: str


class TwoFactorVerify(BaseModel):
  code: str