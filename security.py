import datetime
import re
import secrets
import pyotp
import os
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY_HERE")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
  return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
  return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None):
  to_encode = data.copy()
  if expires_delta:
    expire = datetime.utcnow() + expires_delta
  else:
    expire = datetime.utcnow() + timedelta(minutes=15)
  to_encode.update({"exp": expire})
  encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
  return encoded_jwt


def get_totp_uri(email: str, secret: str):
  return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="SecureApp")


def verify_totp(secret: str, code: str):
  totp = pyotp.totp.TOTP(secret)
  return totp.verify(code)


def validate_password_policy(password: str) -> tuple[bool, str]:
  # - не менше 8 символів
  # - великі та малі літери
  # - хоча б одна цифра
  # - хоча б один спецсимвол
  if len(password) < 8:
    return False, "Пароль повинен містити щонайменше 8 символів."
  if not re.search(r"[A-Z]", password):
    return False, "Пароль повинен містити хоча б одну велику літеру (A-Z)."
  if not re.search(r"[a-z]", password):
    return False, "Пароль повинен містити хоча б одну малу літеру (a-z)."
  if not re.search(r"\d", password):
    return False, "Пароль повинен містити хоча б одну цифру (0-9)."
  if not re.search(r"[^A-Za-z0-9]", password):
    return (
        False,
        "Пароль повинен містити щонайменше один спецсимвол (наприклад, !@#$%).",
    )
  return True, "Пароль відповідає політиці безпеки."


def generate_token():
  return secrets.token_urlsafe(32)