import datetime
from database import Base
from sqlalchemy import Boolean, Column, DateTime, Integer, String


class User(Base):
  __tablename__ = "users"

  id = Column(Integer, primary_key=True, index=True)
  email = Column(String, unique=True, index=True, nullable=False)
  hashed_password = Column(String, nullable=False)
  role = Column(
      String, default="user"
  )
  # ролі юзр або адмін
  is_active = Column(
      Boolean, default=False
  )
  # активація через пошту
  activation_token = Column(String, nullable=True)
  activation_token_expires = Column(DateTime, nullable=True)

  # брутфорс
  failed_login_attempts = Column(Integer, default=0)
  is_locked = Column(Boolean, default=False)
  lock_until = Column(DateTime, nullable=True)

  # 2факторка
  is_2fa_enabled = Column(Boolean, default=False)
  totp_secret = Column(String, nullable=True)
  oidc_sub = Column(String, unique=True, nullable=True)

  # відн.пароля
  reset_token = Column(String, nullable=True)
  reset_token_expires = Column(DateTime, nullable=True)


class LoginLog(Base):
  __tablename__ = "login_logs"

  id = Column(Integer, primary_key=True, index=True)
  email = Column(String, index=True)
  ip_address = Column(String)
  success = Column(Boolean)
  timestamp = Column(DateTime, default=datetime.datetime.utcnow)