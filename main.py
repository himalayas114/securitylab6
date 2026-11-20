from datetime import datetime, timedelta
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

from database import Base, engine, get_db
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

import models
import security
import pyotp
import os
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

load_dotenv()

# Створення таблиць у базі даних
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Account Management System")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "YOUR_SECRET_KEY_HERE"))
templates = Jinja2Templates(directory="templates")

# OIDC Configuration
oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email'
    }
)

# --- НАЛАШТУВАННЯ SMTP ДЛЯ РЕАЛЬНОЇ ВІДПРАВКИ ПОШТИ ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465  # SSL порт для Gmail
SENDER_EMAIL = (
    "114himalayas@gmail.com"  # <--- Впишіть сюди вашу пошту (наприклад, Gmail)
)
SENDER_PASSWORD = (
    "qwij lhyu fzzk wxuk"  # <--- Впишіть сюди Пароль додатка (App Password)
)


def send_email(to_email: str, subject: str, html_content: str):
  """Функція для реальної відправки email через поштовий сервер"""
  try:
    message = MIMEMultipart("alternative")
    message["Subject"] = Header(subject, "utf-8")
    message["From"] = SENDER_EMAIL
    message["To"] = to_email

    part = MIMEText(html_content, "html", "utf-8")
    message.attach(part)

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
      server.login(SENDER_EMAIL, SENDER_PASSWORD)
      server.sendmail(SENDER_EMAIL, to_email, message.as_string())
    print(f"[MAIL SUCCESS] Лист успішно надіслано на {to_email}")
  except Exception as e:
    print(f"[MAIL ERROR] Помилка відправки листа на {to_email}: {e}")
    raise HTTPException(
        status_code=500, detail="Не вдалося надіслати електронного листа."
    )


# --- Головна сторінка та вебсторінки (HTML) ---
@app.get("/", response_class=HTMLResponse)
def read_root():
  return RedirectResponse(url="/login-page")


@app.get("/register-page", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"request": request})
@app.get("/login-page", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})

@app.get("/profile-page", response_class=HTMLResponse)
def profile_page(request: Request):
    return templates.TemplateResponse(request, "profile.html", {"request": request})

@app.get("/forgot-page", response_class=HTMLResponse)
def forgot_page(request: Request):
    return templates.TemplateResponse(request, "forgot.html", {"request": request})

# --- Завдання 1 & 2: Реєстрація, політика паролів та CAPTCHA ---
@app.post("/register")
def register(
    email: str = Form(...),
    password: str = Form(...),
    captcha: str = Form(...),
    db: Session = Depends(get_db),
):
  if captcha != "5":
    raise HTTPException(
        status_code=400, detail="Неправильна відповідь CAPTCHA (введіть 5)."
    )

  is_valid, msg = security.validate_password_policy(password)
  if not is_valid:
    raise HTTPException(status_code=400, detail=msg)

  existing_user = (
      db.query(models.User).filter(models.User.email == email).first()
  )
  if existing_user:
    raise HTTPException(
        status_code=400, detail="Користувач з такою поштою вже існує."
    )

  # Генерація токена активації (Завдання 3)
  activation_token = security.generate_token()
  token_expires = datetime.utcnow() + timedelta(hours=24)

  user_count = db.query(models.User).count()
  role = "admin" if user_count == 0 else "user"

  new_user = models.User(
      email=email,
      hashed_password=security.get_password_hash(password),
      role=role,
      is_active=False,
      activation_token=activation_token,
      activation_token_expires=token_expires,
  )
  db.add(new_user)
  db.commit()

  # Реальна відправка листа з посиланням активації на пошту
  activation_link = f"http://127.0.0.1:8000/activate/{activation_token}"
  html_body = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
        <h2 style="color: #007bff;">Вітаємо у безпечній системі!</h2>
        <p>Дякуємо за реєстрацію. Для активації вашого облікового запису натисніть кнопку нижче:</p>
        <a href="{activation_link}" style="background: #007bff; color: white; padding: 12px 20px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">Активувати акаунт</a>
        <p style="margin-top: 20px;">Або скопіюйте це посилання у браузер:<br><a href="{activation_link}">{activation_link}</a></p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #666; font-size: 12px;">Термін дії посилання: 24 години.</p>
    </div>
    """
  send_email(email, "Активація облікового запису", html_body)

  return {
      "message": (
          "Реєстрація успішна! Лист з активацією надіслано на вашу електронну"
          " пошту."
      )
  }


# --- Завдання 3: Активація облікового запису ---
@app.get("/activate/{token}", response_class=HTMLResponse)
def activate_account(token: str, db: Session = Depends(get_db)):
  user = (
      db.query(models.User)
      .filter(models.User.activation_token == token)
      .first()
  )
  if not user or user.activation_token_expires < datetime.utcnow():
    raise HTTPException(
        status_code=400, detail="Токен активації недійсний або прострочений."
    )

  user.is_active = True
  user.activation_token = None
  user.activation_token_expires = None
  db.commit()

  return """
    <html>
        <body style="font-family: Arial; text-align: center; margin-top: 50px; background: #f4f4f9;">
            <div style="background: white; padding: 40px; border-radius: 8px; display: inline-block; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #28a745;">Обліковий запис успішно активовано!</h2>
                <p>Тепер ви можете увійти у систему під своїм обліковим записом.</p>
                <a href="/login-page" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; margin-top: 15px;">Перейти до сторінки входу</a>
            </div>
        </body>
    </html>
    """


# --- Завдання 4: Вхід у систему з захистом від Brute Force ---
@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
  client_ip = request.client.host
  user = db.query(models.User).filter(models.User.email == email).first()

  if user and user.is_locked:
    if user.lock_until and user.lock_until > datetime.utcnow():
      db.add(
          models.LoginLog(
              email=email, ip_address=client_ip, success=False
          )
      )
      db.commit()
      raise HTTPException(
          status_code=403,
          detail=(
              "Обліковий запис тимчасово заблоковано через перевищену кількість"
              " невдалих спроб входу."
          ),
      )
    else:
      user.is_locked = False
      user.failed_login_attempts = 0
      user.lock_until = None
      db.commit()

  if not user or not security.verify_password(
      password, user.hashed_password
  ):
    if user:
      user.failed_login_attempts += 1
      if user.failed_login_attempts >= 3:
        user.is_locked = True
        user.lock_until = datetime.utcnow() + timedelta(minutes=5)
      db.commit()

    db.add(models.LoginLog(email=email, ip_address=client_ip, success=False))
    db.commit()
    raise HTTPException(status_code=400, detail="Невірний email або пароль.")

  if not user.is_active:
    raise HTTPException(
        status_code=400, detail="Обліковий запис не активовано через пошту."
    )

  user.failed_login_attempts = 0
  db.add(models.LoginLog(email=email, ip_address=client_ip, success=True))
  db.commit()

  if user.is_2fa_enabled:
      request.session["pending_2fa_email"] = email
      return RedirectResponse(url="/login/2fa-page", status_code=status.HTTP_303_SEE_OTHER)

  request.session["user_email"] = email
  return RedirectResponse(url="/profile-page", status_code=status.HTTP_303_SEE_OTHER)


# --- Адмін-панель (Завдання 4: логи та блокування) ---
@app.get("/admin/logs")
def view_logs(db: Session = Depends(get_db)):
  logs = (
      db.query(models.LoginLog)
      .order_by(models.LoginLog.timestamp.desc())
      .all()
  )
  return logs


@app.post("/admin/toggle-lock/{user_id}")
def toggle_user_lock(user_id: int, db: Session = Depends(get_db)):
  user = db.query(models.User).filter(models.User.id == user_id).first()
  if not user:
    raise HTTPException(status_code=404, detail="Користувача не знайдено.")
  user.is_locked = not user.is_locked
  if not user.is_locked:
    user.failed_login_attempts = 0
  db.commit()
  return {
      "message": f"Статус блокування користувача змінено на: {user.is_locked}"
  }


# --- Завдання 7: Відновлення пароля ---
@app.post("/forgot-password")
def forgot_password(email: str = Form(...), db: Session = Depends(get_db)):
  user = db.query(models.User).filter(models.User.email == email).first()
  if user:
    token = security.generate_token()
    user.reset_token = token
    user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
    db.commit()

    # Реальна відправка листа для відновлення пароля
    reset_link = f"http://127.0.0.1:8000/reset-password-page?token={token}"
    html_body = f"""
        <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
            <h2 style="color: #ffc107;">Відновлення пароля</h2>
            <p>Отримано запит на скидання пароля для вашого акаунта у системі.</p>
            <a href="{reset_link}" style="background: #ffc107; color: #333; padding: 12px 20px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">Скинути пароль</a>
            <p style="margin-top: 20px;">Або перейдіть за цим посиланням:<br><a href="{reset_link}">{reset_link}</a></p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">Посилання дійсне протягом 1 години. Якщо ви не запитували відновлення, просто проігноруйте цей лист.</p>
        </div>
        """
    send_email(email, "Відновлення пароля", html_body)

  return {
      "message": (
          "Якщо такий email існує, інструкції з відновлення надіслано на пошту."
      )
  }


@app.get("/reset-password-page", response_class=HTMLResponse)
def reset_password_page(request: Request, token: str = ""):
  return templates.TemplateResponse(
      request, "reset_password.html", {"request": request, "token": token}
  )


@app.post("/reset-password")
def reset_password(
    token: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
  user = (
      db.query(models.User)
      .filter(
          models.User.reset_token == token,
          models.User.reset_token_expires > datetime.utcnow(),
      )
      .first()
  )
  if not user:
    raise HTTPException(
        status_code=400, detail="Токен недійсний або прострочений."
    )

  is_valid, msg = security.validate_password_policy(new_password)
  if not is_valid:
    raise HTTPException(status_code=400, detail=msg)

  user.hashed_password = security.get_password_hash(new_password)
  user.reset_token = None
  user.reset_token_expires = None
  db.commit()
  return {"message": "Пароль успішно оновлено."}

# --- Task 5: 2FA Endpoints ---

@app.get("/2fa/setup")
async def setup_2fa(request: Request, db: Session = Depends(get_db)):
    # Simple check for session (we would use JWT in real app)
    email = request.session.get("user_email")
    if not email:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if user.is_2fa_enabled:
        return {"message": "2FA is already enabled"}
    
    secret = pyotp.random_base32()
    otpauth_url = security.get_totp_uri(email, secret)
    
    # Store temp secret in session
    request.session["temp_totp_secret"] = secret
    
    return {"secret": secret, "otpauth_url": otpauth_url}

@app.post("/2fa/enable")
async def enable_2fa(request: Request, code: str = Form(...), db: Session = Depends(get_db)):
    email = request.session.get("user_email")
    temp_secret = request.session.get("temp_totp_secret")
    
    if not email or not temp_secret:
        raise HTTPException(status_code=400, detail="Setup 2FA first")
    
    if security.verify_totp(temp_secret, code):
        user = db.query(models.User).filter(models.User.email == email).first()
        user.totp_secret = temp_secret
        user.is_2fa_enabled = True
        db.commit()
        request.session.pop("temp_totp_secret")
        return {"message": "2FA enabled successfully"}
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP code")

@app.post("/2fa/disable")
async def disable_2fa(request: Request, code: str = Form(...), db: Session = Depends(get_db)):
    email = request.session.get("user_email")
    if not email:
         raise HTTPException(status_code=401, detail="Not authenticated")
         
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user.is_2fa_enabled:
        return {"message": "2FA is already disabled"}
        
    if security.verify_totp(user.totp_secret, code):
        user.is_2fa_enabled = False
        user.totp_secret = None
        db.commit()
        return {"message": "2FA disabled successfully"}
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP code")

@app.get("/login/2fa-page", response_class=HTMLResponse)
def login_2fa_page(request: Request):
    return templates.TemplateResponse(request, "login_2fa.html", {"request": request})
@app.post("/login/2fa")
async def login_2fa(request: Request, code: str = Form(...), db: Session = Depends(get_db)):
    email = request.session.get("pending_2fa_email")
    if not email:
        raise HTTPException(status_code=400, detail="No pending 2FA login")
        
    user = db.query(models.User).filter(models.User.email == email).first()
    if security.verify_totp(user.totp_secret, code):
        request.session.pop("pending_2fa_email")
        request.session["user_email"] = email
        return RedirectResponse(url="/profile-page", status_code=status.HTTP_303_SEE_OTHER)
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP code")


# --- Task 6: OIDC Endpoints ---

@app.get("/auth/login")
async def auth_login(request: Request):
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OIDC error: {str(e)}")
        
    userinfo = token.get('userinfo')
    if not userinfo:
        raise HTTPException(status_code=400, detail="Failed to get userinfo")
        
    email = userinfo.get('email')
    sub = userinfo.get('sub')
    
    user = db.query(models.User).filter((models.User.email == email) | (models.User.oidc_sub == sub)).first()
    
    if not user:
        # Create new user if not exists
        user = models.User(
            email=email,
            hashed_password="OIDC_USER", # Dummy password
            is_active=True,
            oidc_sub=sub
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Link sub if not already linked
        if not user.oidc_sub:
            user.oidc_sub = sub
            db.commit()
            
    request.session["user_email"] = email
    return RedirectResponse(url="/profile-page")