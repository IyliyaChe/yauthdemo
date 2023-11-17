# FastApi-server
import base64
# Чтобы можно было указать, что куки опциональны
from typing import Optional
# модули для подписи данных
import hmac
import hashlib
import json

# Импорт необходимых модулей, в том числе для отправки
# ответа в браузер
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

# Создание экземпляра приложения
app = FastAPI()

SECRET_KEY = '951d6e1f69fe26182cb3542d720d7d5c837f7d0713b63d7b974f0b5349ace4d1'
PASSWORD_SALT = "5ba0adc177b5b4c4d3e6c90c25b503ffa1e4b8a171f2cff1dca4ee2dd5b624c5"


# Функция для формирования цифровой подписи
def sign_data(data: str) -> str:
    '''Возвращает подписанные данные'''
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

# Функция декодирует цифровую подпись
def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username
    
# Функция для верификации пароля
def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return  password_hash == stored_password_hash

users = {
    'alex': {
        'name': 'Alex',
        'password': '08d5f8893dc182f35e5fcd444bd548b08e7ab34b5f083015c26b2e2957db79fb',
        'balance': 100_000
    },
    'petr': {
        'name': 'Petr',
        'password': '6e72c6ecc3c0fa95ca04e4af08c112b86630956daafe0fce901f31a40cd07c6a',
        'balance': 555_555
    }
}

# Функция для формирования ответа, когда приходит запрос
# на корневую страницу сайта
@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    # Выход если имени пользователя не передано
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    # Если подпись не валидна, кукис удаляются
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key='username')
        return response
    # Проверка, есть ли такой пользователь и удаление кукис
    # если такого нет
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key='username')
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс {users[valid_username]['balance']}",
        media_type="text/html")


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form()):
    # Проверка, что пользователь существует и пароль верный
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю!"
            }),
            media_type="application/json")
    
    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}!<br />Ваш баланс {user['balance']}."
        }),
        media_type="application/json")
    
    # Установка кукис
    username_signed = base64.b64encode(username.encode()).decode()+'.'+sign_data(username)
    response.set_cookie(key='username', value=username_signed, max_age=1000000, expires=1000000)
    return response