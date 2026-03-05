# Secure Authentication Microservice

Node.js микросервис для лабораторной работы №1 по защищенной аутентификации.

## Возможности

- Регистрация и вход с `bcrypt` (соль + хеш).
- JWT со временем жизни **15 минут**.
- Ограничение неудачных попыток входа: **3 попытки / минуту** (на пару `username+ip`).
- Дополнительный IP rate limit на `/login`.
- Ролевая модель: `user`, `moderator`, `admin`.
- Запрет параллельных сессий: у пользователя активна только последняя сессия.
- Логирование всех попыток входа в `auth.log`.
- Экранирование выводимых пользовательских данных.
- Обновление токена через `/token/refresh`.
- Дополнительно: восстановление пароля одноразовым токеном.

## Запуск

```bash
npm install
JWT_SECRET="super_secret" npm start
```

## Основные маршруты

- `POST /register` — регистрация (`username`, `password`, опционально `role`).
- `POST /login` — вход (`username`, `password`).
- `POST /logout` — выход (JWT).
- `POST /token/refresh` — обновление JWT.
- `GET /me` — информация о текущем пользователе.
- `GET /moderator` — для `moderator|admin`.
- `GET /admin` — только для `admin`.
- `POST /password-reset/request` — запрос токена восстановления.
- `POST /password-reset/confirm` — подтверждение сброса.

## Тесты

```bash
npm test
```


> Безопасность по умолчанию: регистрация привилегированных ролей отключена. 
> Чтобы разрешить это для учебных сценариев, установите `ALLOW_PRIVILEGED_ROLE_REGISTRATION=true`.
