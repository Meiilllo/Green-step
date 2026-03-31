Green Step

Структура проекта:
- backend/ - Node.js + Express API
- frontend/ - статический frontend на HTML/CSS/JS

Что уже подготовлено для деплоя:
- backend умеет раздавать frontend сам
- frontend использует относительный API URL и не зависит от localhost
- uploads доступны через `/uploads`
- база и загруженные файлы хранятся в единой папке `backend/storage`
- есть `.env.example` для production-настроек

Локальный запуск:
1. Перейди в `backend`
2. Выполни `npm install`
3. Выполни `npm start`
4. Открой `http://localhost:3000`

Production-запуск:
1. Залей проект на сервер
2. Перейди в `backend`
3. Установи зависимости: `npm install --omit=dev`
4. Создай `.env` на основе `.env.example`
5. Запусти приложение: `npm start`

Переменные окружения:
- `PORT` - порт приложения
- `NODE_ENV` - режим запуска, обычно `production`
- `STORAGE_DIR` - путь к общей папке хранения базы и загруженных файлов
- `CORS_ORIGIN` - нужен только если frontend и backend будут на разных доменах

Маршруты:
- `/` - экран входа
- `/admin` - админка
- `/user` - кабинет пользователя
- `/api/*` - backend API
- `/uploads/*` - загруженные файлы

Тестовый администратор:
- логин: `admin`
- пароль: `admin`

Что важно перед боевым запуском:
- пароли сейчас хранятся в открытом виде, для production лучше добавить хеширование
- данные сейчас хранятся в `backend/storage/db.json`
- загруженные фото хранятся в `backend/storage/uploads`
- если сервер будет пересоздаваться, папку `backend/storage` нужно сохранять как persistent storage

Railway:
- для Railway теперь достаточно одного volume
- рекомендуемый mount path: `/app/backend/storage`
