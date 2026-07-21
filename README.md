# Proxy Fraud Score Checker Bot

Telegram-бот для проверки SOCKS5/HTTP прокси на Fraud Score сразу по нескольким лучшим бесплатным сервисам 2026 года:

- Scamalytics
- IPLogs
- Fraudcache
- ip-api

## Формат прокси

```
socks5://логин:пароль@хост:порт
```

## Деплой на Railway (из GitHub)

### 1. Создай репозиторий на GitHub
Загрузи все файлы из этой папки в новый репозиторий.

### 2. Создай проект на Railway
1. Зайди на [railway.app](https://railway.app)
2. New Project → Deploy from GitHub repo
3. Выбери свой репозиторий

### 3. Добавь переменную окружения
В настройках сервиса → Variables:

```
BOT_TOKEN = твой_токен_от_BotFather
```

### 4. Настройки деплоя
Railway обычно сам подхватывает `Procfile`.  
Если нужно вручную:

- **Start Command**: `python bot.py`
- Или оставь как есть (Procfile уже содержит `worker: python bot.py`)

### 5. Деплой
Нажми Deploy. Бот запустится и будет работать 24/7.

## Локальный запуск (для теста)

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
export BOT_TOKEN="твой_токен"
python bot.py
```

## Важно
- Токен бота **никогда** не коммить в GitHub.
- Используй только переменные окружения Railway.
