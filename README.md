# Proxy Fraud Score Checker Bot

Telegram-бот для проверки прокси на Fraud Score сразу по нескольким лучшим бесплатным сервисам 2026 года:

- Scamalytics
- IPLogs
- Fraudcache
- ip-api

## Поддерживаемые форматы прокси (любые)

Бот понимает почти все существующие форматы:

```
socks5://user:pass@host:port
socks5://host:port
user:pass@host:port
host:port:user:pass
host:port
http://user:pass@host:port
http://host:port
https://host:port
```

Если протокол не указан — по умолчанию используется `socks5`.

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

### 4. Деплой
Railway сам подхватит `Procfile` и запустит бота командой `python bot.py`.

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
