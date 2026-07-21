# Proxy Fraud Score Checker Bot

Telegram-бот для точной проверки прокси на Fraud Score.

### Что умеет
- Принимает почти любой формат прокси
- Точные оценки через **IPQualityScore** и **proxycheck.io** (если указать ключи)
- Бесплатные проверки (Scamalytics, IPLogs, Fraudcache и др.)
- Показывает реальную ошибку, если прокси не работает

---

## Деплой на Railway

### 1. Залей файлы в GitHub репозиторий

### 2. Создай проект на Railway → Deploy from GitHub

### 3. Добавь переменные окружения

Обязательная:
```
BOT_TOKEN = твой_токен_от_BotFather
```

Рекомендуемые (для точной оценки):
```
IPQS_API_KEY = твой_ключ_от_IPQualityScore
PROXYCHECK_API_KEY = твой_ключ_от_proxycheck.io
```

---

## Как получить бесплатные API-ключи

### IPQualityScore (рекомендуется)
1. Зайди на https://www.ipqualityscore.com
2. Зарегистрируйся (бесплатно)
3. В личном кабинете скопируй API Key
4. Лимит: **1000 проверок в месяц**

### proxycheck.io
1. Зайди на https://proxycheck.io
2. Зарегистрируйся
3. В Dashboard скопируй API Key
4. Лимит: **1000 проверок в день**

---

## Локальный запуск

```bash
pip install -r requirements.txt
export BOT_TOKEN="..."
export IPQS_API_KEY="..."          # опционально
export PROXYCHECK_API_KEY="..."    # опционально
python bot.py
```

---

## Важно
- Без ключей бот работает, но оценки менее точные
- С ключами IPQS + proxycheck.io — значительно ближе к реальному антифроду
