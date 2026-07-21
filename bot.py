import asyncio
import os
import re
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import CommandStart
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
import httpx

# ================== CONFIG ==================
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable is not set!")

bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML)
)
dp = Dispatcher()


def parse_proxy(proxy_str: str) -> dict | None:
    """
    Поддерживает почти все существующие форматы прокси + частые опечатки:

    1. protocol://user:pass@host:port
    2. protocol:/user:pass@host:port   ← частая опечатка (один слэш)
    3. protocol:user:pass@host:port
    4. user:pass@host:port
    5. host:port:user:pass
    6. host:port
    """
    raw = proxy_str.strip()
    if not raw:
        return None

    scheme = "socks5"  # дефолт
    user = None
    password = None
    host = None
    port = None

    # === Убираем протокол (поддерживаем // и / и даже без слэшей) ===
    # Примеры: socks5://  |  socks5:/  |  socks5:
    proto_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):/{0,2}(.+)$', raw)
    if proto_match:
        possible_scheme = proto_match.group(1).lower()
        rest = proto_match.group(2)

        # Только если это действительно похоже на протокол
        if possible_scheme in ("socks5", "socks5h", "socks4", "socks", "http", "https", "socks4a"):
            scheme = possible_scheme
            raw = rest

    # === user:pass@host:port ===
    if "@" in raw:
        try:
            auth_part, hostport = raw.rsplit("@", 1)
            if ":" in auth_part:
                user, password = auth_part.split(":", 1)
            else:
                user = auth_part
            raw = hostport
        except Exception:
            return None

    # === Теперь raw = host:port  или  host:port:user:pass ===
    parts = raw.split(":")

    if len(parts) == 2:
        # host:port
        host, port = parts[0], parts[1]
    elif len(parts) == 4:
        # host:port:user:pass
        host, port, user, password = parts
    elif len(parts) == 3:
        # host:port:user
        host, port, user = parts
    else:
        return None

    # Валидация
    if not host or not port:
        return None
    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            return None
    except ValueError:
        return None

    # Нормализация схемы
    scheme = scheme.lower()
    if scheme in ("socks", "socks5h", "socks4a"):
        scheme = "socks5"
    if scheme == "socks4":
        scheme = "socks4"

    return {
        "scheme": scheme,
        "host": host.strip(),
        "port": str(port_int),
        "user": user.strip() if user else None,
        "password": password.strip() if password else None,
    }


def build_proxy_url(data: dict) -> str:
    """Собирает правильный URL для httpx"""
    scheme = data["scheme"]
    host = data["host"]
    port = data["port"]
    user = data.get("user")
    password = data.get("password")

    if user and password:
        return f"{scheme}://{user}:{password}@{host}:{port}"
    return f"{scheme}://{host}:{port}"


async def get_ip_through_proxy(proxy_url: str) -> str | None:
    try:
        async with httpx.AsyncClient(
            proxies=proxy_url,
            timeout=18.0,
            verify=False,
            follow_redirects=True
        ) as client:
            r = await client.get("https://api.ipify.org?format=json")
            return r.json()["ip"]
    except Exception:
        return None


async def check_scamalytics(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"https://scamalytics.com/ip/{ip}", timeout=12.0)
        text = r.text
        score_match = re.search(r'Fraud Score:\s*(\d+)', text)
        score = int(score_match.group(1)) if score_match else None
        if score is None:
            return {"source": "Scamalytics", "raw": "не найден"}
        risk = "Low" if score < 40 else "Medium" if score < 75 else "High"
        return {
            "source": "Scamalytics",
            "score": score,
            "risk": risk,
            "raw": f"{score}/100"
        }
    except Exception as e:
        return {"source": "Scamalytics", "error": str(e)[:100]}


async def check_iplogs(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.post(
            "https://iplogs.com/v1/check",
            json={"ip": ip},
            timeout=15.0,
            headers={"Content-Type": "application/json", "User-Agent": "ProxyCheckerBot/1.0"}
        )
        data = r.json()
        score = data.get("score")
        verdict = data.get("verdict", "?")
        is_vpn = data.get("is_vpn", False)
        return {
            "source": "IPLogs",
            "score": score,
            "verdict": verdict,
            "is_vpn": is_vpn,
            "raw": f"score={score}, verdict={verdict}, vpn={is_vpn}"
        }
    except Exception as e:
        return {"source": "IPLogs", "error": str(e)[:100]}


async def check_fraudcache(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"https://fraudcache.com/api/v1/check/{ip}",
            timeout=12.0
        )
        data = r.json()
        listed = data.get("listed", False)
        privacy = data.get("enrichment", {}).get("privacy", {})
        conn = data.get("enrichment", {}).get("connection", {})
        return {
            "source": "Fraudcache",
            "listed": listed,
            "is_proxy": privacy.get("is_proxy"),
            "is_vpn": privacy.get("is_vpn"),
            "is_tor": privacy.get("is_tor"),
            "is_hosting": conn.get("is_hosting"),
            "connection_type": conn.get("type"),
            "raw": f"listed={listed}, proxy={privacy.get('is_proxy')}, vpn={privacy.get('is_vpn')}, hosting={conn.get('is_hosting')}"
        }
    except Exception as e:
        return {"source": "Fraudcache", "error": str(e)[:100]}


async def check_ipapi(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,as,mobile,proxy,hosting,query",
            timeout=10.0
        )
        data = r.json()
        if data.get("status") != "success":
            return {"source": "ip-api", "error": data.get("message", "unknown")}
        return {
            "source": "ip-api",
            "country": f"{data.get('country')} ({data.get('countryCode')})",
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "mobile": data.get("mobile"),
            "proxy": data.get("proxy"),
            "hosting": data.get("hosting"),
        }
    except Exception as e:
        return {"source": "ip-api", "error": str(e)[:100]}


async def check_proxy(proxy_str: str) -> str:
    data = parse_proxy(proxy_str)
    if not data:
        return (
            "❌ Не удалось распознать формат прокси.\n\n"
            "Поддерживаются почти все форматы:\n"
            "• <code>socks5://user:pass@host:port</code>\n"
            "• <code>user:pass@host:port</code>\n"
            "• <code>host:port:user:pass</code>\n"
            "• <code>host:port</code>\n"
            "• <code>http://host:port</code>\n"
            "и другие"
        )

    proxy_url = build_proxy_url(data)
    scheme = data["scheme"]
    host = data["host"]
    port = data["port"]

    # Получаем реальный IP через прокси
    ip = await get_ip_through_proxy(proxy_url)
    if not ip:
        return (
            "❌ Прокси не работает\n\n"
            "Возможные причины:\n"
            "• Неверный логин/пароль\n"
            "• Прокси оффлайн\n"
            "• Неправильный тип (socks5/http)\n"
            "• Таймаут соединения"
        )

    lines = [
        f"<b>Прокси:</b> <code>{host}:{port}</code>",
        f"<b>Тип:</b> {scheme.upper()}",
        f"<b>Выходной IP:</b> <code>{ip}</code>",
        "",
        "<b>══════ Fraud Score / Risk ══════</b>"
    ]

    async with httpx.AsyncClient(
        timeout=20.0,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ProxyCheckerBot/1.0)"}
    ) as client:
        results = await asyncio.gather(
            check_scamalytics(ip, client),
            check_iplogs(ip, client),
            check_fraudcache(ip, client),
            check_ipapi(ip, client),
            return_exceptions=False
        )

    scores = []

    for res in results:
        src = res.get("source", "Unknown")

        if "error" in res:
            lines.append(f"• <b>{src}:</b> ⚠️ {res['error']}")
            continue

        if src == "Scamalytics":
            lines.append(f"• <b>Scamalytics:</b> <code>{res['raw']}</code> ({res.get('risk', '?')} Risk)")
            if isinstance(res.get("score"), int):
                scores.append(res["score"])

        elif src == "IPLogs":
            lines.append(f"• <b>IPLogs:</b> <code>{res['raw']}</code>")
            if isinstance(res.get("score"), (int, float)):
                scores.append(int(float(res["score"]) * 100))

        elif src == "Fraudcache":
            flags = []
            if res.get("listed"):
                flags.append("BLACKLIST")
            if res.get("is_proxy"):
                flags.append("PROXY")
            if res.get("is_vpn"):
                flags.append("VPN")
            if res.get("is_tor"):
                flags.append("TOR")
            if res.get("is_hosting"):
                flags.append("HOSTING")
            flag_str = ", ".join(flags) if flags else "чисто"
            lines.append(f"• <b>Fraudcache:</b> {flag_str}")

        elif src == "ip-api":
            lines.append(
                f"• <b>ip-api:</b> proxy={res.get('proxy')}, "
                f"hosting={res.get('hosting')}, mobile={res.get('mobile')}"
            )
            lines.append(
                f"  └ {res.get('country')}, {res.get('city')} | {res.get('isp')}"
            )

    lines.append("")
    if scores:
        avg = sum(scores) / len(scores)
        if avg < 30:
            verdict = "✅ Хороший / Низкий риск"
        elif avg < 60:
            verdict = "⚠️ Средний риск"
        else:
            verdict = "❌ Высокий риск (скорее всего детектится)"
        lines.append(f"<b>Итоговый вердикт:</b> {verdict}")
        lines.append(f"<b>Средний балл:</b> ~{avg:.0f}/100")
    else:
        lines.append("<b>Итоговый вердикт:</b> не удалось рассчитать средний балл")

    lines += [
        "",
        "<b>WebRTC / DNS Leak:</b>",
        "Полноценную проверку WebRTC из бота сделать нельзя.",
        "Проверь вручную через этот прокси:",
        "• https://browserleaks.com/webrtc",
        "• https://ipleak.net",
        "• https://whoer.net"
    ]

    return "\n".join(lines)


@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    await message.answer(
        "Пришли прокси в <b>любом</b> формате:\n\n"
        "• <code>socks5://user:pass@host:port</code>\n"
        "• <code>user:pass@host:port</code>\n"
        "• <code>host:port:user:pass</code>\n"
        "• <code>host:port</code>\n"
        "• <code>http://host:port</code>\n\n"
        "Я автоматически определю тип и проверю Fraud Score."
    )


@dp.message(F.text)
async def handle_message(message: types.Message):
    status = await message.answer("🔄 Проверяю прокси по всем сервисам (15–25 сек)...")
    try:
        result = await check_proxy(message.text)
        await status.edit_text(result)
    except Exception as e:
        await status.edit_text(f"❌ Ошибка при проверке:\n<code>{str(e)[:300]}</code>")


async def main():
    print("Bot started successfully")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
