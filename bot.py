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

# Опциональные API-ключи (точные оценки)
IPQS_API_KEY = os.getenv("IPQS_API_KEY")          # IPQualityScore
PROXYCHECK_API_KEY = os.getenv("PROXYCHECK_API_KEY")  # proxycheck.io

bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML)
)
dp = Dispatcher()


def parse_proxy(proxy_str: str) -> dict | None:
    """
    Поддерживает почти все существующие форматы прокси + частые опечатки.
    """
    raw = proxy_str.strip()
    if not raw:
        return None

    scheme = "socks5"
    user = None
    password = None
    host = None
    port = None

    # Поддержка socks5://  socks5:/  socks5:
    proto_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):/{0,2}(.+)$', raw)
    if proto_match:
        possible_scheme = proto_match.group(1).lower()
        rest = proto_match.group(2)
        if possible_scheme in ("socks5", "socks5h", "socks4", "socks", "http", "https", "socks4a"):
            scheme = possible_scheme
            raw = rest

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

    parts = raw.split(":")
    if len(parts) == 2:
        host, port = parts[0], parts[1]
    elif len(parts) == 4:
        host, port, user, password = parts
    elif len(parts) == 3:
        host, port, user = parts
    else:
        return None

    if not host or not port:
        return None
    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            return None
    except ValueError:
        return None

    scheme = scheme.lower()
    if scheme in ("socks", "socks5h", "socks4a"):
        scheme = "socks5"

    return {
        "scheme": scheme,
        "host": host.strip(),
        "port": str(port_int),
        "user": user.strip() if user else None,
        "password": password.strip() if password else None,
    }


def build_proxy_url(data: dict) -> str:
    scheme = data["scheme"]
    host = data["host"]
    port = data["port"]
    user = data.get("user")
    password = data.get("password")

    if user and password:
        return f"{scheme}://{user}:{password}@{host}:{port}"
    return f"{scheme}://{host}:{port}"


async def get_ip_through_proxy(proxy_url: str) -> tuple[str | None, str | None]:
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=20.0,
            verify=False,
            follow_redirects=True
        ) as client:
            r = await client.get("https://api.ipify.org?format=json")
            return r.json()["ip"], None
    except httpx.ProxyError as e:
        return None, f"ProxyError: {str(e)}"
    except httpx.ConnectError as e:
        return None, f"ConnectError: {str(e)}"
    except httpx.TimeoutException as e:
        return None, f"Timeout: {str(e)}"
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)}"


# ================== ТОЧНЫЕ ПРОВЕРКИ (с API-ключами) ==================

async def check_ipqs(ip: str, client: httpx.AsyncClient) -> dict | None:
    if not IPQS_API_KEY:
        return None
    try:
        url = (
            f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"
            f"?strictness=1&allow_public_access_points=true&fast=true&mobile=true"
        )
        r = await client.get(url, timeout=12.0)
        data = r.json()
        if not data.get("success"):
            return {"source": "IPQualityScore", "error": data.get("message", "API error")}
        return {
            "source": "IPQualityScore",
            "fraud_score": data.get("fraud_score"),
            "proxy": data.get("proxy"),
            "vpn": data.get("vpn"),
            "tor": data.get("tor"),
            "is_crawler": data.get("is_crawler"),
            "recent_abuse": data.get("recent_abuse"),
            "bot_status": data.get("bot_status"),
            "ISP": data.get("ISP"),
            "organization": data.get("organization"),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "raw": data
        }
    except Exception as e:
        return {"source": "IPQualityScore", "error": str(e)[:120]}


async def check_proxycheck(ip: str, client: httpx.AsyncClient) -> dict | None:
    if not PROXYCHECK_API_KEY:
        return None
    try:
        url = (
            f"https://proxycheck.io/v2/{ip}"
            f"?key={PROXYCHECK_API_KEY}&vpn=1&asn=1&risk=1&port=1&seen=1&days=7"
        )
        r = await client.get(url, timeout=12.0)
        data = r.json()
        if data.get("status") != "ok":
            return {"source": "proxycheck.io", "error": data.get("message", "API error")}
        
        info = data.get(ip, {})
        return {
            "source": "proxycheck.io",
            "proxy": info.get("proxy") == "yes",
            "type": info.get("type"),
            "risk": info.get("risk"),          # 0-100
            "provider": info.get("provider"),
            "organisation": info.get("organisation"),
            "asn": info.get("asn"),
            "isocode": info.get("isocode"),
            "raw": info
        }
    except Exception as e:
        return {"source": "proxycheck.io", "error": str(e)[:120]}


# ================== БЕСПЛАТНЫЕ ПРОВЕРКИ ==================

async def check_scamalytics(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"https://scamalytics.com/ip/{ip}", timeout=12.0)
        text = r.text
        score_match = re.search(r'Fraud Score:\s*(\d+)', text)
        score = int(score_match.group(1)) if score_match else None
        if score is None:
            return {"source": "Scamalytics", "raw": "не найден"}
        risk = "Low" if score < 40 else "Medium" if score < 75 else "High"
        return {"source": "Scamalytics", "score": score, "risk": risk, "raw": f"{score}/100"}
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
        return {
            "source": "IPLogs",
            "score": data.get("score"),
            "verdict": data.get("verdict", "?"),
            "is_vpn": data.get("is_vpn", False),
            "raw": f"score={data.get('score')}, verdict={data.get('verdict')}, vpn={data.get('is_vpn')}"
        }
    except Exception as e:
        return {"source": "IPLogs", "error": str(e)[:100]}


async def check_fraudcache(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"https://fraudcache.com/api/v1/check/{ip}", timeout=12.0)
        data = r.json()
        privacy = data.get("enrichment", {}).get("privacy", {})
        conn = data.get("enrichment", {}).get("connection", {})
        return {
            "source": "Fraudcache",
            "listed": data.get("listed", False),
            "is_proxy": privacy.get("is_proxy"),
            "is_vpn": privacy.get("is_vpn"),
            "is_tor": privacy.get("is_tor"),
            "is_hosting": conn.get("is_hosting"),
        }
    except Exception as e:
        return {"source": "Fraudcache", "error": str(e)[:100]}


async def check_ipapi(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,as,mobile,proxy,hosting",
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
            "proxy": data.get("proxy"),
            "hosting": data.get("hosting"),
            "mobile": data.get("mobile"),
        }
    except Exception as e:
        return {"source": "ip-api", "error": str(e)[:100]}


async def check_proxy(proxy_str: str) -> str:
    data = parse_proxy(proxy_str)
    if not data:
        return (
            "❌ Не удалось распознать формат прокси.\n\n"
            "Примеры:\n"
            "• <code>socks5://user:pass@host:port</code>\n"
            "• <code>user:pass@host:port</code>\n"
            "• <code>host:port:user:pass</code>"
        )

    proxy_url = build_proxy_url(data)
    scheme = data["scheme"]
    host = data["host"]
    port = data["port"]

    ip, error = await get_ip_through_proxy(proxy_url)
    if not ip:
        return (
            "❌ Прокси не работает\n\n"
            f"<b>Реальная ошибка:</b>\n<code>{error}</code>"
        )

    lines = [
        f"<b>Прокси:</b> <code>{host}:{port}</code>",
        f"<b>Тип:</b> {scheme.upper()}",
        f"<b>Выходной IP:</b> <code>{ip}</code>",
        ""
    ]

    async with httpx.AsyncClient(
        timeout=20.0,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (compatible; ProxyCheckerBot/1.1)"}
    ) as client:

        # Сначала точные проверки (если есть ключи)
        accurate_tasks = []
        if IPQS_API_KEY:
            accurate_tasks.append(check_ipqs(ip, client))
        if PROXYCHECK_API_KEY:
            accurate_tasks.append(check_proxycheck(ip, client))

        accurate_results = await asyncio.gather(*accurate_tasks) if accurate_tasks else []

        # Бесплатные проверки
        free_results = await asyncio.gather(
            check_scamalytics(ip, client),
            check_iplogs(ip, client),
            check_fraudcache(ip, client),
            check_ipapi(ip, client),
        )

    # === Вывод точных оценок ===
    has_accurate = False
    accurate_scores = []

    if accurate_results:
        lines.append("<b>══════ ТОЧНЫЕ ОЦЕНКИ ══════</b>")
        for res in accurate_results:
            if not res:
                continue
            has_accurate = True
            src = res.get("source")

            if "error" in res:
                lines.append(f"• <b>{src}:</b> ⚠️ {res['error']}")
                continue

            if src == "IPQualityScore":
                score = res.get("fraud_score")
                lines.append(f"• <b>IPQualityScore:</b> <code>{score}/100</code>")
                flags = []
                if res.get("proxy"): flags.append("PROXY")
                if res.get("vpn"): flags.append("VPN")
                if res.get("tor"): flags.append("TOR")
                if res.get("recent_abuse"): flags.append("ABUSE")
                if res.get("bot_status"): flags.append("BOT")
                if flags:
                    lines.append(f"  └ {', '.join(flags)}")
                if isinstance(score, (int, float)):
                    accurate_scores.append(score)

            elif src == "proxycheck.io":
                risk = res.get("risk")
                lines.append(f"• <b>proxycheck.io:</b> risk=<code>{risk}</code>, type={res.get('type')}")
                if res.get("proxy"):
                    lines.append(f"  └ PROXY detected, provider={res.get('provider')}")
                if isinstance(risk, (int, float)):
                    accurate_scores.append(risk)

        lines.append("")

    # === Бесплатные ===
    lines.append("<b>══════ Бесплатные проверки ══════</b>")
    free_scores = []

    for res in free_results:
        src = res.get("source", "?")
        if "error" in res:
            lines.append(f"• <b>{src}:</b> ⚠️ {res['error']}")
            continue

        if src == "Scamalytics":
            lines.append(f"• <b>Scamalytics:</b> <code>{res.get('raw')}</code> ({res.get('risk')} Risk)")
            if isinstance(res.get("score"), int):
                free_scores.append(res["score"])
        elif src == "IPLogs":
            lines.append(f"• <b>IPLogs:</b> <code>{res.get('raw')}</code>")
        elif src == "Fraudcache":
            flags = []
            if res.get("listed"): flags.append("BLACKLIST")
            if res.get("is_proxy"): flags.append("PROXY")
            if res.get("is_vpn"): flags.append("VPN")
            if res.get("is_hosting"): flags.append("HOSTING")
            lines.append(f"• <b>Fraudcache:</b> {', '.join(flags) if flags else 'чисто'}")
        elif src == "ip-api":
            lines.append(f"• <b>ip-api:</b> proxy={res.get('proxy')}, hosting={res.get('hosting')}")
            lines.append(f"  └ {res.get('country')}, {res.get('city')} | {res.get('isp')}")

    # === Итоговый вердикт ===
    lines.append("")
    if accurate_scores:
        avg = sum(accurate_scores) / len(accurate_scores)
        if avg < 25:
            verdict = "✅ Хороший / Низкий риск"
        elif avg < 55:
            verdict = "⚠️ Средний риск"
        elif avg < 80:
            verdict = "🟠 Высокий риск"
        else:
            verdict = "❌ Очень высокий риск"
        lines.append(f"<b>Итоговый вердикт (точные):</b> {verdict}")
        lines.append(f"<b>Средний точный балл:</b> ~{avg:.0f}/100")
    else:
        lines.append("<b>Итоговый вердикт:</b> только бесплатные источники (менее точные)")
        if free_scores:
            avg = sum(free_scores) / len(free_scores)
            lines.append(f"Средний бесплатный балл: ~{avg:.0f}/100")

    if not has_accurate:
        lines.append("")
        lines.append("💡 Для точной оценки добавь API-ключи IPQS / proxycheck.io")

    lines += [
        "",
        "<b>WebRTC / DNS Leak:</b> проверяй вручную через прокси",
        "• https://browserleaks.com/webrtc",
        "• https://ipleak.net"
    ]

    return "\n".join(lines)


@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    keys_status = []
    if IPQS_API_KEY:
        keys_status.append("✅ IPQualityScore")
    else:
        keys_status.append("❌ IPQualityScore")
    if PROXYCHECK_API_KEY:
        keys_status.append("✅ proxycheck.io")
    else:
        keys_status.append("❌ proxycheck.io")

    await message.answer(
        "Пришли прокси в любом формате.\n\n"
        f"<b>Точные API:</b>\n" + "\n".join(keys_status) + "\n\n"
        "Если ключи не добавлены — используются только бесплатные источники."
    )


@dp.message(F.text)
async def handle_message(message: types.Message):
    status = await message.answer("🔄 Проверяю прокси...")
    try:
        result = await check_proxy(message.text)
        await status.edit_text(result)
    except Exception as e:
        await status.edit_text(f"❌ Ошибка:\n<code>{str(e)[:400]}</code>")


async def main():
    print("Bot started")
    print(f"IPQS key: {'set' if IPQS_API_KEY else 'not set'}")
    print(f"proxycheck key: {'set' if PROXYCHECK_API_KEY else 'not set'}")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
