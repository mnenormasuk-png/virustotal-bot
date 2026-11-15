
import os
import time
import threading
import hashlib
import html
import requests
from flask import Flask, request

app = Flask(__name__)

TG = os.environ["BOT_TOKEN"]
VT = os.environ["VT_API_KEY"]

TG_API = f"https://api.telegram.org/bot{TG}"
VT_API = "https://www.virustotal.com/api/v3"

HEADERS = {"x-apikey": VT}

MAX_SIZE = 50 * 1024 * 1024

VIDEO_EXTENSIONS = (
    ".gif", ".mp4", ".mov", ".webm", ".avi",
    ".mkv", ".mpeg", ".mpg", ".3gp", ".m4v"
)


def send(chat_id, text):
    try:
        response = requests.post(
            TG_API + "/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML"
            },
            timeout=20
        )
        response.raise_for_status()

        result = response.json()
        if not result.get("ok"):
            print("TELEGRAM ERROR:", result)

    except Exception as e:
        print("SEND ERROR:", repr(e))


def send_long(chat_id, text):
    while text:
        if len(text) <= 4000:
            send(chat_id, text)
            break

        cut = text.rfind("\n\n", 0, 4000)
        if cut == -1:
            cut = 4000

        send(chat_id, text[:cut])
        text = text[cut:].lstrip()


def is_video_or_gif(doc):
    name = (doc.get("file_name") or "").lower()
    mime = (doc.get("mime_type") or "").lower()

    return (
        name.endswith(VIDEO_EXTENSIONS)
        or mime.startswith("video/")
        or mime == "image/gif"
    )


def has_video_or_gif_signature(data):
    if data.startswith((b"GIF87a", b"GIF89a")):
        return True

    if len(data) >= 12 and data[4:8] == b"ftyp":
        return True

    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return True

    if (
        len(data) >= 12
        and data[:4] == b"RIFF"
        and data[8:12] == b"AVI "
    ):
        return True

    return False


def get_report(sha):
    response = requests.get(
        f"{VT_API}/files/{sha}",
        headers=HEADERS,
        timeout=30
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()

    return response.json()["data"]["attributes"]


def upload_file(name, file_data):
    if len(file_data) <= 32 * 1024 * 1024:
        response = requests.post(
            VT_API + "/files",
            headers=HEADERS,
            files={"file": (name, file_data)},
            timeout=300
        )
    else:
        url_response = requests.get(
            VT_API + "/files/upload_url",
            headers=HEADERS,
            timeout=30
        )
        url_response.raise_for_status()

        upload_url = url_response.json()["data"]

        response = requests.post(
            upload_url,
            files={"file": (name, file_data)},
            timeout=300
        )

    response.raise_for_status()
    return response.json()["data"]["id"]


def make_report(name, sha, data, cached=False):
    stats = data.get(
        "last_analysis_stats",
        data.get("stats", {})
    )

    results = data.get(
        "last_analysis_results",
        data.get("results", {})
    )

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)

    total = sum(
        value for value in stats.values()
        if isinstance(value, int)
    )

    if malicious:
        verdict = "🔴 ОБНАРУЖЕНА УГРОЗА"
    elif suspicious:
        verdict = "🟠 ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ"
    else:
        verdict = "🟢 УГРОЗ НЕ ОБНАРУЖЕНО"

    detections = []

    for engine, item in results.items():
        if item.get("category") in ("malicious", "suspicious"):
            threat = item.get("result") or "Название не указано"

            detections.append(
                f"• {html.escape(str(engine))}: "
                f"{html.escape(str(threat))}"
            )

    report = (
        f"{verdict}\n\n"
        f"📁 Файл: {html.escape(str(name))}\n"
        f"🧪 Всего проверок: {total}\n\n"
        f"🔴 Обнаружено: {malicious}\n"
        f"🟠 Подозрительно: {suspicious}\n"
        f"🟢 Без обнаружений: {undetected + harmless}\n"
    )

    if cached:
        report += "\n⚡ Использован сохранённый отчёт VirusTotal.\n"

    if detections:
        report += "\n🦠 ОБНАРУЖЕННЫЕ УГРОЗЫ:\n\n"
        report += "\n\n".join(detections)
    else:
        report += "\n🦠 Обнаруженных угроз нет."

    report += (
        "\n\n<a href=\"https://www.virustotal.com/gui/file/"
        f"{sha}\">📊 Открыть полный отчёт VirusTotal</a>"
    )

    return report


def scan(chat_id, doc):
    try:
        file_id = doc["file_id"]
        name = doc.get("file_name") or "file"

        if doc.get("file_size", 0) > MAX_SIZE:
            send(chat_id, "Файл больше 50 МБ.")
            return

        info_response = requests.get(
            TG_API + "/getFile",
            params={"file_id": file_id},
            timeout=30
        )
        info_response.raise_for_status()

        info = info_response.json()

        if not info.get("ok"):
            send(chat_id, "Не удалось получить файл из Telegram.")
            return

        path = info["result"]["file_path"]

        content = requests.get(
            f"https://api.telegram.org/file/bot{TG}/{path}",
            timeout=120
        )
        content.raise_for_status()

        file_data = content.content

        if len(file_data) > MAX_SIZE:
            send(chat_id, "Файл больше 50 МБ.")
            return

        if has_video_or_gif_signature(file_data):
            send(chat_id, "Видео и GIF проверять нельзя.")
            return

        sha = hashlib.sha256(file_data).hexdigest()

        send(chat_id, "🔍 Закидываю файл в VirusTotal...")

        old_report = get_report(sha)

        if old_report is not None:
            send_long(
                chat_id,
                make_report(name, sha, old_report, cached=True)
            )
            return

        analysis_id = upload_file(name, file_data)

        send(chat_id, "⏳ Файл отправлен. Ожидаю результат...")

        for _ in range(60):
            time.sleep(5)

            result = requests.get(
                f"{VT_API}/analyses/{analysis_id}",
                headers=HEADERS,
                timeout=30
            )
            result.raise_for_status()

            data = result.json()["data"]["attributes"]

            if data.get("status") == "completed":
                break

        else:
            send(
                chat_id,
                "Проверка ещё выполняется. "
                "Открой отчёт VirusTotal по ссылке ниже:\n"
                f"https://www.virustotal.com/gui/file/{sha}"
            )
            return

        final_report = get_report(sha)

        if final_report is None:
            final_report = data

        send_long(
            chat_id,
            make_report(name, sha, final_report)
        )

    except requests.HTTPError as e:
        print("HTTP ERROR:", repr(e))

        if e.response is not None:
            print("DETAILS:", e.response.text[:1000])

        send(chat_id, "Ошибка запроса. Проверь Logs на Render.")

    except Exception as e:
        print("ERROR:", repr(e))
        send(chat_id, "Ошибка проверки. Попробуй позже.")


@app.route("/", methods=["GET"])
def home():
    return "VirusTotal bot is running!"


@app.route("/webhook", methods=["POST"])
def webhook():
    update = request.get_json(silent=True) or {}
    message = update.get("message", {})

    chat_id = message.get("chat", {}).get("id")

    if not chat_id:
        return "OK"

    if message.get("text") == "/start":
        send(
            chat_id,
            "Привет! Отправь файл для проверки VirusTotal."
        )
        return "OK"

    if message.get("video") or message.get("animation"):
        send(chat_id, "Видео и GIF проверять нельзя.")
        return "OK"

    if message.get("document"):
        doc = message["document"]

        if is_video_or_gif(doc):
            send(chat_id, "Видео и GIF проверять нельзя.")
            return "OK"

        threading.Thread(
            target=scan,
            args=(chat_id, doc),
            daemon=True
        ).start()

    return "OK"


url = os.environ.get("RENDER_EXTERNAL_URL")

if url:
    try:
        response = requests.post(
            TG_API + "/setWebhook",
            json={"url": url + "/webhook"},
            timeout=20
        )
        print("WEBHOOK:", response.status_code, response.text)

    except Exception as e:
        print("WEBHOOK ERROR:", repr(e))
    
