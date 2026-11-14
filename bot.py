
import os
import time
import threading
import hashlib
import requests
from flask import Flask, request

app = Flask(__name__)

TG = os.environ["BOT_TOKEN"]
VT = os.environ["VT_API_KEY"]

TG_API = f"https://api.telegram.org/bot{TG}"
VT_API = "https://www.virustotal.com/api/v3"

MAX_SIZE = 50 * 1024 * 1024

VIDEO_EXTENSIONS = (
    ".gif", ".mp4", ".mov", ".webm", ".avi",
    ".mkv", ".mpeg", ".mpg", ".3gp", ".m4v"
)


def send(chat_id, text):
    try:
        requests.post(
            TG_API + "/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=20
        )
    except Exception as e:
        print("SEND ERROR:", repr(e))


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

        send(chat_id, "🔍 Отправляю файл на проверку VirusTotal...")

        response = requests.post(
            VT_API + "/files",
            headers={"x-apikey": VT},
            files={"file": (name, file_data)},
            timeout=300
        )
        response.raise_for_status()

        analysis_id = response.json()["data"]["id"]

        data = {}

        # Проверяем готовность каждые 3 секунды
        for _ in range(80):
            time.sleep(3)

            result = requests.get(
                VT_API + "/analyses/" + analysis_id,
                headers={"x-apikey": VT},
                timeout=30
            )
            result.raise_for_status()

            data = result.json()["data"]["attributes"]

            if data.get("status") == "completed":
                break
        else:
            send(
                chat_id,
                "Проверка ещё выполняется. Попробуй позже."
            )
            return

        stats = data.get("stats", {})
        results = data.get("results", {})

        sha = hashlib.sha256(file_data).hexdigest()

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
            category = item.get("category", "")

            if category in ("malicious", "suspicious"):
                threat = item.get("result") or "Название не указано"
                detections.append(
                    f"• {engine}: {threat}"
                )

        report = (
            f"{verdict}\n\n"
            f"📁 Файл: {name}\n"
            f"🧪 Всего проверок: {total}\n\n"
            f"🔴 Обнаружено: {malicious}\n"
            f"🟠 Подозрительно: {suspicious}\n"
            f"🟢 Без обнаружений: {undetected + harmless}\n"
        )

        if detections:
            report += "\n🦠 ОБНАРУЖЕННЫЕ УГРОЗЫ:\n\n"
            report += "\n\n".join(detections[:20])

            if len(detections) > 20:
                report += (
                    f"\n\nИ ещё {len(detections) - 20} обнаружений."
                )
        else:
            report += "\n🦠 Обнаруженных угроз нет."

        report += (
            f"\n\n📊 Полный отчёт:\n"
            f"https://www.virustotal.com/gui/file/{sha}"
        )

        send(chat_id, report[:4000])

    except requests.HTTPError as e:
        print("HTTP ERROR:", repr(e))

        if e.response is not None:
            print("DETAILS:", e.response.text[:500])

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

    if message.get("video") or message.get("animation"):
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
        
