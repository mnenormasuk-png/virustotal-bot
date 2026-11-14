
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

        # Дополнительная проверка формата
        file_start = file_data[:16]

        if (
            file_start[:3] == b"GIF"
            or (
                file_start[:4] == b"RIFF"
                and file_start[8:12] == b"WEBP"
            )
            or file_start[4:8] == b"ftyp"
            or file_start[:4] == b"\x1a\x45\xdf\xa3"
        ):
            send(chat_id, "Видео и GIF не проверяются.")
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

        for _ in range(24):
            time.sleep(10)

            result = requests.get(
                VT_API + "/analyses/" + analysis_id,
                headers={"x-apikey": VT},
                timeout=30
            )
            result.raise_for_status()

            data = result.json()["data"]["attributes"]

            if data.get("status") == "completed":
                stats = data.get("stats", {})
                break
        else:
            send(chat_id, "Проверка ещё выполняется. Попробуй позже.")
            return

        sha = data.get("meta", {}).get("file_info", {}).get("sha256")

        if not sha:
            sha = hashlib.sha256(file_data).hexdigest()

        report = (
            "✅ Проверка завершена!\n\n"
            f"Файл: {name}\n"
            f"Обнаружено: {stats.get('malicious', 0)}\n"
            f"Подозрительно: {stats.get('suspicious', 0)}\n"
            f"Без обнаружений: {stats.get('undetected', 0)}\n\n"
            f"Отчёт: https://www.virustotal.com/gui/file/{sha}"
        )

        send(chat_id, report)

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
        send(chat_id, "Привет! Отправь мне файл для проверки VirusTotal.")

    elif message.get("video") or message.get("animation"):
        return "OK"

    elif message.get("document"):
        doc = message["document"]

        if is_video_or_gif(doc):
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
        
