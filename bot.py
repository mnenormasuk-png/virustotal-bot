
import os
import time
import threading
import requests
from flask import Flask, request

app = Flask(__name__)

TG = os.environ["BOT_TOKEN"]
VT = os.environ["VT_API_KEY"]

TG_API = f"https://api.telegram.org/bot{TG}"
VT_API = "https://www.virustotal.com/api/v3"

def send(chat_id, text):
    requests.post(
        TG_API + "/sendMessage",
        json={"chat_id": chat_id, "text": text},
        timeout=20
    )

def scan(chat_id, doc):
    try:
        file_id = doc["file_id"]
        name = doc.get("file_name", "file")

        if doc.get("file_size", 0) > 20 * 1024 * 1024:
            send(chat_id, "Файл больше 20 МБ. Отправь файл поменьше.")
            return

        info = requests.get(
            TG_API + "/getFile",
            params={"file_id": file_id},
            timeout=20
        ).json()

        if not info.get("ok"):
            send(chat_id, "Не удалось получить файл из Telegram.")
            return

        path = info["result"]["file_path"]

        content = requests.get(
            f"https://api.telegram.org/file/bot{TG}/{path}",
            timeout=60
        )
        content.raise_for_status()

        send(chat_id, "🔍 Отправляю файл на проверку VirusTotal...")

        response = requests.post(
            VT_API + "/files",
            headers={"x-apikey": VT},
            files={"file": (name, content.content)},
            timeout=180
        )
        response.raise_for_status()

        analysis_id = response.json()["data"]["id"]

        for _ in range(18):
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
            import hashlib
            sha = hashlib.sha256(content.content).hexdigest()

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
    chat = message.get("chat", {})
    chat_id = chat.get("id")

    if not chat_id:
        return "OK"

    if message.get("text") == "/start":
        send(chat_id, "Привет! Отправь мне файл для проверки VirusTotal.")
    elif message.get("document"):
        threading.Thread(
            target=scan,
            args=(chat_id, message["document"]),
            daemon=True
        ).start()

    return "OK"

if __name__ == "__main__":
    url = os.environ.get("RENDER_EXTERNAL_URL")

    if url:
        requests.post(
            TG_API + "/setWebhook",
            json={"url": url + "/webhook"},
            timeout=20
        )

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
      
