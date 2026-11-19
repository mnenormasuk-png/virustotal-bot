
import os
import time
import threading
import hashlib
import html
import requests
from flask import Flask, request

app = Flask(__name__)

TG_TOKEN = os.environ["BOT_TOKEN"]
VT_API_KEY = os.environ["VT_API_KEY"]

TG_API = f"https://api.telegram.org/bot{TG_TOKEN}"
TG_FILE_API = f"https://api.telegram.org/file/bot{TG_TOKEN}"
VT_API = "https://www.virustotal.com/api/v3"

MAX_TG_SIZE = 20 * 1024 * 1024

VIDEO_EXTENSIONS = (
    ".gif", ".mp4", ".mov", ".webm", ".avi",
    ".mkv", ".mpeg", ".mpg", ".3gp", ".m4v"
)

tg_session = requests.Session()
vt_session = requests.Session()
vt_session.headers.update({"x-apikey": VT_API_KEY})


def send(chat_id, text, reply_to=None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    if reply_to:
        payload["reply_to_message_id"] = reply_to

    try:
        r = tg_session.post(
            f"{TG_API}/sendMessage",
            json=payload,
            timeout=20
        )
        data = r.json()
        if not data.get("ok"):
            print("TELEGRAM ERROR:", data)
        return data.get("result", {}).get("message_id")
    except Exception as e:
        print("SEND ERROR:", repr(e))
        return None


def edit_msg(chat_id, message_id, text):
    if not message_id:
        return send(chat_id, text)

    try:
        r = tg_session.post(
            f"{TG_API}/editMessageText",
            json={
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            },
            timeout=20
        )
        if not r.json().get("ok"):
            send(chat_id, text)
    except Exception:
        send(chat_id, text)


def send_long(chat_id, text, first_msg_id=None):
    chunks = []
    while len(text) > 4000:
        cut = text.rfind("\n", 0, 4000)
        if cut == -1:
            cut = 4000
        chunks.append(text[:cut])
        text = text[cut:].lstrip()

    if text:
        chunks.append(text)

    for i, chunk in enumerate(chunks):
        if i == 0 and first_msg_id:
            edit_msg(chat_id, first_msg_id, chunk)
        else:
            send(chat_id, chunk)


def is_video_or_gif_meta(doc):
    name = (doc.get("file_name") or "").lower()
    mime = (doc.get("mime_type") or "").lower()

    return (
        name.endswith(VIDEO_EXTENSIONS)
        or mime.startswith("video/")
        or mime == "image/gif"
    )


def get_existing_report(sha):
    r = vt_session.get(f"{VT_API}/files/{sha}", timeout=20)

    if r.status_code == 404:
        return None
    if r.status_code == 429:
        return "RATE_LIMIT"

    r.raise_for_status()

    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    if sum(v for v in stats.values() if isinstance(v, int)) > 0:
        return attrs

    return None


def upload_file(name, file_data):
    if len(file_data) <= 32 * 1024 * 1024:
        r = vt_session.post(
            f"{VT_API}/files",
            files={"file": (name, file_data)},
            timeout=180
        )
    else:
        u = vt_session.get(
            f"{VT_API}/files/upload_url",
            timeout=20
        )
        u.raise_for_status()

        r = vt_session.post(
            u.json()["data"],
            files={"file": (name, file_data)},
            timeout=300
        )

    r.raise_for_status()
    return r.json()["data"]["id"]


def report_link(sha):
    return (
        f'<a href="https://www.virustotal.com/gui/file/{sha}">'
        f'📊 Открыть полный отчёт VirusTotal</a>'
    )


def make_report(name, sha, data, cached=False):
    stats = data.get("last_analysis_stats") or data.get("stats") or {}
    results = data.get("last_analysis_results") or data.get("results") or {}

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)

    total = malicious + suspicious + undetected + harmless

    if malicious:
        verdict = "🔴 ОБНАРУЖЕНА УГРОЗА"
    elif suspicious:
        verdict = "🟠 ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ"
    else:
        verdict = "🟢 УГРОЗ НЕ ОБНАРУЖЕНО"

    report = (
        f"<b>{verdict}</b>\n\n"
        f"📁 <b>Файл:</b> {html.escape(str(name))}\n"
        f"🔑 <b>SHA-256:</b> <code>{sha[:16]}...</code>\n"
        f"🧪 <b>Всего проверок:</b> {total}\n\n"
        f"🔴 <b>Обнаружено:</b> {malicious}\n"
        f"🟠 <b>Подозрительно:</b> {suspicious}\n"
        f"🟢 <b>Безопасно:</b> {undetected + harmless}\n"
    )

    if cached:
        report += "\n⚡ <i>Мгновенный результат из базы VirusTotal.</i>\n"

    detections = [
        f"• <b>{html.escape(str(engine))}</b>: "
        f"<code>{html.escape(str(item.get('result') or 'Подозрительный объект'))}</code>"
        for engine, item in results.items()
        if item.get("category") in ("malicious", "suspicious")
    ]

    if detections:
        report += "\n🦠 <b>СРАБОТАВШИЕ АНТИВИРУСЫ:</b>\n"
        report += "\n".join(detections[:40])

        if len(detections) > 40:
            report += f"\n...и ещё {len(detections) - 40}"

    else:
        report += "\n✅ <b>Ни один антивирус не обнаружил угроз.</b>"

    report += "\n\n" + report_link(sha)
    return report


def download_and_hash(file_path):
    sha = hashlib.sha256()
    chunks = []
    size = 0

    with tg_session.get(
        f"{TG_FILE_API}/{file_path}",
        stream=True,
        timeout=60
    ) as r:
        r.raise_for_status()

        for chunk in r.iter_content(chunk_size=65536):
            if not chunk:
                continue

            size += len(chunk)
            if size > MAX_TG_SIZE:
                return None, None

            sha.update(chunk)
            chunks.append(chunk)

    return b"".join(chunks), sha.hexdigest()


def scan(chat_id, doc, msg_id):
    status_id = None

    try:
        name = doc.get("file_name") or "file"

        if is_video_or_gif_meta(doc):
            return

        if doc.get("file_size", 0) > MAX_TG_SIZE:
            send(chat_id, "❌ Файл слишком большой. Лимит 20 МБ.", msg_id)
            return

        status_id = send(
            chat_id,
            "📥 Получаю файл и проверяю хеш...",
            msg_id
        )

        info = tg_session.get(
            f"{TG_API}/getFile",
            params={"file_id": doc["file_id"]},
            timeout=20
        ).json()

        if not info.get("ok"):
            edit_msg(chat_id, status_id, "❌ Не удалось получить файл.")
            return

        file_data, sha = download_and_hash(info["result"]["file_path"])

        if file_data is None:
            edit_msg(chat_id, status_id, "❌ Файл превышает лимит 20 МБ.")
            return

        existing = get_existing_report(sha)

        if existing == "RATE_LIMIT":
            edit_msg(chat_id, status_id, "⚠️ Лимит VirusTotal. Попробуйте позже.")
            return

        if existing is not None:
            send_long(
                chat_id,
                make_report(name, sha, existing, True),
                status_id
            )
            return

        edit_msg(
            chat_id,
            status_id,
            "📤 Отправляю новый файл в VirusTotal..."
        )

        analysis_id = upload_file(name, file_data)
        del file_data

        for attempt in range(1, 9):
            edit_msg(
                chat_id,
                status_id,
                f"⏳ Проверка антивирусами... {attempt * 15} сек.\n\n"
                + report_link(sha)
            )

            time.sleep(15)

            r = vt_session.get(
                f"{VT_API}/analyses/{analysis_id}",
                timeout=20
            )

            if r.status_code == 429:
                continue

            r.raise_for_status()

            attrs = r.json().get("data", {}).get("attributes", {})

            if attrs.get("status") == "completed":
                final = get_existing_report(sha)

                if not isinstance(final, dict):
                    final = attrs

                send_long(
                    chat_id,
                    make_report(name, sha, final),
                    status_id
                )
                return

        edit_msg(
            chat_id,
            status_id,
            "⚠️ Проверка ещё выполняется. Результат:\n\n"
            + report_link(sha)
        )

    except Exception as e:
        print("SCAN ERROR:", repr(e))
        edit_msg(
            chat_id,
            status_id,
            "❌ Ошибка при проверке. Попробуйте позже."
        )


@app.route("/", methods=["GET"])
def home():
    return "VirusTotal bot is running!"


@app.route("/webhook", methods=["POST"])
def webhook():
    update = request.get_json(silent=True) or {}
    message = update.get("message") or {}

    chat_id = message.get("chat", {}).get("id")
    msg_id = message.get("message_id")

    if not chat_id:
        return "OK"

    text = message.get("text", "")

    if text and text.split("@")[0] == "/start":
        send(
            chat_id,
            "👋 <b>Привет!</b> Отправь мне любой файл до 20 МБ, "
            "и я проверю его через <b>VirusTotal</b>.\n\n"
            "⚡ Знакомые файлы проверяются по готовому отчёту."
        )
        return "OK"

    # Игнорируем видео, GIF и видеосообщения
    if any(key in message for key in (
        "video", "animation", "video_note"
    )):
        return "OK"

    doc = message.get("document")

    if doc:
        if is_video_or_gif_meta(doc):
            return "OK"

        threading.Thread(
            target=scan,
            args=(chat_id, doc, msg_id),
            daemon=True
        ).start()

    return "OK"


def setup_webhook():
    url = os.environ.get("RENDER_EXTERNAL_URL")

    if url:
        try:
            r = tg_session.post(
                f"{TG_API}/setWebhook",
                json={
                    "url": f"{url.rstrip('/')}/webhook",
                    "drop_pending_updates": True
                },
                timeout=20
            )
            print("WEBHOOK:", r.status_code, r.text)
        except Exception as e:
            print("WEBHOOK ERROR:", repr(e))


setup_webhook()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
            
