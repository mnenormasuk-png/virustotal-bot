
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
        resp = tg_session.post(
            f"{TG_API}/sendMessage",
            json=payload,
            timeout=20
        )
        data = resp.json()
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
        resp = tg_session.post(
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
        if not resp.json().get("ok"):
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


def has_video_or_gif_signature(header: bytes) -> bool:
    if header.startswith((b"GIF87a", b"GIF89a")):
        return True

    if len(header) >= 12 and header[4:8] == b"ftyp":
        return True

    if header.startswith(b"\x1a\x45\xdf\xa3"):
        return True

    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"AVI ":
        return True

    return False


def get_existing_report(sha: str):
    resp = vt_session.get(
        f"{VT_API}/files/{sha}",
        timeout=20
    )

    if resp.status_code == 404:
        return None

    if resp.status_code == 429:
        return "RATE_LIMIT"

    resp.raise_for_status()

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(v for v in stats.values() if isinstance(v, int))

    if total > 0:
        return attrs

    return None


def upload_file(name: str, file_data: bytes) -> str:
    if len(file_data) <= 32 * 1024 * 1024:
        resp = vt_session.post(
            f"{VT_API}/files",
            files={"file": (name, file_data)},
            timeout=180
        )
    else:
        url_resp = vt_session.get(
            f"{VT_API}/files/upload_url",
            timeout=20
        )
        url_resp.raise_for_status()

        upload_url = url_resp.json()["data"]

        resp = vt_session.post(
            upload_url,
            files={"file": (name, file_data)},
            timeout=300
        )

    resp.raise_for_status()
    return resp.json()["data"]["id"]


def report_link(sha: str) -> str:
    return (
        f'<a href="https://www.virustotal.com/gui/file/{sha}">'
        f'📊 Открыть полный отчёт VirusTotal</a>'
    )


def make_report(name: str, sha: str, data: dict, cached: bool = False) -> str:
    stats = data.get("last_analysis_stats") or data.get("stats") or {}
    results = data.get("last_analysis_results") or data.get("results") or {}

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)

    total = malicious + suspicious + undetected + harmless

    if malicious > 0:
        verdict = "🔴 ОБНАРУЖЕНА УГРОЗА"
    elif suspicious > 0:
        verdict = "🟠 ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ"
    else:
        verdict = "🟢 УГРОЗ НЕ ОБНАРУЖЕНО"

    detections = []

    for engine, item in results.items():
        if item.get("category") in ("malicious", "suspicious"):
            threat = item.get("result") or "Подозрительный объект"

            detections.append(
                f"• <b>{html.escape(str(engine))}</b>: "
                f"<code>{html.escape(str(threat))}</code>"
            )

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
        report += (
            "\n⚡ <i>Мгновенный результат "
            "(файл уже был в базе VirusTotal).</i>\n"
        )

    if detections:
        report += "\n🦠 <b>СРАБОТАВШИЕ АНТИВИРУСЫ:</b>\n"
        shown = detections[:40]
        report += "\n".join(shown)

        if len(detections) > 40:
            report += (
                f"\n<i>...и ещё {len(detections) - 40} "
                "(см. полный отчёт)</i>"
            )
    else:
        report += "\n✅ <b>Ни один антивирус не обнаружил угроз.</b>"

    report += "\n\n" + report_link(sha)

    return report


def download_and_hash(file_path: str):
    sha256 = hashlib.sha256()
    chunks = []
    total_size = 0
    first_chunk = True

    with tg_session.get(
        f"{TG_FILE_API}/{file_path}",
        stream=True,
        timeout=60
    ) as r:
        r.raise_for_status()

        for chunk in r.iter_content(chunk_size=65536):
            if not chunk:
                continue

            if first_chunk:
                first_chunk = False

                if has_video_or_gif_signature(chunk[:32]):
                    return None, None, "VIDEO_SIGNATURE"

            total_size += len(chunk)

            if total_size > MAX_TG_SIZE:
                return None, None, "TOO_LARGE"

            sha256.update(chunk)
            chunks.append(chunk)

    return b"".join(chunks), sha256.hexdigest(), None


def scan(chat_id: int, doc: dict, msg_id: int):
    status_msg_id = None

    try:
        file_id = doc["file_id"]
        name = doc.get("file_name") or "file"
        file_size = doc.get("file_size", 0)

        if file_size > MAX_TG_SIZE:
            send(
                chat_id,
                "❌ <b>Файл слишком большой.</b>\n"
                "Telegram позволяет ботам скачивать файлы до <b>20 МБ</b>.",
                reply_to=msg_id
            )
            return

        status_msg_id = send(
            chat_id,
            "📥 Получаю файл и проверяю хеш...",
            reply_to=msg_id
        )

        info_resp = tg_session.get(
            f"{TG_API}/getFile",
            params={"file_id": file_id},
            timeout=20
        )

        info = info_resp.json()

        if not info.get("ok"):
            edit_msg(
                chat_id,
                status_msg_id,
                "❌ Не удалось скачать файл из Telegram."
            )
            return

        file_path = info["result"]["file_path"]

        file_data, sha, err = download_and_hash(file_path)

        # Видео и GIF полностью игнорируются
        if err == "VIDEO_SIGNATURE":
            if status_msg_id:
                try:
                    tg_session.post(
                        f"{TG_API}/deleteMessage",
                        json={
                            "chat_id": chat_id,
                            "message_id": status_msg_id
                        },
                        timeout=10
                    )
                except Exception:
                    pass
            return

        if err == "TOO_LARGE":
            edit_msg(
                chat_id,
                status_msg_id,
                "❌ Файл превышает лимит 20 МБ."
            )
            return

        existing = get_existing_report(sha)

        if existing == "RATE_LIMIT":
            edit_msg(
                chat_id,
                status_msg_id,
                "⚠️ Превышен лимит запросов VirusTotal. "
                "Подождите 30 секунд."
            )
            return

        if existing is not None:
            send_long(
                chat_id,
                make_report(name, sha, existing, cached=True),
                first_msg_id=status_msg_id
            )
            return

        edit_msg(
            chat_id,
            status_msg_id,
            "📤 Это новый файл, его ещё нет в базе.\n"
            "Отправляю в VirusTotal на анализ..."
        )

        analysis_id = upload_file(name, file_data)

        del file_data

        for attempt in range(1, 9):
            edit_msg(
                chat_id,
                status_msg_id,
                f"⏳ Антивирусы проверяют файл... ({attempt * 15} сек.)\n\n"
                f"<i>Можно открыть результат по ссылке:</i>\n"
                f"{report_link(sha)}"
            )

            time.sleep(15)

            res = vt_session.get(
                f"{VT_API}/analyses/{analysis_id}",
                timeout=20
            )

            if res.status_code == 429:
                time.sleep(15)
                continue

            res.raise_for_status()

            attrs = res.json().get("data", {}).get("attributes", {})
            status = attrs.get("status")
            stats = attrs.get("stats", {})

            done_engines = sum(
                v for v in stats.values() if isinstance(v, int)
            )

            if status == "completed" or done_engines >= 55:
                final_report = get_existing_report(sha)

                if not isinstance(final_report, dict):
                    final_report = attrs

                send_long(
                    chat_id,
                    make_report(name, sha, final_report),
                    first_msg_id=status_msg_id
                )
                return

        edit_msg(
            chat_id,
            status_msg_id,
            "⚠️ <b>Очередь VirusTotal перегружена.</b>\n"
            "Итоговый результат появится по ссылке:\n\n"
            + report_link(sha)
        )

    except requests.HTTPError as e:
        print("HTTP ERROR:", repr(e))

        if e.response is not None:
            print("DETAILS:", e.response.text[:500])

            if e.response.status_code == 429:
                edit_msg(
                    chat_id,
                    status_msg_id,
                    "⚠️ Достигнут лимит бесплатного ключа VirusTotal. "
                    "Попробуйте через минуту."
                )
                return

        edit_msg(
            chat_id,
            status_msg_id,
            "❌ Ошибка при обращении к API. Проверьте логи."
        )

    except Exception as e:
        print("ERROR:", repr(e))
        edit_msg(
            chat_id,
            status_msg_id,
            "❌ Произошла ошибка при проверке. Попробуйте позже."
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
            "👋 <b>Привет!</b> Отправь мне любой файл (до 20 МБ), "
            "и я проверю его через <b>VirusTotal</b>.\n\n"
            "⚡ Если файл уже знаком базе VirusTotal, "
            "ты получишь отчёт за 1 секунду!"
        )
        return "OK"

    # Видео и GIF игнорируются без сообщений
    if message.get("video") or message.get("animation"):
        return "OK"

    doc = message.get("document")

    if doc:
        # Проверка типа и расширения до запуска потока
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
            resp = tg_session.post(
                f"{TG_API}/setWebhook",
                json={
                    "url": f"{url.rstrip('/')}/webhook",
                    "drop_pending_updates": True
                },
                timeout=20
            )

            print("WEBHOOK:", resp.status_code, resp.text)

        except Exception as e:
            print("WEBHOOK ERROR:", repr(e))


setup_webhook()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
