from flask import Flask, render_template, redirect, request, session, jsonify
from flask_socketio import SocketIO, emit
import os, base64, math, json, secrets
from email import message_from_bytes
from email.header import decode_header
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, async_mode="eventlet")

# ======================
# Google OAuth
# ======================

CLIENT_SECRETS_FILE = "client_secret.json"

with open(CLIENT_SECRETS_FILE, "r") as f:
    CLIENT_CONFIG = json.load(f)

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

REDIRECT_URI = (
    "https://email-cleaner-bxsc.onrender.com/oauth2callback"
    if os.environ.get("RENDER") == "true"
    else "http://localhost:5000/oauth2callback"
)

# ======================
# Helpers
# ======================

def credentials_to_dict(c):
    return {
        "token": c.token,
        "refresh_token": c.refresh_token,
        "token_uri": c.token_uri,
        "client_id": c.client_id,
        "client_secret": c.client_secret,
        "scopes": c.scopes,
    }

def gmail_service():
    if "credentials" not in session:
        return None
    creds = Credentials(**session["credentials"])
    return build("gmail", "v1", credentials=creds)

def safe_decode(value):
    if not value:
        return ""
    result = ""
    for part, enc in decode_header(value):
        try:
            if isinstance(part, bytes):
                result += part.decode(enc or "utf-8", errors="ignore")
            else:
                result += part
        except Exception:
            continue
    return result

processing = False

# ======================
# OAuth Routes
# ======================

@app.route("/login")
def login():
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)
    session["credentials"] = credentials_to_dict(flow.credentials)
    return redirect("/")

# ======================
# UI Routes
# ======================

@app.route("/")
def index():
    return render_template("index.html", connected="credentials" in session)

@app.route("/labels")
def labels():
    service = gmail_service()
    if not service:
        return jsonify([])
    res = service.users().labels().list(userId="me").execute()
    return jsonify(res.get("labels", []))

# ======================
# SocketIO Processing
# ======================

@socketio.on("process_emails")
def process_emails(data):
    global processing
    service = gmail_service()

    if not service:
        emit("log", "❌ Non connecté à Gmail")
        return

    processing = True

    keywords = [k.strip().lower() for k in data["keywords"].split(",") if k]
    keep_attachments = data["keepAttachments"]
    simulate = data["simulate"]
    label_id = data["label"]

    query = "" if label_id == "ALL" else f"label:{label_id}"

    # -------- PHASE 1 : comptage réel --------
    emit("log", "🔍 Comptage des mails…")

    all_ids = []
    page_token = None

    while processing:
        res = service.users().messages().list(
            userId="me",
            q=query,
            pageToken=page_token
        ).execute()

        all_ids.extend(res.get("messages", []))
        page_token = res.get("nextPageToken")

        if not page_token:
            break

        socketio.sleep(0)

    total = len(all_ids)
    emit("log", f"📨 {total} mails trouvés")

    # -------- PHASE 2 : traitement --------
    for i, meta in enumerate(all_ids, start=1):
        if not processing:
            break

        try:
            msg = service.users().messages().get(
                userId="me",
                id=meta["id"],
                format="raw"
            ).execute()

            raw = base64.urlsafe_b64decode(msg["raw"])
            email_msg = message_from_bytes(raw)

            sender = safe_decode(email_msg.get("From", ""))

            match_keyword = any(k in sender.lower() for k in keywords)

            has_attachment = False
            for part in email_msg.walk():
                try:
                    if part.get_filename():
                        has_attachment = True
                        break
                except Exception:
                    continue

            conserve = match_keyword or (keep_attachments and has_attachment)

            if not conserve and not simulate:
                service.users().messages().trash(
                    userId="me",
                    id=meta["id"]
                ).execute()

            emit(
                "log",
                f"{i}/{total}\n"
                f"From: {sender}\n"
                f"match_keyword = {match_keyword}\n"
                f"has_attachment = {has_attachment}\n"
                f"conserve = {conserve}\n"
                f"{'-'*40}"
            )

            emit("progress", math.floor(i / total * 100))

        except Exception as e:
            emit("log", f"⚠️ Mail ignoré ({i}/{total}) : {e}")

        socketio.sleep(0.02)

    processing = False
    emit("log", "✅ Traitement terminé")

@socketio.on("stop")
def stop():
    global processing
    processing = False

# ======================
# Run
# ======================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)
