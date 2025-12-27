from flask import Flask, render_template, redirect, request, session, jsonify
from flask_socketio import SocketIO, emit
import os, base64, math
from email import message_from_bytes
from email.header import decode_header

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import secrets

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, async_mode="eventlet")

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

processing = False


# ======================
# OAuth
# ======================

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri="http://localhost:5000/oauth2callback"
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)


@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri="http://localhost:5000/oauth2callback"
    )
    flow.fetch_token(authorization_response=request.url)
    session["credentials"] = credentials_to_dict(flow.credentials)
    return redirect("/")


def credentials_to_dict(c):
    return {
        "token": c.token,
        "refresh_token": c.refresh_token,
        "token_uri": c.token_uri,
        "client_id": c.client_id,
        "client_secret": c.client_secret,
        "scopes": c.scopes
    }


def gmail_service():
    if "credentials" not in session:
        return None
    creds = Credentials(**session["credentials"])
    return build("gmail", "v1", credentials=creds)


# ======================
# UI
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
# EMAIL PROCESSING
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

    messages = []
    request_api = service.users().messages().list(userId="me", q=query, maxResults=500)

    while request_api and processing:
        response = request_api.execute()
        messages.extend(response.get("messages", []))
        request_api = service.users().messages().list_next(request_api, response)

    total = len(messages)
    emit("log", f"📨 {total} mails trouvés")

    for i, meta in enumerate(messages, start=1):
        if not processing:
            break

        msg = service.users().messages().get(
            userId="me",
            id=meta["id"],
            format="raw"
        ).execute()

        raw = base64.urlsafe_b64decode(msg["raw"])
        email_msg = message_from_bytes(raw)

        sender = decode(email_msg.get("From", ""))
        match_keyword = any(k in sender.lower() for k in keywords)

        has_attachment = False
        for part in email_msg.walk():
            if part.get_filename():
                has_attachment = True
                break

        conserve = match_keyword or (keep_attachments and has_attachment)

        if not conserve and not simulate:
            service.users().messages().trash(userId="me", id=meta["id"]).execute()

        emit("log",
             f"{i}/{total}\n"
             f"From: {sender}\n"
             f"match_keyword = {match_keyword}\n"
             f"has_attachment = {has_attachment}\n"
             f"conserve = {conserve}\n"
             f"{'-'*40}"
        )

        emit("progress", math.floor(i / total * 100))
        socketio.sleep(0.03)

    processing = False
    emit("log", "✅ Traitement terminé")


@socketio.on("stop")
def stop():
    global processing
    processing = False


def decode(value):
    parts = decode_header(value)
    out = ""
    for txt, enc in parts:
        if isinstance(txt, bytes):
            out += txt.decode(enc or "utf-8", errors="ignore")
        else:
            out += txt
    return out


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
