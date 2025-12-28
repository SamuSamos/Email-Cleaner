import os
import secrets
import json
import base64
import math
from email import message_from_bytes
from email.header import decode_header
from flask import Flask, render_template, redirect, request, session, jsonify
from flask_socketio import SocketIO, emit
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# ======================
# Eventlet monkey patching
# Must be done before importing other modules
# ======================
import eventlet
eventlet.monkey_patch()

# ======================
# Flask App
# ======================
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, async_mode="eventlet")

# ======================
# Google OAuth
# ======================
CLIENT_SECRETS_FILE = "client_secret.json"
if not os.path.exists(CLIENT_SECRETS_FILE):
    raise RuntimeError(f"Le fichier {CLIENT_SECRETS_FILE} est introuvable !")

with open(CLIENT_SECRETS_FILE, "r") as f:
    CLIENT_CONFIG = json.load(f)

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

if os.environ.get("RENDER") == "true":
    REDIRECT_URI = "https://email-cleaner-bxsc.onrender.com/oauth2callback"
else:
    REDIRECT_URI = "http://localhost:5000/oauth2callback"

# ======================
# Helper functions
# ======================
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

def safe_decode(value):
    """Décodage sûr des headers"""
    if not value:
        return ""
    try:
        parts = decode_header(value)
        out = ""
        for txt, enc in parts:
            if isinstance(txt, bytes):
                out += txt.decode(enc or "utf-8", errors="ignore")
            else:
                out += txt
        return out
    except:
        return value

def has_attachments(msg):
    """Détecte si un mail contient des pièces jointes"""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_filename():
                return True
    return False

# ======================
# Routes OAuth
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
# Routes UI
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
# SocketIO Email Processing
# ======================
processing = False

@socketio.on("process_emails")
def process_emails(data):
    global processing
    service = gmail_service()
    if not service:
        emit("log", "❌ Non connecté à Gmail")
        return

    processing = True
    keywords = [k.strip().lower() for k in data.get("keywords","").split(",") if k]
    keep_attachments = data.get("keepAttachments", False)
    simulate = data.get("simulate", True)
    label_id = data.get("label", "ALL")
    query = "" if label_id == "ALL" else f"label:{label_id}"

    next_page_token = None
    batch_size = 100  # limite mémoire

    total = 0
    while processing:
        result = service.users().messages().list(
            userId="me",
            q=query,
            maxResults=batch_size,
            pageToken=next_page_token
        ).execute()

        messages = result.get("messages", [])
        if not messages:
            break

        for i, meta in enumerate(messages, start=1):
            if not processing:
                break
            try:
                msg = service.users().messages().get(
                    userId="me", id=meta["id"], format="raw"
                ).execute()
                raw = base64.urlsafe_b64decode(msg["raw"])
                email_msg = message_from_bytes(raw)

                sender = safe_decode(email_msg.get("From"))
                match_keyword = any(k in sender.lower() for k in keywords)
                conserve = match_keyword or (keep_attachments and has_attachments(email_msg))

                if not conserve and not simulate:
                    service.users().messages().trash(userId="me", id=meta["id"]).execute()

                total += 1
                emit("log",
                     f"{total}\n"
                     f"From: {sender}\n"
                     f"match_keyword = {match_keyword}\n"
                     f"has_attachment = {has_attachments(email_msg)}\n"
                     f"conserve = {conserve}\n"
                     f"{'-'*40}")
                emit("progress", math.floor(total / 1000 * 100))  # approximation
                socketio.sleep(0.03)
            except Exception as e:
                emit("log", f"⚠️ Erreur mail {meta.get('id')}: {e}")

        next_page_token = result.get("nextPageToken")
        if not next_page_token:
            break

    processing = False
    emit("log", "✅ Traitement terminé")

@socketio.on("stop")
def stop():
    global processing
    processing = False

# ======================
# Run App
# ======================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port)
