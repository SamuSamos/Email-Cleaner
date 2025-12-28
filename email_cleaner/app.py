# ======================
# EVENTLET (OBLIGATOIRE EN PREMIER)
# ======================
import eventlet
eventlet.monkey_patch()

# ======================
# Imports
# ======================
from flask import Flask, render_template, redirect, request, session, jsonify
from flask_socketio import SocketIO, emit
import os, math, secrets, json, gc
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# ======================
# Flask
# ======================
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# ======================
# Google OAuth
# ======================
CLIENT_SECRETS_FILE = "client_secret.json"
with open(CLIENT_SECRETS_FILE, "r") as f:
    CLIENT_CONFIG = json.load(f)

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

REDIRECT_URI = (
    "https://email-cleaner-bxsc.onrender.com/oauth2callback"
    if os.environ.get("RENDER")
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
    return build("gmail", "v1", credentials=creds, cache_discovery=False)

def get_header(headers, name):
    for h in headers:
        if h["name"].lower() == name.lower():
            return h["value"]
    return ""

def has_attachment(payload):
    parts = payload.get("parts", [])
    for p in parts:
        if p.get("filename"):
            return True
    return False

processing = False

# ======================
# OAuth Routes
# ======================
@app.route("/login")
def login():
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    flow.fetch_token(authorization_response=request.url)
    session["credentials"] = credentials_to_dict(flow.credentials)
    return redirect("/")

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
# SocketIO – Processing
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

    # ======================
    # FIRST CALL → TOTAL
    # ======================
    first = service.users().messages().list(
        userId="me",
        q=query,
        maxResults=1
    ).execute()

    total = first.get("resultSizeEstimate", 0)
    emit("log", f"📨 {total} mails trouvés")

    i = 0
    request_api = service.users().messages().list(
        userId="me",
        q=query,
        maxResults=50
    )

    while request_api and processing:
        response = request_api.execute()

        for meta in response.get("messages", []):
            if not processing:
                break

            i += 1

            try:
                msg = service.users().messages().get(
                    userId="me",
                    id=meta["id"],
                    format="metadata",
                    metadataHeaders=["From"]
                ).execute()

                headers = msg["payload"].get("headers", [])
                sender = get_header(headers, "From")
                sender_l = sender.lower()

                match_keyword = any(k in sender_l for k in keywords)
                attachment = has_attachment(msg["payload"])
                conserve = match_keyword or (keep_attachments and attachment)

                if not conserve and not simulate:
                    service.users().messages().trash(
                        userId="me",
                        id=meta["id"]
                    ).execute()

                emit("log",
                    f"{i}/{total}\n"
                    f"From: {sender}\n"
                    f"match_keyword = {match_keyword}\n"
                    f"has_attachment = {attachment}\n"
                    f"conserve = {conserve}\n"
                    f"{'-'*40}"
                )

                emit("progress", math.floor(i / total * 100))

            except Exception as e:
                emit("log", f"{i}/{total} ⚠️ Mail ignoré ({e})")

            finally:
                del msg
                gc.collect()
                socketio.sleep(0.03)

        request_api = service.users().messages().list_next(request_api, response)

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
