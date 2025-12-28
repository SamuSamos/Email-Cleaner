import os
import json
from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import base64
import imaplib
from email import message_from_bytes
from email.header import decode_header

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")
socketio = SocketIO(app)

# ===========================
# Utils
# ===========================
def safe_decode_header(hdr):
    """
    Décodage robuste des headers pour éviter les mails "cassés".
    """
    parts = decode_header(hdr or "")
    decoded = []
    for part, encoding in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(encoding or 'utf-8', errors='replace'))
            except Exception:
                decoded.append(part.decode('utf-8', errors='replace'))
        else:
            decoded.append(part)
    return ''.join(decoded)

def process_mail(msg_bytes):
    """
    Parse un email et renvoie un dict avec les infos nécessaires.
    Gestion robuste pour mails exceptionnels.
    """
    try:
        msg = message_from_bytes(msg_bytes)
        subject = safe_decode_header(msg.get("Subject"))
        sender = safe_decode_header(msg.get("From"))
        has_attachment = False
        if msg.is_multipart():
            for part in msg.walk():
                try:
                    if part.get_content_disposition() == "attachment":
                        has_attachment = True
                        break
                except Exception:
                    continue

        # Logique pour le match_keyword (adapter selon ton code)
        match_keyword = "urgent" in subject.lower()  # exemple, remplacer par ta logique
        conserve = True

        return {
            "subject": subject,
            "from": sender,
            "has_attachment": has_attachment,
            "match_keyword": match_keyword,
            "conserve": conserve
        }

    except Exception as e:
        print(f"[process_mail] Erreur parsing mail: {e}")
        return {
            "subject": "",
            "from": "",
            "has_attachment": False,
            "match_keyword": False,
            "conserve": False
        }

# ===========================
# Routes
# ===========================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        redirect_uri=url_for("oauth2callback", _external=True)
    )
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true"
    )
    session["state"] = state
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    try:
        state = session["state"]
        flow = Flow.from_client_secrets_file(
            "client_secret.json",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            state=state,
            redirect_uri=url_for("oauth2callback", _external=True)
        )
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        session["credentials"] = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes
        }
        return redirect(url_for("inbox"))
    except Exception as e:
        return f"Erreur OAuth: {e}"

@app.route("/inbox")
def inbox():
    try:
        creds_data = session.get("credentials")
        if not creds_data:
            return redirect(url_for("login"))

        creds = Credentials(**creds_data)
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(creds.token, "")  # attention: adapter login si nécessaire
        mail.select("inbox")
        status, messages = mail.search(None, "ALL")
        mail_ids = messages[0].split()

        all_emails = []
        for i, mail_id in enumerate(mail_ids, start=1):
            status, data = mail.fetch(mail_id, "(RFC822)")
            for response_part in data:
                if isinstance(response_part, tuple):
                    msg_info = process_mail(response_part[1])
                    all_emails.append(msg_info)
                    print(f"{i}/{len(mail_ids)} - From: {msg_info['from']}")
        return render_template("inbox.html", emails=all_emails)
    except Exception as e:
        return f"Erreur inbox: {e}"

# ===========================
# SocketIO Events
# ===========================
@socketio.on("connect")
def handle_connect():
    emit("message", {"data": "Connecté au serveur Email-Cleaner"})

# ===========================
# Main
# ===========================
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
