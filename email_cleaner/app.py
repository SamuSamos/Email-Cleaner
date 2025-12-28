import os
import json
import base64
import email
from email.header import decode_header
from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CLIENT_SECRETS_FILE = "client_secret.json"


# ====== Routes OAuth ======
@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
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
        state = session.get("state")
        if not state:
            return redirect(url_for("login"))

        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
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


# ====== Helper functions ======
def get_gmail_service():
    creds_data = session.get("credentials")
    if not creds_data:
        return None
    creds = Credentials(**creds_data)
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        session["credentials"] = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes
        }
    service = build("gmail", "v1", credentials=creds)
    return service


def decode_mime_words(s):
    try:
        decoded = ''.join(
            [t.decode(enc or 'utf-8') if isinstance(t, bytes) else t
             for t, enc in decode_header(s)]
        )
        return decoded
    except Exception:
        return s


def process_mail(message):
    payload = message.get("payload", {})
    headers = payload.get("headers", [])
    mail_from = ""
    for h in headers:
        if h.get("name", "").lower() == "from":
            mail_from = decode_mime_words(h.get("value", ""))
            break

    # Check attachments
    has_attachment = False
    parts = payload.get("parts", [])
    for part in parts:
        if part.get("filename"):
            has_attachment = True
            break

    # Check for keywords (example)
    keywords = ["facture", "invoice", "receipt"]
    match_keyword = False
    body = ""
    if "parts" in payload:
        for part in payload["parts"]:
            try:
                if part["mimeType"] == "text/plain" and "data" in part["body"]:
                    data = part["body"]["data"]
                    body += base64.urlsafe_b64decode(data.encode()).decode(errors="ignore")
            except Exception:
                continue
    match_keyword = any(k.lower() in body.lower() for k in keywords)

    conserve = match_keyword or has_attachment

    return {
        "from": mail_from,
        "has_attachment": has_attachment,
        "match_keyword": match_keyword,
        "conserve": conserve
    }


# ====== Inbox ======
@app.route("/inbox")
def inbox():
    service = get_gmail_service()
    if not service:
        return redirect(url_for("login"))

    try:
        results = service.users().messages().list(userId="me", maxResults=50).execute()
        messages = results.get("messages", [])
        processed_mails = []

        for idx, msg in enumerate(messages, start=1):
            m = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
            info = process_mail(m)
            processed_mails.append(info)
            print(f"{idx}/{len(messages)} From: {info['from']}")
            print(f"match_keyword = {info['match_keyword']}")
            print(f"has_attachment = {info['has_attachment']}")
            print(f"conserve = {info['conserve']}")
            print("----------------------------------------")

        return render_template("inbox.html", mails=processed_mails)
    except Exception as e:
        return f"Erreur inbox: {e}"


# ====== Home ======
@app.route("/")
def home():
    return render_template("home.html")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=10000)
