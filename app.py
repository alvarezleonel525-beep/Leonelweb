import os
import secrets
import hashlib
import base64
import requests

from urllib.parse import urlencode
from flask import Flask, render_template, redirect, request, session

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    secrets.token_hex(32)
)

CLIENT_ID = os.environ.get("KICK_CLIENT_ID")
CLIENT_SECRET = os.environ.get("KICK_CLIENT_SECRET")

REDIRECT_URI = "https://leonelweb-1.onrender.com/callback"


def create_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


@app.route("/")
def inicio():
    return render_template("index.html")


@app.route("/login/kick")
def login_kick():
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = create_code_challenge(code_verifier)

    session["oauth_state"] = state
    session["code_verifier"] = code_verifier

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "channel:read",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state
    }

    url = "https://id.kick.com/oauth/authorize?" + urlencode(params)

    return redirect(url)


@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not code:
        return "No se recibió el código de autorización.", 400

    if state != session.get("oauth_state"):
        return "Estado OAuth inválido.", 400

    code_verifier = session.get("code_verifier")

    if not code_verifier:
        return "No se encontró el código PKCE.", 400

    token_response = requests.post(
        "https://id.kick.com/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "code_verifier": code_verifier
        },
        timeout=15
    )

    if token_response.status_code != 200:
        print("KICK TOKEN ERROR:", token_response.status_code)
        print("KICK RESPONSE:", token_response.text)

        return (
            "Kick rechazó la autorización.<br><br>"
            "Código de error: "
            + str(token_response.status_code)
            + "<br><br>"
            + token_response.text
        ), 400

    return "¡Kick conectado correctamente! 🚀"


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
