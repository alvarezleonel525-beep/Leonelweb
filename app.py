import os
import secrets
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


@app.route("/")
def inicio():
    return render_template("index.html")


@app.route("/login/kick")
def login_kick():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "channel:read",
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

    token_response = requests.post(
        "https://id.kick.com/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "code": code
        },
        timeout=15
    )

    if token_response.status_code != 200:
        return "No se pudo completar la autorización con Kick.", 400

    return "¡Kick conectado correctamente! 🚀"


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
