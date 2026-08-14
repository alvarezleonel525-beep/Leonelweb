from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def inicio():
    return render_template("index.html")

@app.route("/callback")
def callback():
    return "Autorización recibida correctamente. Podés cerrar esta página."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
