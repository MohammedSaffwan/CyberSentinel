from flask import Flask, render_template, request

from scanner import (
    webshield_scan,
    url_detector,
    nmap_scan,
    cloud_security_demo
)

app = Flask(__name__)


# ==============================
# HOME / DASHBOARD
# ==============================

@app.route("/")
def home():
    return render_template("index.html")


# ==============================
# WEBSHIELD
# ==============================

@app.route("/webshield", methods=["POST"])
def webshield():

    url = request.form.get("url", "").strip()

    result = webshield_scan(url)

    return render_template(
        "index.html",
        web_result=result
    )


# ==============================
# URL DETECTOR
# ==============================

@app.route("/url-detector", methods=["POST"])
def url_detector_route():

    url = request.form.get("url", "").strip()

    result = url_detector(url)

    return render_template(
        "index.html",
        url_result=result,
        scanned_url=url
    )


# ==============================
# NMAP SCANNER
# ==============================

@app.route("/nmap", methods=["POST"])
def nmap_route():

    target = request.form.get("target", "").strip()

    result = nmap_scan(target)

    return render_template(
        "index.html",
        nmap_result=result,
        scanned_target=target
    )


# ==============================
# CLOUD SECURITY
# ==============================

@app.route("/cloud")
def cloud():

    result = cloud_security_demo()

    return render_template(
        "index.html",
        cloud_result=result
    )


# ==============================
# START SERVER
# ==============================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )