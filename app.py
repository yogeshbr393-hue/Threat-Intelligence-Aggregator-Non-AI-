from flask import Flask, jsonify, send_file
from flask_socketio import SocketIO
from reportlab.pdfgen import canvas

import datetime
import csv
import os

from parser import fetch_url_feed
from normalizer import normalize_iocs
from correlator import correlate_iocs

app = Flask(__name__)

socketio = SocketIO(app, cors_allowed_origins="*")


# Dummy Risk Score Function
def calculate_risk_score(normalized, correlated):

    scored = []

    for ioc in normalized:

        score = 1

        if "malware" in str(ioc).lower():
            score = 5

        elif "phishing" in str(ioc).lower():
            score = 4

        elif "suspicious" in str(ioc).lower():
            score = 3

        ioc["risk_score"] = score

        scored.append(ioc)

    return scored


def build_pipeline():

    urls = [
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    ]

    raw = []

    for url in urls:

        try:
            raw.extend(fetch_url_feed(url))

        except:
            pass

    normalized = normalize_iocs(raw, "live_dashboard")

    correlated = correlate_iocs(normalized)

    scored = calculate_risk_score(normalized, correlated)

    return scored


@app.route("/")
def home():

    return """
    <h1>Threat Intelligence Aggregator</h1>
    <h3>Project Running Successfully</h3>

    <ul>
        <li><a href='/api/iocs'>View IOC Data</a></li>
        <li><a href='/api/stats'>View Statistics</a></li>
        <li><a href='/export/pdf'>Download PDF</a></li>
        <li><a href='/export/csv'>Download CSV</a></li>
    </ul>
    """


@app.route("/api/iocs")
def api_iocs():

    data = build_pipeline()

    socketio.emit("ioc_update", data)

    return jsonify(data)


@app.route("/api/stats")
def api_stats():

    data = build_pipeline()

    return jsonify({
        "total": len(data),
        "high": len([i for i in data if i.get("risk_score", 0) >= 4]),
        "medium": len([i for i in data if i.get("risk_score", 0) == 3]),
        "low": len([i for i in data if i.get("risk_score", 0) <= 2]),
    })


@app.route("/export/pdf")
def export_pdf():

    data = build_pipeline()

    os.makedirs("output", exist_ok=True)

    file_path = "output/report.pdf"

    c = canvas.Canvas(file_path)

    c.setFont("Helvetica-Bold", 16)

    c.drawString(140, 800, "Threat Intelligence Report")

    c.setFont("Helvetica", 10)

    c.drawString(
        170,
        780,
        f"Generated: {datetime.datetime.now()}"
    )

    y = 740

    for ioc in data[:25]:

        text = (
            f"{ioc.get('type')} | "
            f"{ioc.get('value')} | "
            f"Risk: {ioc.get('risk_score')}"
        )

        c.drawString(40, y, text)

        y -= 20

        if y < 50:
            c.showPage()
            y = 800

    c.save()

    return send_file(file_path, as_attachment=True)


@app.route("/export/csv")
def export_csv():

    data = build_pipeline()

    os.makedirs("output", exist_ok=True)

    file_path = "output/report.csv"

    with open(
        file_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Type",
            "Value",
            "Risk Score"
        ])

        for ioc in data:

            writer.writerow([
                ioc.get("type"),
                ioc.get("value"),
                ioc.get("risk_score")
            ])

    return send_file(file_path, as_attachment=True)


@app.route("/logout")
def logout():

    return "<h2>Logged Out Successfully</h2>"


if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    socketio.run(
        app,
        host="0.0.0.0",
        port=port
    )
