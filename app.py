from flask import Flask, jsonify, send_file
from flask_socketio import SocketIO
from reportlab.pdfgen import canvas

import datetime
import csv
import os
import requests

app = Flask(__name__)

socketio = SocketIO(app, cors_allowed_origins="*")


# -----------------------------
# IOC FETCH FUNCTION
# -----------------------------
def fetch_url_feed(url):

    results = []

    try:

        response = requests.get(url, timeout=10)

        lines = response.text.splitlines()

        for line in lines:

            line = line.strip()

            if line and not line.startswith("#"):

                results.append({
                    "type": "ioc",
                    "value": line,
                    "source": url
                })

    except Exception as e:

        print("ERROR:", e)

    return results


# -----------------------------
# NORMALIZER
# -----------------------------
def normalize_iocs(raw_data, source_name):

    normalized = []

    for item in raw_data:

        try:

            normalized.append({
                "type": item.get("type", "ioc"),
                "value": item.get("value", ""),
                "source": source_name,
                "risk_score": 3
            })

        except:
            pass

    return normalized


# -----------------------------
# CORRELATOR
# -----------------------------
def correlate_iocs(data):

    correlated = []

    for item in data:

        value = item.get("value", "").lower()

        if "malware" in value:
            item["risk_score"] = 5

        elif "phishing" in value:
            item["risk_score"] = 4

        elif "trojan" in value:
            item["risk_score"] = 5

        else:
            item["risk_score"] = 2

        correlated.append(item)

    return correlated


# -----------------------------
# PIPELINE
# -----------------------------
def build_pipeline():

    urls = [
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    ]

    raw = []

    for url in urls:

        raw.extend(fetch_url_feed(url))

    normalized = normalize_iocs(raw, "threat_feed")

    correlated = correlate_iocs(normalized)

    return correlated


# -----------------------------
# HOME PAGE
# -----------------------------
@app.route("/")
def home():

    return """
    <h1>Threat Intelligence Aggregator</h1>

    <h3>Project Running Successfully ✅</h3>

    <ul>
        <li><a href='/api/iocs'>View IOC Data</a></li>
        <li><a href='/api/stats'>View Statistics</a></li>
        <li><a href='/export/pdf'>Download PDF Report</a></li>
        <li><a href='/export/csv'>Download CSV Report</a></li>
    </ul>
    """


# -----------------------------
# IOC API
# -----------------------------
@app.route("/api/iocs")
def api_iocs():

    data = build_pipeline()

    return jsonify(data)


# -----------------------------
# STATS API
# -----------------------------
@app.route("/api/stats")
def api_stats():

    data = build_pipeline()

    return jsonify({

        "total": len(data),

        "high":
        len([i for i in data if i.get("risk_score", 0) >= 4]),

        "medium":
        len([i for i in data if i.get("risk_score", 0) == 3]),

        "low":
        len([i for i in data if i.get("risk_score", 0) <= 2]),
    })


# -----------------------------
# EXPORT PDF
# -----------------------------
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
        160,
        780,
        f"Generated: {datetime.datetime.now()}"
    )

    y = 740

    for ioc in data[:25]:

        text = (
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


# -----------------------------
# EXPORT CSV
# -----------------------------
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
            "Risk Score",
            "Source"
        ])

        for ioc in data:

            writer.writerow([
                ioc.get("type"),
                ioc.get("value"),
                ioc.get("risk_score"),
                ioc.get("source")
            ])

    return send_file(file_path, as_attachment=True)


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port
    )
