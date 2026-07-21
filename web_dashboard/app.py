import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend_python'))
from flask import Flask,render_template
from db_handler import get_all_alerts

app=Flask(__name__)

@app.route("/")
def index():
    alerts=get_all_alerts()
    """
    alerts=[
        {"id": 1, "source_ip": "192.168.1.5", "destination_ip": "10.0.0.1", "attack_type":"port_scan","risk_level":"high","detected_at":"2026-06-24"},
        {"id": 2, "source_ip": "164.188.1.2", "destination_ip": "20.2.0.5", "attack_type":"arp_spoofing","risk_level":"critical","detected_at":"2026-05-24"}
    ]"""
    return render_template("index.html",alerts=alerts)


if __name__ == "__main__" :
    app.run(debug=True)


