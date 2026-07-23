import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend_python'))
from flask import Flask,render_template
from db_handler import get_all_alerts,get_dashboard_stats

app=Flask(__name__)

@app.route("/")
def dashboard():
    alerts=get_all_alerts()
    stats=get_dashboard_stats()
    return render_template("index.html",alerts=alerts,stats=stats)


if __name__ == "__main__" :
    app.run(debug=True)


