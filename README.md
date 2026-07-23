# NIDS — Network Intrusion Detection System

A personal project to detect suspicious network activity (port scanning, ARP spoofing, brute force) using Python, MySQL, and a Flask web dashboard, with a planned C/C++ module for low-level packet capture.

## 🛠️ Tech Stack
- **Python (Scapy)** — packet capture and analysis
- **MySQL** — alert storage
- **Flask (Jinja)** — web dashboard
- **C / C++** — planned for low-level capture (coming soon)

## ✅ Current Progress
- [x] MySQL database + alerts table
- [x] Packet capture with Scapy
- [x] Extract source and destination IPs
- [x] Insert captured packet data into the alerts table via db_handler.py
- [x] Detection logic: Port Scanning, ARP Spoofing, Brute Force
- [x] Flask web dashboard with styled UI
- [x] Dashboard statistics (total alerts, most common attack, most active day)
- [ ] C/C++ low-level capture engine
- [ ] JavaScript-based real-time updates & charts

## 📸 Preview





## 📂 Project Structure
```
NIDS_Project/
├── backend_python/
│   ├── sniffer.py
│   └── db_handler.py
├── web_dashboard/
│   ├── app.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── css/style.css
│       └── js/
├── screenshots/
│   └── dashboard.png
└── backend_c_cpp/      (coming soon)
```

## 🚀 How to Run

**1. Install dependencies:**
```bash
pip install scapy mysql-connector-python flask python-dotenv

2. Run the sniffer (captures traffic and stores alerts in MySQL):

python backend_python/sniffer.py

3. Run the dashboard:

python web_dashboard/app.py

4. Open your browser and go to:

http://127.0.0.1:5000


## 📌 Next Steps (Future Improvements)
1. Build C/C++ packet capture module
2. Learn JavaScript to add real-time dashboard updates and data visualization (Chart.js)
3. Explore integrating Machine Learning for anomaly-based detection
4. Add simulated automatic response for detected threats

👤 Author

Wahiba Labrini — AI Student, Ibn Tofaïl University

📝 Note

This project is being developed incrementally, with each component built and tested individually before integration.
