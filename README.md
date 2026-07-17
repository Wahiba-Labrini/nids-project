# NIDS — Network Intrusion Detection System

A personal project to detect suspicious network activity (e.g. port scanning) using Python and MySQL, with a planned C/C++ module for low-level packet capture.

## 🛠️ Tech Stack
- **Python (Scapy)** — packet capture and analysis
- **MySQL** — alert storage
- **C / C++** — planned for low-level capture (coming soon)
- **Flask** — planned for the web dashboard

## ✅ Current Progress
- [x] MySQL database + alerts table
- [x] Packet capture with Scapy
- [x] Extract source and destination IPs
- [x] Insert captured packet data into the alerts table via db_handler.py
- [x] Port scan detection
- [ ] Web dashboard
- [ ] C/C++ engine

## 📂 Project Structure
```
NIDS_Project/
├── backend_python/
│   ├── sniffer.py
│   └── db_handler.py
├── web_dashboard/      (coming soon)
└── backend_c_cpp/      (coming soon)
```

## 🚀 How to Run
```bash
pip install scapy mysql-connector-python
sudo python3 backend_python/sniffer.py

Requires Linux/macOS and libpcap. MySQL must be running with the nids_db database created.

📌 What's Next
Add port scan detection
Build Flask dashboard
Integrate the C/C++ engine
📝 Note
This project is being developed incrementally, with each component built and tested individually before integration.
