

# 🛡️ Intrusion Detection System (IDS) – Man-in-the-Middle Attack Detection

This is a **Cybersecurity Project** focused on detecting and responding to **Man-in-the-Middle (MITM)** attacks. It utilizes Python for backend monitoring and detection logic, along with a web-based frontend built with HTML, CSS, and JavaScript to display alerts and system status.

---

## 🔍 Project Overview

Man-in-the-Middle (MITM) attacks are a serious threat in network security. This Intrusion Detection System (IDS):

- 📡 Monitors network traffic in real-time
- 🧠 Detects patterns indicative of MITM attacks (e.g., ARP spoofing)
- ⚠️ Notifies the user via the frontend interface
- 🛠️ (Optional) Initiates a predefined response or logs the event

---

## 💻 Tech Stack

- **Backend:** Python (Scapy, socket, etc.)
- **Frontend:** HTML, CSS, JavaScript
- **Visualization:** Live alerts and logs on the frontend
- **Deployment:** Localhost / LAN (no live demo available)

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/intrusion-detection-system.git
cd intrusion-detection-system
2. Install Dependencies (Python)
Ensure Python is installed, then install required libraries:
pip install -r requirements.txt
Required packages may include:

scapy

flask 
3. Run the IDS
bash
Always show details


python ids.py
This will start the MITM detection module.

4. Launch Frontend
Open the index.html file in your browser to view alerts and status.

📁 Project Structure
bash


Copy
.
├── ids.py                # Core IDS logic written in Python
├── requirements.txt      # Python dependencies
├── /frontend
│   ├── index.html        # Main dashboard UI
│   ├── style.css         # Styles
│   └── script.js         # Logic for displaying alerts
└── README.md
⚠️ Disclaimer
This project is for educational and research purposes only. Do not use it on unauthorized networks or without permission.

🙌 Contributions
Contributions are welcome to improve detection logic, enhance UI, or support additional types of intrusions.

Fork the repository

Create your feature branch (git checkout -b feature/your-feature)

Commit your changes

Push to the branch

Open a Pull Request

👨‍💻 Author
Manush Prajwal

🔐 Building tools for a safer digital world.
