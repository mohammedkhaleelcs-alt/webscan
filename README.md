# WebScan - Flask Starter


Runs locally. Features:
- Passive header analysis (requests + bs4)
- Active scan using nmap (subprocess or python-nmap)
- CSV and PDF exports
- Local rule-based AI chatbot (advice.json)


## Requirements
- Python 3.8+
- system `nmap` binary installed for active scans (Linux/Mac/Windows)
- Install Python deps: `pip install -r requirements.txt`


## Run
```bash
export FLASK_APP=app.py
export FLASK_ENV=development
flask run