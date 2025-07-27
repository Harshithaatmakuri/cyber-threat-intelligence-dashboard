from flask import Flask, render_template, request, send_file
import requests, os, json, csv, pytz
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime

# ----------------------------------------------------------------------
#  Initialisation
# ----------------------------------------------------------------------
load_dotenv()

# MongoDB setup
MONGODB_URI = os.getenv("MONGODB_URI")
mongo_client = MongoClient(MONGODB_URI)
db = mongo_client["threat_dashboard"]
collection = db["ip_reports"]

app = Flask(__name__)

# API Keys
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
THREATFOX_API_KEY  = os.getenv("THREATFOX_API_KEY")
print("ThreatFox API Key:", THREATFOX_API_KEY)


abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
vt_headers    = {"x-apikey": VIRUSTOTAL_API_KEY}

# Global chart list (latest IP only)
abuse_scores = []

# ----------------------------------------------------------------------
#  Helper Functions
# ----------------------------------------------------------------------
def get_abuse_data(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=abuse_headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "abuseConfidenceScore": int(data.get("abuseConfidenceScore", 0)),
            "countryCode": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "domain": data.get("domain", "N/A"),
            "usageType": data.get("usageType", "N/A"),
            "abuseCategories": ", ".join(data.get("categories", [])) or "None reported"
        }
    except Exception as e:
        return {"error": f"Error fetching AbuseIPDB data: {e}"}


def get_virustotal_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers=vt_headers, timeout=10)
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "harmless":   stats.get("harmless",   0),
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0)
        }
    except Exception as e:
        return {"error": f"Error fetching VirusTotal data: {e}"}


def get_threatfox_data(limit=25):
    url = "https://threatfox-api.abuse.ch/api/v1/"
    body = {
        "query": "get_iocs",
        "limit": limit
    }
    headers = {
        "Auth-Key": THREATFOX_API_KEY
    }
    try:
        response = requests.post(url, headers=headers, json=body, timeout=10)
        response.raise_for_status()
        data = response.json()
        rows = data.get("data", [])
        return [{
            "ioc": row.get("ioc", "N/A"),
            "threat_type": row.get("threat_type", "N/A"),
            "malware": row.get("malware_name", "N/A"),
            "confidence": row.get("confidence_level", "N/A")
        } for row in rows]
    except Exception as e:
        return [{
            "ioc": "Error",
            "threat_type": str(e),
            "malware": "",
            "confidence": ""
        }]



def convert_utc_to_local(utc_dt):
    """Convert UTC datetime to formatted local IST string"""
    local_tz = pytz.timezone('Asia/Kolkata')
    return utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S")

# ----------------------------------------------------------------------
#  Routes
# ----------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check_ip():
    ip = request.form['ip'].strip()
    abuse_result = get_abuse_data(ip)
    vt_result    = get_virustotal_data(ip)

    score = abuse_result.get("abuseConfidenceScore", 0)
    abuse_scores.clear()
    abuse_scores.append({"ip": ip, "score": score})

    ip_report = {
        "ip": ip,
        "abuse_result": abuse_result,
        "vt_result": vt_result,
        "timestamp": datetime.utcnow()  # Store as UTC
    }

    try:
        collection.insert_one(ip_report)
    except Exception as e:
        print(f"[❌ MongoDB Insert Error] {e}")

    return render_template(
        'ip_checker.html',
        ip=ip,
        abuse_result=abuse_result,
        vt_result=vt_result,
        abuse_scores=abuse_scores
    )


@app.route('/history')
def view_history():
    try:
        history = list(collection.find().sort("timestamp", -1))
        for h in history:
            utc_ts = h.get('timestamp')
            if isinstance(utc_ts, datetime):
                h['timestamp'] = convert_utc_to_local(utc_ts)
            else:
                h['timestamp'] = str(utc_ts)
    except Exception as e:
        print(f"[❌ MongoDB Read Error] {e}")
        history = []

    return render_template('history.html', history=history)


@app.route('/dashboard')
def dashboard():
    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={
                "Content-Type": "application/json",
                "Auth-Key": THREATFOX_API_KEY
            },
            json={"query": "get_iocs", "days": 1}
        )
        data = response.json()
        threat_data = data.get("data", [])
    except Exception as e:
        threat_data = [{"ioc": f"Error {e}", "threat_type": "", "malware": "", "confidence": ""}]

    labels = [item.get("ioc", "Unknown") for item in threat_data[:10]]
    scores = [item.get("confidence", 0) if isinstance(item.get("confidence", 0), int) else 0 for item in threat_data[:10]]

    return render_template('dashboard.html', threat_data=threat_data[:20], labels=labels, scores=scores)


@app.route('/test-threatfox')
def test_threatfox():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    body = {"query": "get_iocs", "limit": 5}
    headers = {"Auth-Key": THREATFOX_API_KEY}
    try:
        r = requests.post(url, headers=headers, json=body, timeout=10)
        r.raise_for_status()
        return f"<h2>Status Code: {r.status_code}</h2><pre>{r.text}</pre>"
    except Exception as e:
        return f"<p>Error: {e}</p>"


@app.route('/export')
def export_csv():
    try:
        reports = list(collection.find({}, {'_id': 0}))
        with open('ip_reports.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['IP', 'Abuse Score', 'Country', 'VT Harmless', 'VT Malicious', 'VT Suspicious'])
            for r in reports:
                abuse = r.get('abuse_result', {})
                vt = r.get('vt_result', {})
                writer.writerow([
                    r.get('ip', ''),
                    abuse.get('abuseConfidenceScore', 'N/A'),
                    abuse.get('countryCode', 'N/A'),
                    vt.get('harmless', 'N/A'),
                    vt.get('malicious', 'N/A'),
                    vt.get('suspicious', 'N/A')
                ])
        return send_file('ip_reports.csv', as_attachment=True)
    except Exception as e:
        return f"[❌ Export Error] {e}"

# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("✅ Flask app running →  http://127.0.0.1:5000/")
    app.run(debug=True)
