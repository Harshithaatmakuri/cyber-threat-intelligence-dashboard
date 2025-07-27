Cyber Threat Intelligence Dashboard
Overview
This project is a web-based dashboard that aggregates real-time cyber threat intelligence data. It allows users to check IP reputation by querying APIs like AbuseIPDB and VirusTotal, visualize threat scores, and view live threat feeds.

Features
IP reputation lookup using AbuseIPDB and VirusTotal APIs

Visualization of abuse scores in interactive charts

Integration with live threat intelligence feeds (planned/implemented)

Secure handling of API keys (using .env file)

Clean, responsive Flask web app interface

Installation
Clone the repository:

git clone https://github.com/Harshithaatmakuri/cyber-threat-intelligence-dashboard.git
cd cyber-threat-intelligence-dashboard

Create a Python virtual environment and activate it:

python -m venv venv

On Windows, activate with:
venv\Scripts\activate

On Linux/macOS, activate with:
source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Create a .env file in the project root directory and add your API keys:

ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
Threatfox_auth_key=your_original_key
MongoDB=Local/host:/

Run the Flask application:

python main

Open your browser and navigate to:

http://127.0.0.1:5000

Contributing
Feel free to fork this repository and submit pull requests for improvements or bug fixes.

License
This project is licensed under the MIT License.
