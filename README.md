**IP Investigation Tool**
**Introduction**
This tool is designed to perform investigations on a list of IP addresses using various threat intelligence sources, including VirusTotal, ThreatBook, and AbuseIPDB. The results are then saved in an Excel file for further analysis.

**Prerequisites**
Python 3.x
**Install required Python packages using:**
pip install -r requirements.txt

**Configuration**
Before running the tool, make sure to update the API keys in the script:

vt_api_key: Your VirusTotal API key
CTI_api_key: Your ThreatBook API key
Abuse_api_key: Your AbuseIPDB API key

**Usage**
Create an Excel file named input.xlsx containing a list of IP addresses in a single column labeled "IP".

**Run the script using the following command:**
python ip_investigation.py

The results will be saved in the Result folder in a file named output_<timestamp>.xlsx.
**Output Format**
The output Excel file will contain information gathered from each source for each IP address, including VirusTotal malicious count, ThreatBook judgment values, and AbuseIPDB abuse confidence score.
