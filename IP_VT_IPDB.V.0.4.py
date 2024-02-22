import os
import requests
import pandas as pd
from datetime import datetime
from colorama import Fore, Style, init
import json

# Initialize Colorama
init(autoreset=True)

def load_api_keys(api_keys_file):
    with open(api_keys_file, 'r') as f:
        api_keys_data = json.load(f)
    return api_keys_data

# VirusTotal
def get_virustotal_info(api_key, ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        asn_owner = data.get('data', {}).get('attributes', {}).get('as_owner', '')
        country = data.get('data', {}).get('attributes', {}).get('country', '')
        asn = data.get('data', {}).get('attributes', {}).get('asn', '')

        return malicious_count, asn_owner, country, asn
    elif response.status_code == 404:
        print(f'{Fore.RED}IP address {ip_address} not found on VirusTotal.{Style.RESET_ALL}')
    else:
        print(f'{Fore.RED}Error: {response.status_code}{Style.RESET_ALL}')

    return 0, '', '', ''

def process_excel_VT(input_file, vt_api_key, results):
    df = pd.read_excel(input_file)

    for index, row in df.iterrows():
        threat_actor = row['Threat actor']
        ip_address = row['IP']

        # Check if the IP already exists in results
        existing_entry = next((entry for entry in results if entry['IP'] == ip_address), None)

        if existing_entry:
            print(f'{Fore.GREEN}IP in VT already processed: {ip_address}. Updating entry...{Style.RESET_ALL}')

            # Update the existing entry
            vt_malicious_count, vt_asn_owner, vt_country, vt_asn = get_virustotal_info(vt_api_key, ip_address)

            existing_entry.update({
                'Date': datetime.now().strftime(" %d-%m-%Y "),
                'Threat_Actor': threat_actor,
                'VT_Malicious_Count': vt_malicious_count,
                'VT_ASN_Owner': vt_asn_owner,
                'VT_Country': vt_country,
                'VT_ASN': vt_asn,
            })

        else:
            print(f'{Fore.GREEN}Processing IP in VT: {ip_address}...', end=' ')

            vt_malicious_count, vt_asn_owner, vt_country, vt_asn = get_virustotal_info(vt_api_key, ip_address)

            print(f'Malicious Count: {vt_malicious_count}{Style.RESET_ALL}')
            print(f'IP Owner: {vt_asn_owner}{Style.RESET_ALL}')
            print(f'Country: {vt_country}{Style.RESET_ALL}')
            print(f'ASN: {vt_asn}{Style.RESET_ALL}')

            results.append({
                'Date': datetime.now().strftime("%d-%m-%Y"),
                'Threat_Actor': threat_actor,
                'IP': ip_address,
                'VT_Malicious_Count': vt_malicious_count,
                'VT_ASN_Owner': vt_asn_owner,
                'VT_Country': vt_country,
                'VT_ASN': vt_asn,
            })

def get_threatbook_info(api_key, ip_address):
    # ... (same as your existing get_threatbook_info function)
    url = f"https://api.threatbook.io/v1/community/ip"
    params = {"apikey": api_key, "resource": ip_address}
    headers = {"accept": "application/json"}

    response = requests.get(url, params=params, headers=headers)

    if response.status_code == 200:
        data = response.json()

    # Extract the judgments value
        judgments_value = data.get("data", {}).get("summary", {}).get("judgments", [])

    # If judgments value is empty, assign 'unknown'
        if not judgments_value:
            judgments_value = 'unknown'

# Determine the final verdict based on conditions
        if 'IDC' in judgments_value or 'unknown' in judgments_value:
            final_verdict = 'unknown'
        else:
            final_verdict = 'Malicious'

        return judgments_value, final_verdict
    else:
        print(f'{Fore.GREEN}Error for IP {ip_address}: {response.status_code} - {response.text}{Style.RESET_ALL}')

    return '', ''

def process_excel_CTI(input_file, CTI_api_key, results):
    df = pd.read_excel(input_file, header=None, names=['IP'], skiprows=1)

    for index, row in df.iterrows():
        ip_address = row['IP']

        # Check if the IP already exists in results
        existing_entry = next((entry for entry in results if entry['IP'] == ip_address), None)

        if existing_entry:
            print(f'{Fore.GREEN}IP in CTI already processed: {ip_address}. Updating entry...{Style.RESET_ALL}')

            # Update the existing entry
            judgments_value, final_verdict = get_threatbook_info(CTI_api_key, ip_address)

            if not judgments_value:
                judgments_value = "unknown"

            if 'IDC' in judgments_value or 'unknown' in judgments_value:
                final_verdict = 'unknown'
            else:
                final_verdict = "Malicious"

            existing_entry.update({
                'Judgment values': judgments_value,
                'Final verdict': final_verdict,
            })

        else:
            # Display processing message with colored output
            print(f'{Fore.GREEN}Processing IP in CTI : {ip_address}...', end=' ')

            judgments_value, final_verdict = get_threatbook_info(CTI_api_key, ip_address)

            # Display the number of malicious count
            if not judgments_value:
                judgments_value = "unknown"

            if 'IDC' in judgments_value or 'unknown' in judgments_value:
                final_verdict = 'unknown'
            else:
                final_verdict = "Malicious"
            print(f'Final verdict : {final_verdict}{Style.RESET_ALL}')

            # Append a new entry to results
            results.append({
                'IP': ip_address,
                'Judgment values': judgments_value,
                'Final verdict': final_verdict,
            })

def get_abuse_info(api_key, ip_address):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Check if the request was successful

        data = response.json()
        abuse_confidence_score = data['data']['abuseConfidenceScore']
        abuse_reports = data['data']['totalReports']
        last_updated = data['data']['lastReportedAt']

        return abuse_confidence_score, abuse_reports, last_updated[:10]

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

def process_excel_abuse(input_file, api_key, results):
    # Read IPs from Excel input file
    df = pd.read_excel(input_file, names=['IP'])

    for ip_address in df['IP']:
        abuse_info = get_abuse_info(api_key, ip_address)

        if abuse_info:
            abuse_confidence_score, totalReports, last_updated = abuse_info

            # Check if the IP already exists in results
            existing_entry = next((entry for entry in results if entry['IP'] == ip_address), None)
            if existing_entry:
                print(f'{Fore.RED}IP in AbuseIPDB already processed: {ip_address}. Updating entry...{Style.RESET_ALL}')

                # Update the existing entry
                existing_entry.update({
                    'Abuse_Confidence_Score': abuse_confidence_score,
                    'Number_of_Reports': totalReports,
                    'Last_Updated': last_updated,
                })
            else:
                # If IP not in results, append a new entry
                print(f'{Fore.GREEN}Processing IP in AbuseIPDB: {ip_address}...', end=' ')
                print(f'Abuse Confidence Score: {abuse_confidence_score}{Style.RESET_ALL}')
                print(f'Number of Reports: {totalReports}{Style.RESET_ALL}')
                print(f'Last Updated: {last_updated}{Style.RESET_ALL}')

                results.append({
                    'IP': ip_address,
                    'Abuse_Confidence_Score': abuse_confidence_score,
                    'Number_of_Reports': totalReports,
                    'Last_Updated': last_updated,
                })
        else:
            # If failed to retrieve abuse information, populate with NaN values
            existing_entry = next((entry for entry in results if entry['IP'] == ip_address), None)

            if existing_entry:
                print(f'{Fore.RED}IP in AbuseIPDB already processed: {ip_address}. Updating entry with NaN values...{Style.RESET_ALL}')

                # Update the existing entry with NaN values
                existing_entry.update({
                    'Abuse_Confidence_Score': None,
                    'Number_of_Reports': None,
                    'Last_Updated': None,
                })
            else:
                # If IP not in results, append a new entry with NaN values
                print(f'{Fore.GREEN}Processing IP in AbuseIPDB: {ip_address} with NaN values...{Style.RESET_ALL}')

                results.append({
                    'IP': ip_address,
                    'Abuse_Confidence_Score': None,
                    'Number_of_Reports': None,
                    'Last_Updated': None,
                })

if __name__ == "__main__":
    # Load API keys from a JSON file
    api_keys_data = load_api_keys('api_keys.json')

    # Extract API keys
    vt_api_key = api_keys_data.get('VirusTotal', [''])[0]
    CTI_api_key = api_keys_data.get('CTI_ThreatBook', [''])[0]
    Abuse_api_key = api_keys_data.get('AbuseIPDB', [''])[0]
    
    input_file = 'input.xlsx'
    output_file = f'output_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'

    # Initialize results list
    results = []

    # Process VirusTotal data
    process_excel_VT(input_file, vt_api_key, results)

    # Process CTI_ThreatBook data
    process_excel_CTI(input_file, CTI_api_key, results)

    # Process Abuse
    process_excel_abuse(input_file, Abuse_api_key, results)

    # Create a DataFrame from the results list
    output_df = pd.DataFrame(results)

    # Check if the "Result" folder exists, if not, create it
    result_folder = 'Result'
    if not os.path.exists(result_folder):
        os.makedirs(result_folder)

    output_path = os.path.join(result_folder, output_file)
    output_df.to_excel(output_path, index=False)

    print(f'{Fore.YELLOW}Results saved to the "Result" folder in {output_file}{Style.RESET_ALL}')
