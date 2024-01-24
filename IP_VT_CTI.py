import os
import requests
import pandas as pd
from datetime import datetime, timezone
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

#AbuseIPDB
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
        #print(data)
        abuse_confidence_score = data['data']['abuseConfidenceScore']
        abuse_reports = data['data']['totalReports']
        last_updated = data['data']['lastReportedAt']

        return abuse_confidence_score, abuse_reports, last_updated

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")

def calculate_time_elapsed(last_updated):
    if last_updated is None:
        return None, None, None

    last_updated_datetime = datetime.strptime(last_updated, "%Y-%m-%dT%H:%M:%S%z")
    
    # Make current_datetime timezone-aware
    current_datetime = datetime.utcnow().replace(tzinfo=timezone.utc)
    
    time_elapsed = current_datetime - last_updated_datetime

    # Calculate time elapsed in hours, weeks, and months
    time_elapsed_hours = time_elapsed.total_seconds() / 3600
    time_elapsed_weeks = time_elapsed.days / 7
    time_elapsed_months = time_elapsed.days / 30  # Approximation for months

    return time_elapsed_hours, time_elapsed_weeks, time_elapsed_months

def process_excel_abuse(input_file, api_key):
    # Read IPs from Excel input file
    df = pd.read_excel(input_file, names=['IP'])

    # Initialize output DataFrame
    output_data = {'IP': [], 'Abuse Confidence Score': [], 'Number of Reports': [], 'Last Updated': [],
                   'Time Elapsed (Hours)': [], 'Time Elapsed (Weeks)': [], 'Time Elapsed (Months)': []}

    for ip_address in df['IP']:
        abuse_info = get_abuse_info(api_key, ip_address)

        if abuse_info:
            abuse_confidence_score, totalReports, last_updated = abuse_info
            output_data['IP'].append(ip_address)
            output_data['Abuse Confidence Score'].append(abuse_confidence_score)
            output_data['Number of Reports'].append(totalReports)
            output_data['Last Updated'].append(last_updated)

            # Calculate time elapsed
            time_elapsed_hours, time_elapsed_weeks, time_elapsed_months = calculate_time_elapsed(last_updated)
            output_data['Time Elapsed (Hours)'].append(time_elapsed_hours)
            output_data['Time Elapsed (Weeks)'].append(time_elapsed_weeks)
            output_data['Time Elapsed (Months)'].append(time_elapsed_months)
        else:
            # If failed to retrieve abuse information, populate with NaN values
            output_data['IP'].append(ip_address)
            output_data['Abuse Confidence Score'].append(None)
            output_data['Number of Reports'].append(None)
            output_data['Last Updated'].append(None)
            output_data['Time Elapsed (Hours)'].append(None)
            output_data['Time Elapsed (Weeks)'].append(None)
            output_data['Time Elapsed (Months)'].append(None)

        results.append({
            'ip':ip_address,
            'Abuse Confidence Score':abuse_confidence_score,
            'Number of Reports':totalReports,
            'Last Updated':last_updated,
            'Hours':time_elapsed_hours,
            "Weeks":time_elapsed_weeks,
            'months':time_elapsed_months
        })
        

def get_virustotal_info(api_key, ip_address):
    # ... (same as your existing get_virustotal_info function)
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)

        # Modify this line based on the actual structure of the response
        asn_owner = data.get('data', {}).get('attributes', {}).get('as_owner', '')

        # Include the country information
        country = data.get('data', {}).get('attributes', {}).get('country', {})


        return malicious_count, asn_owner, country
    elif response.status_code == 404:
        print(f'{Fore.RED}IP address {ip_address} not found on VirusTotal.{Style.RESET_ALL}')
    else:
        print(f'{Fore.RED}Error: {response.status_code}{Style.RESET_ALL}')

    return 0, '', ''

def process_excel_VT(input_file, vt_api_key, results):
    df = pd.read_excel(input_file, header=None, names=['IP'], skiprows=1)

    for index, row in df.iterrows():
        ip_address = row['IP']

        # Check if the IP already exists in results
        existing_entry = next((entry for entry in results if entry['IP'] == ip_address), None)

        if existing_entry:
            print(f'{Fore.GREEN}IP in VT already processed: {ip_address}. Updating entry...{Style.RESET_ALL}')

            # Update the existing entry
            vt_malicious_count, vt_asn_owner, vt_country = get_virustotal_info(vt_api_key, ip_address)

            existing_entry.update({
                'VT_Malicious_Count': vt_malicious_count,
                'VT_ASN_Owner': vt_asn_owner,
                'VT_Country': vt_country,
            })

        else:
            # Display processing message with colored output
            print(f'{Fore.GREEN}Processing IP in VT: {ip_address}...', end=' ')

            vt_malicious_count, vt_asn_owner, vt_country = get_virustotal_info(vt_api_key, ip_address)

            # Display the number of malicious count
            print(f'Malicious Count: {vt_malicious_count}{Style.RESET_ALL}')
            print(f'IP Owner: { vt_asn_owner}{Style.RESET_ALL}')
            print(f'Country: {vt_country}{Style.RESET_ALL}')

            # Append a new entry to results
            results.append({
                'IP': ip_address,
                'VT_Malicious_Count': vt_malicious_count,
                'VT_ASN_Owner': vt_asn_owner,
                'VT_Country': vt_country,
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
        print(f'{Fore.RED}Error for IP {ip_address}: {response.status_code} - {response.text}{Style.RESET_ALL}')

    return '', ''

def process_excel_CTI(input_file, CTI_api_key, results):
    df = pd.read_excel(input_file, header=None, names=['IP'], skiprows=1)

    for index, row in df.iterrows():
        ip_address = row['IP']

        # Check if the IP already exists in results
        existing_entry = next((entry for entry in results if entry['IP'] == ip_address), None)

        if existing_entry:
            print(f'{Fore.RED}IP in CTI already processed: {ip_address}. Updating entry...{Style.RESET_ALL}')

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
            print(f'{Fore.RED}Processing IP in CTI : {ip_address}...', end=' ')

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

if __name__ == "__main__":
    vt_api_key = '029455493eb333bf6e839263f7375ceb5a97db5845de1b3646775188a7879269'
    CTI_api_key = '23dc017398e440988588d242dc9fcb75ef744b9063b14d48aea0e8ffb498cca0'
    Abuse_api_key = 'd245bd1979cbe344954820165650546329f8b2598a357927136ed319f9565fd5c5cb0bdcc9796ba6'
    input_file = 'input.xlsx'
    output_file = f'output_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'

    # Initialize results list
    results = []

    # Process VirusTotal data
    process_excel_VT(input_file, vt_api_key, results)

    # Process CTI_ThreatBook data
    process_excel_CTI(input_file, CTI_api_key, results)

    # Process CTI_ThreatBook data
    process_excel_abuse(input_file, Abuse_api_key)

    # Create a DataFrame from the results list
    output_df = pd.DataFrame(results)

    # Check if the "Result" folder exists, if not, create it
    result_folder = 'Result'
    if not os.path.exists(result_folder):
        os.makedirs(result_folder)

    output_path = os.path.join(result_folder, output_file)
    output_df.to_excel(output_path, index=False)

    print(f'{Fore.YELLOW}Results saved to the "Result" folder in {output_file}{Style.RESET_ALL}')