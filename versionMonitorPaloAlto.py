#!/usr/bin/python

import sys
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')  # Adjust this path based on your version of FMOS.
import yaml
import logging
from logging.handlers import RotatingFileHandler
import requests
import re
from itertools import zip_longest
import csv
import os
import json
from datetime import datetime, timedelta, timezone
from dateutil import parser
from dateutil.tz import gettz
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
from threading import Lock
from urllib.parse import quote

# Load configuration from YAML file
try:
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)
except FileNotFoundError:
    print("Configuration file 'config.yaml' not found. Exiting.")
    sys.exit(1)
except yaml.YAMLError as e:
    print(f"Error parsing the configuration file: {e}. Exiting.")
    sys.exit(1)

# Initialize eol_violations as an empty set
eol_violations = set()

# Setup logging with rotation
logger = logging.getLogger('PaloAltoVersionMonitor')
logger.setLevel(getattr(logging, config['log_level'].upper()))

if config['logging_enabled']:
    # Create a rotating file handler
    file_handler = RotatingFileHandler(
        config['log_file_path'], 
        maxBytes=config['max_log_size_mb'] * 1024 * 1024, 
        backupCount=config['backup_count']
    )
    # Create a formatter and add it to the handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    # Add the handler to the logger
    logger.addHandler(file_handler)
else:
    logger.addHandler(logging.NullHandler())

# Current time reference
now = time.time()

# Unpack configuration variables for ease of use
host_url = config['host_url']
ignore_certificate = config['ignore_certificate']
username = config['username']
password = config['password']
control_uuid = config['control_uuid']
device_group_id = config['device_group_id']
email_enabled = config['email_enabled']
smtp_server = config['smtp_server']
smtp_port = config['smtp_port']
smtp_username = config['smtp_username']
smtp_password = config['smtp_password']
sender_email = config['sender_email']
recipient_email = config['recipient_email']
use_tls = config['use_tls']
send_aggregate_email = config['send_aggregate_email']
attach_csv_to_email = config['attach_csv_to_email']
wildfire_max_age = config['wildfire_max_age_hours'] * 3600
av_max_age = config['av_max_age_days'] * 86400
threat_max_age = config['threat_max_age_days'] * 86400
app_max_age = config['app_max_age_days'] * 86400
revision_max_age = config['revision_max_age_hours'] * 3600
save_violations_csv = config['save_violations_csv']
violations_csv_path = config['violations_csv_path']
eol_alert_window_months = config['eol_alert_window_months']
hw_eol_file_path = config['hw_eol_file_path']
sw_eol_file_path = config['sw_eol_file_path']
firemon_max_workers = config['firemon_max_workers']
cvss_threshold = config['cvss_threshold']
sw_versions = {}
models = {}

# Determine if SMTP authentication is required
smtp_authentication_required = bool(smtp_username)

# Define the authentication URL for FireMon
auth_url = f'{host_url}/securitymanager/api/authentication/login'

# Disable InsecureRequestWarning (ignores certificate warnings)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Timezone information for parsing timestamps
tzinfos = {
    "EST": gettz("America/New_York"),
    "EDT": gettz("America/New_York"),
    "CST": gettz("America/Chicago"),
    "CDT": gettz("America/Chicago"),
    "MST": gettz("America/Denver"),
    "MDT": gettz("America/Denver"),
    "PST": gettz("America/Los_Angeles"),
    "PDT": gettz("America/Los_Angeles"),
    "AKST": gettz("America/Anchorage"),
    "AKDT": gettz("America/Anchorage"),
    "HST": gettz("Pacific/Honolulu"),
    "HAST": gettz("Pacific/Honolulu"),
    "HADT": gettz("Pacific/Honolulu"),
    "ART": gettz("America/Argentina/Buenos_Aires"),
    "BRT": gettz("America/Sao_Paulo"),
    "BRST": gettz("America/Sao_Paulo"),
    "GMT": gettz("Europe/London"),
    "BST": gettz("Europe/London"),
    "CET": gettz("Europe/Paris"),
    "CEST": gettz("Europe/Paris"),
    "EET": gettz("Europe/Helsinki"),
    "EEST": gettz("Europe/Helsinki"),
    "IST": gettz("Asia/Kolkata"),
    "HKT": gettz("Asia/Hong_Kong"),
    "SGT": gettz("Asia/Singapore"),
    "JST": gettz("Asia/Tokyo"),
    "KST": gettz("Asia/Seoul"),
    "CST": gettz("Asia/Shanghai"),
    "AWST": gettz("Australia/Perth"),
    "ACST": gettz("Australia/Adelaide"),
    "ACDT": gettz("Australia/Adelaide"),
    "AEST": gettz("Australia/Sydney"),
    "AEDT": gettz("Australia/Sydney"),
    "NZST": gettz("Pacific/Auckland"),
    "NZDT": gettz("Pacific/Auckland"),
    "UTC": gettz("UTC"),
    "Z": gettz("UTC"),
    "IDT": gettz("Asia/Jerusalem"),
    "AST": gettz("Asia/Riyadh"),
    "WAT": gettz("Africa/Lagos"),
    "CAT": gettz("Africa/Johannesburg"),
    "EAT": gettz("Africa/Nairobi"),
    "PKT": gettz("Asia/Karachi"),
    "BST": gettz("Asia/Dhaka"),
    "WIB": gettz("Asia/Jakarta"),
    "WITA": gettz("Asia/Makassar"),
    "WIT": gettz("Asia/Jayapura"),
    "ALMT": gettz("Asia/Almaty"),
    "MSK": gettz("Europe/Moscow"),
    "SAMT": gettz("Europe/Samara"),
    "YEKT": gettz("Asia/Yekaterinburg"),
    "OMST": gettz("Asia/Omsk"),
    "KRAT": gettz("Asia/Krasnoyarsk"),
    "IRKT": gettz("Asia/Irkutsk"),
    "YAKT": gettz("Asia/Yakutsk"),
    "VLAT": gettz("Asia/Vladivostok"),
    "UTC+0": gettz("UTC"),
    "UTC+1": gettz("Etc/GMT-1"),
    "UTC+2": gettz("Etc/GMT-2"),
    "UTC+3": gettz("Etc/GMT-3"),
    "UTC+4": gettz("Etc/GMT-4"),
    "UTC+5": gettz("Etc/GMT-5"),
    "UTC+6": gettz("Etc/GMT-6"),
    "UTC+7": gettz("Etc/GMT-7"),
    "UTC+8": gettz("Etc/GMT-8"),
    "UTC+9": gettz("Etc/GMT-9"),
    "UTC+10": gettz("Etc/GMT-10"),
    "UTC+11": gettz("Etc/GMT-11"),
    "UTC+12": gettz("Etc/GMT-12"),
    "UTC-1": gettz("Etc/GMT+1"),
    "UTC-2": gettz("Etc/GMT+2"),
    "UTC-3": gettz("Etc/GMT+3"),
    "UTC-4": gettz("Etc/GMT+4"),
    "UTC-5": gettz("Etc/GMT+5"),
    "UTC-6": gettz("Etc/GMT+6"),
    "UTC-7": gettz("Etc/GMT+7"),
    "UTC-8": gettz("Etc/GMT+8"),
    "UTC-9": gettz("Etc/GMT+9"),
    "UTC-10": gettz("Etc/GMT+10"),
    "UTC-11": gettz("Etc/GMT+11"),
    "UTC-12": gettz("Etc/GMT+12"),
}

# Implement the RateLimiter class for controlling API request rates
class RateLimiter:
    def __init__(self, max_calls, period):
        self.max_calls = max_calls
        self.period = period
        self.calls = deque()
        self.lock = Lock()

    def wait(self):
        with self.lock:
            if len(self.calls) >= self.max_calls:
                elapsed = time.time() - self.calls[0]
                if elapsed < self.period:
                    time.sleep(self.period - elapsed)
            self.calls.append(time.time())
            if len(self.calls) > self.max_calls:
                self.calls.popleft()

# Create a rate limiter for API requests to the NVD
nvd_rate_limiter = RateLimiter(50, 30)

# Function to format time differences for display
def format_time_difference(seconds):
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = round(remainder / 60)
    
    if days > 0:
        return f"{days} days, {hours} hrs, {minutes} mins"
    elif hours > 0:
        return f"{hours} hrs, {minutes} mins"
    else:
        return f"{minutes} minutes"

# Function to check if a device's revision is current based on its age
def is_device_current(device_id, max_age):
    logger.debug(f"Checking if device {device_id} is current. Max age: {max_age} seconds")
    if max_age is None:
        logger.debug(f"Device {device_id}: No max age set, considering current")
        return True
    
    device_info_url = f'{host_url}/securitymanager/api/domain/1/device/{device_id}/rev/latest'
    logger.debug(f"Fetching device info from: {device_info_url}")
    try:
        device_info_response = requests.get(device_info_url, headers=headers, verify=not ignore_certificate)
    except requests.RequestException as e:
        logger.error(f"Error fetching device info for {device_id}: {e}")
        return False

    if device_info_response.status_code == 200:
        device_info_data = device_info_response.json()
        postNormalizationCompleteDate = device_info_data.get('postNormalizationCompleteDate')
        revision_id = device_info_data.get('id', 'Unknown Revision ID')

        if postNormalizationCompleteDate:
            postNormalizationCompleteDate_timestamp = datetime.strptime(postNormalizationCompleteDate, '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
            age = now - postNormalizationCompleteDate_timestamp
            is_current = age <= max_age if max_age is not None else True

            logger.info(f"Device ID: {device_id}, Revision ID: {revision_id}, Revision Date: {postNormalizationCompleteDate}, Age: {age:.2f} seconds, Current: {is_current}")
            return is_current
        else:
            logger.warning(f"Device {device_id}: No postNormalizationCompleteDate found")
    else:
        logger.error(f"Failed to fetch device info for {device_id}. Status code: {device_info_response.status_code}")

    return False

# Function to read EOL dates from a CSV file and return a dictionary
def read_eol_dates(csv_file_path):
    eol_dates = {}
    date_formats = ['%B %d, %Y', '%b %d, %Y', '%Y-%m-%d']
    try:
        with open(csv_file_path, 'r') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # Skip header
            for row in reader:
                if len(row) < 2:
                    continue
                for date_format in date_formats:
                    try:
                        eol_dates[row[0]] = datetime.strptime(row[1], date_format)
                        break
                    except ValueError:
                        continue
    except FileNotFoundError:
        logger.error(f"EOL file not found: {csv_file_path}")
    except Exception as e:
        logger.error(f"Error reading EOL file {csv_file_path}: {str(e)}")
    return eol_dates

# Function to compare device version with EOL version
def version_compare(version1, version2):
    """
    Compare two version strings.
    
    :param version1: First version string to compare
    :param version2: Second version string to compare
    :return: -1 if version1 < version2, 0 if version1 == version2, 1 if version1 > version2
    """
    def normalize(v):
        return [int(x) if x.isdigit() else x for x in re.findall(r'([0-9]+|[a-zA-Z]+|-)', v)]

    v1_parts = normalize(version1)
    v2_parts = normalize(version2)
    
    for v1, v2 in zip_longest(v1_parts, v2_parts, fillvalue=0):
        if isinstance(v1, int) and isinstance(v2, int):
            if v1 > v2:
                return 1
            elif v1 < v2:
                return -1
        elif isinstance(v1, str) and isinstance(v2, str):
            if v1 > v2:
                return 1
            elif v1 < v2:
                return -1
        elif isinstance(v1, int) and isinstance(v2, str):
            return 1  # Consider numeric part greater than string part
        elif isinstance(v1, str) and isinstance(v2, int):
            return -1  # Consider numeric part greater than string part
    
    return 0  # versions are equal

# Function to check if a date is within the next X months
def within_next_months(date, months):
    future_date = datetime.now() + timedelta(days=months * 30)
    return date <= future_date

# Function to parse timestamps from strings into UTC timestamps
def parse_timestamp(timestamp_str):
    try:
        dt = parser.parse(timestamp_str, tzinfos=tzinfos)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        logger.debug(f"Parsed timestamp: {timestamp_str} to UTC: {dt.isoformat()}")
        return dt.astimezone(timezone.utc).timestamp()
    except ValueError as e:
        logger.error(f"Error parsing timestamp: {timestamp_str}. Error: {e}")
        return None

# Function to check for vulnerabilities using the vendor's API
def check_vulnerabilities(panos_version):
    logger.info(f"Checking vulnerabilities for PAN-OS version: {panos_version}")
    base_url = "https://security.paloaltonetworks.com/api/v1/products/PAN-OS"
    url = f"{base_url}/{quote(panos_version)}/advisories"
    
    vulnerabilities = []
    try:
        nvd_rate_limiter.wait()
        logger.debug(f"Sending request to: {url}")
        response = requests.get(url, verify=not ignore_certificate)
        response.raise_for_status()
        
        data = json.loads(response.text)
        advisories = data.get('data', [])
        logger.debug(f"Received {len(advisories)} advisories for version {panos_version}")
        
        if isinstance(advisories, list):
            for advisory in advisories:
                cve_id = advisory.get('CVE_data_meta', {}).get('ID')
                if not cve_id:
                    logger.debug(f"Skipping advisory without CVE ID for version {panos_version}")
                    continue
                
                impact = advisory.get('impact', {})
                cvss = impact.get('cvss', {})
                cvss_score = cvss.get('baseScore')
                if cvss_score is not None:
                    try:
                        cvss_score = float(cvss_score)
                        if cvss_score < cvss_threshold:
                            logger.debug(f"Skipping CVE {cve_id} due to low CVSS score: {cvss_score}")
                            continue
                    except ValueError:
                        logger.warning(f"Invalid CVSS score for CVE {cve_id}: {cvss_score}")
                
                vulnerabilities.append({
                    "cve_id": cve_id,
                    "description": advisory.get('description', {}).get('description_data', [{}])[0].get('value', 'N/A'),
                    "severity": cvss.get('baseSeverity', 'N/A'),
                    "cvss_score": cvss_score,
                    "vendor_advisory": f"https://security.paloaltonetworks.com/{cve_id}"
                })
                logger.debug(f"Added vulnerability: {cve_id} for version {panos_version}")
        else:
            logger.warning(f"Unexpected advisories format for version {panos_version}: {advisories}")

    except requests.exceptions.RequestException as e:
        logger.error(f'Error checking vulnerabilities for version {panos_version}: {e}')
    except json.JSONDecodeError as e:
        logger.error(f'Error decoding JSON response for version {panos_version}: {e}')
    except Exception as e:
        logger.error(f'Unexpected error checking vulnerabilities for version {panos_version}: {e}')

    logger.info(f"Found {len(vulnerabilities)} vulnerabilities for version {panos_version}")
    return vulnerabilities

# Function to check vulnerabilities in batches for multiple devices
def check_vulnerabilities_batch(devices_versions):
    cve_details = defaultdict(set)
    for device_name, device_id, device_version in devices_versions:
        cves = check_vulnerabilities(device_version)
        for cve in cves:
            cve_key = (cve['cve_id'], cve['description'], cve['severity'], cve['cvss_score'], cve['vendor_advisory'])
            device_info = f"{device_name} ({device_id})"
            cve_details[cve_key].add(device_info)
    return cve_details

# Function to find the correct EOL version and date for a given device version
def find_eol_version_and_date(device_version, sw_eol_dates):
    device_major_version = device_version.split('.')[0]
    matching_eol_version = None
    matching_eol_date = None

    for eol_version, eol_date in sw_eol_dates.items():
        eol_major_version = eol_version.split('.')[0]
        if eol_major_version == device_major_version:
            if matching_eol_version is None or version_compare(eol_version, matching_eol_version) > 0:
                matching_eol_version = eol_version
                matching_eol_date = eol_date

    if matching_eol_version:
        logger.debug(f"Matched EOL version: {matching_eol_version} with device version: {device_version}, EOL date: {matching_eol_date}")
        return matching_eol_version, matching_eol_date
    else:
        logger.debug(f"No matching EOL version found for device version: {device_version}")
        return None, None

# Function to consolidate results from various checks into a single report
def consolidate_results(violations, eol_violations, cve_details, device_summaries, timestamps, sw_versions, models):
    consolidated_results = {}
    
    # Collect all device IDs from various sources
    all_device_ids = set(
        [str(v[0]) for v in violations] +
        [str(v[0]) for v in eol_violations] +  # Ensure correct handling of set
        [d.split('(')[1].rstrip(')') for devices in cve_details.values() for d in devices]
    )
    
    logger.debug(f"Software versions before consolidation: {sw_versions}")

    for device_id in all_device_ids:
        device_name, management_ip = device_summaries.get(int(device_id), ('Unknown Device', 'Unknown IP'))
        consolidated_results[device_id] = {
            'device_name': device_name,
            'management_ip': management_ip,
            'sw_version': sw_versions.get(str(device_id), 'N/A'),
            'model': models.get(int(device_id), 'N/A'),
            'violations': [],
            'eol_violations_hw': None,
            'eol_violations_sw': None,
            'vulnerabilities': set()
        }
        logger.debug(f"Consolidated result for device {device_id}: {consolidated_results[device_id]}")

    # Add violations to the consolidated results
    for device_id, violation_type in violations:
        if str(device_id) in consolidated_results:
            consolidated_results[str(device_id)]['violations'].append((violation_type, timestamps.get(device_id, {}).get(violation_type)))
    
    # Add EOL violations to the consolidated results
    for device_id, violation_type, value, eol_version, eol_date in eol_violations:
        if str(device_id) in consolidated_results:
            if violation_type == 'hardware':
                consolidated_results[str(device_id)]['eol_violations_hw'] = (value, eol_date)
            elif violation_type == 'software':
                consolidated_results[str(device_id)]['eol_violations_sw'] = (value, eol_version, eol_date)
    
    # Add vulnerabilities to the consolidated results
    for cve_key, devices in cve_details.items():
        for device_info in devices:
            device_name, device_id = device_info.split(' (')
            device_id = device_id.rstrip(')')
            if device_id in consolidated_results:
                consolidated_results[device_id]['vulnerabilities'].add(cve_key[0])
    
    logger.debug(f"Consolidated results: {consolidated_results}")
    return consolidated_results

# Read EOL dates from CSV files for both hardware and software
hw_eol_dates = read_eol_dates(hw_eol_file_path)
sw_eol_dates = read_eol_dates(sw_eol_file_path)

logger.info(f"Loaded {len(hw_eol_dates)} hardware EOL dates and {len(sw_eol_dates)} software EOL dates")
logger.debug(f"Hardware EOL dates: {hw_eol_dates}")
logger.debug(f"Software EOL dates: {sw_eol_dates}")

try:
    logger.info("Authenticating to FireMon...")
    auth_payload = {'username': username, 'password': password}
    auth_response = requests.post(auth_url, json=auth_payload, verify=not ignore_certificate)

    if auth_response.status_code == 200:
        auth_data = auth_response.json()
        auth_token = auth_data.get('token', '')
        logger.info("Authentication successful")

        if config['eol_revision_max_age'] == 'None':
            eol_revision_max_age = None
        else:
            eol_revision_max_age = float(config['eol_revision_max_age']) * 3600  # Convert hours to seconds

        logger.info(f"Loaded eol_revision_max_age: {eol_revision_max_age} seconds")

        url = f'{host_url}/securitymanager/api/domain/1/control/{control_uuid}/execute/devicegroup/{device_group_id}?allControlResults=true'
        headers = {'accept': 'application/json', 'X-FM-AUTH-TOKEN': auth_token}

        logger.info(f"Making API call to: {url}")
        response = requests.get(url, headers=headers, verify=not ignore_certificate)
        logger.info(f"Received response with status code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            logger.debug(f"API Response: {json.dumps(data, indent=2)}")
            
            device_summaries = {d['deviceId']: (d['deviceName'], d.get('deviceManagementIp', 'Unknown IP')) for d in data.get('deviceSummaries', [])}

            timestamps = {}
            violations = []
            eol_violations = set()  # Ensure eol_violations is initialized correctly
            palo_alto_devices = []

            for match in data.get('regexMatches', []):
                line = match.get('line', '')
                device_id = match.get('deviceId', None)

                logger.debug(f"Processing line for device {device_id}: {line}")

                current_for_version_check = device_id is not None and is_device_current(device_id, revision_max_age)
                current_for_eol_check = device_id is not None and is_device_current(device_id, eol_revision_max_age)

                if device_id is not None:
                    wildfire_match = re.search(r'<wildfire-release-date>(.*?)</wildfire-release-date>', line)
                    av_match = re.search(r'<av-release-date>(.*?)</av-release-date>', line)
                    app_match = re.search(r'<app-release-date>(.*?)</app-release-date>', line)
                    threat_match = re.search(r'<threat-release-date>(.*?)</threat-release-date>', line)
                    
                    # Correctly assign software version and model
                    sw_version_match = re.search(r'<sw-version>(.*?)</sw-version>', line)
                    if sw_version_match:
                        sw_version = sw_version_match.group(1)
                        if str(device_id) not in sw_versions:
                            sw_versions[str(device_id)] = sw_version
                            logger.info(f"Captured software version for device {device_id}: {sw_version}")
                    
                    model_match = re.search(r'<model>(.*?)</model>', line)
                    if model_match:
                        model = model_match.group(1)
                        models[str(device_id)] = model
                    
                    logger.debug(f"Device {device_id} - Version: {sw_versions.get(str(device_id))}, Model: {models.get(str(device_id))}")

                    if device_id not in timestamps:
                        timestamps[device_id] = {}

                    if current_for_version_check:
                        if wildfire_match:
                            timestamp = parse_timestamp(wildfire_match.group(1))
                            if timestamp:
                                timestamps[device_id]['wildfire-release-date'] = timestamp
                                if now - timestamp > wildfire_max_age:
                                    violations.append((device_id, 'wildfire-release-date'))
                        
                        if av_match:
                            timestamp = parse_timestamp(av_match.group(1))
                            if timestamp:
                                timestamps[device_id]['av-release-date'] = timestamp
                                if now - timestamp > av_max_age:
                                    violations.append((device_id, 'av-release-date'))
                        
                        if app_match:
                            timestamp = parse_timestamp(app_match.group(1))
                            if timestamp:
                                timestamps[device_id]['app-release-date'] = timestamp
                                if now - timestamp > app_max_age:
                                    violations.append((device_id, 'app-release-date'))
                        
                        if threat_match:
                            timestamp = parse_timestamp(threat_match.group(1))
                            if timestamp:
                                timestamps[device_id]['threat-release-date'] = timestamp
                                if now - timestamp > threat_max_age:
                                    violations.append((device_id, 'threat-release-date'))

                    sw_version = sw_versions.get(str(device_id), 'N/A')
                    model = model_match.group(1) if model_match else 'N/A'
                    
                    device_name, management_ip = device_summaries.get(device_id, ('Unknown Device', 'Unknown IP'))
                    palo_alto_devices.append((device_name, device_id, sw_version))

                    logger.info(f"Checked device {device_id}: {device_summaries.get(device_id, ('Unknown Device', 'Unknown IP'))}, "
                                f"Wildfire Date: {timestamps.get(device_id, {}).get('wildfire-release-date', 'N/A')}, "
                                f"AV Date: {timestamps.get(device_id, {}).get('av-release-date', 'N/A')}, "
                                f"App Date: {timestamps.get(device_id, {}).get('app-release-date', 'N/A')}, "
                                f"Threat Date: {timestamps.get(device_id, {}).get('threat-release-date', 'N/A')}, "
                                f"Software Version: {sw_version}, "
                                f"Model: {model}")

                    if current_for_eol_check:
                        sw_version = sw_versions.get(str(device_id), 'N/A')
                        if sw_version != 'N/A':
                            logger.debug(f"Checking EOL for device {device_id}, sw version: {sw_version}")
                            eol_version, eol_date = find_eol_version_and_date(sw_version, sw_eol_dates)
                            if eol_version and eol_date and (within_next_months(eol_date, eol_alert_window_months) or eol_date.timestamp() < now):
                                logger.debug(f"EOL violation found for device {device_id}: version {sw_version}, EOL version: {eol_version}, EOL date: {eol_date}")
                                eol_violations.add((device_id, 'software', sw_version, eol_version, eol_date))

                        if model_match:
                            model = model_match.group(1)
                            logger.debug(f"Checking EOL for device {device_id}, model: {model}")
                            eol_date = hw_eol_dates.get(model)
                            if eol_date:
                                logger.debug(f"Found EOL date for model {model}: {eol_date}")
                                if within_next_months(eol_date, eol_alert_window_months) or eol_date.timestamp() < now:
                                    logger.debug(f"EOL violation found for device {device_id}: model {model}, EOL date: {eol_date}")
                                    eol_violations.add((device_id, 'hardware', model, model, eol_date))

            cve_details = defaultdict(set)
            with ThreadPoolExecutor(max_workers=firemon_max_workers) as executor:
                chunk_size = 10
                futures = []
                for i in range(0, len(palo_alto_devices), chunk_size):
                    chunk = palo_alto_devices[i:i+chunk_size]
                    futures.append(executor.submit(check_vulnerabilities_batch, chunk))
                for future in as_completed(futures):
                    chunk_cve_details = future.result()
                    for cve_key, devices in chunk_cve_details.items():
                        cve_details[cve_key].update(devices)

            total_vulnerable_devices = 0

            for device_id, device_name in device_summaries.items():
                device_info = f"{device_name} ({device_id})"
                device_cves = [cve_key[0] for cve_key, devices in cve_details.items() if device_info in devices]
                if device_cves:
                    if device_id not in timestamps:
                        timestamps[device_id] = {}
                    timestamps[device_id]['Vulnerabilities'] = ', '.join(device_cves)
                    total_vulnerable_devices += 1

            # Collect sw_versions and models for consolidation
            sw_versions = {str(device_id): sw_version for device_name, device_id, sw_version in palo_alto_devices}
            models = {device_id: model for device_id, model in [(match.get('deviceId'), re.search(r'<model>(.*?)</model>', match.get('line', '')).group(1)) for match in data.get('regexMatches', []) if re.search(r'<model>(.*?)</model>', match.get('line', ''))]}

            logger.debug(f"Software versions before report generation: {sw_versions}")

            # Ensure consolidated_results is properly initialized and handles None values
            consolidated_results = {}
            if eol_violations is None:
                eol_violations = set()

            # Add checks to ensure that 'eol_violations' data is correctly handled
            if violations or eol_violations or cve_details:
                logger.warning(f"Issues detected. {len(violations)} update violations, {len(eol_violations)} EOL violations, {len(cve_details)} vulnerabilities")
                
                consolidated_results = consolidate_results(violations, eol_violations, cve_details, device_summaries, timestamps, sw_versions, models)
                
                if consolidated_results:
                    summary = "Palo Alto Devices with Issues Detected:\n\n"
                    for device_id, result in consolidated_results.items():
                        summary += f"FireMon Device ID: {device_id}\n"
                        summary += f"Device Name: {result['device_name']}\n"
                        summary += f"Management IP: {result['management_ip']}\n"
                        summary += f"Version: {result['sw_version']}\n"
                        summary += f"Model: {result['model']}\n"
                        
                        for violation_type, timestamp in result['violations']:
                            timestamp_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
                            formatted_difference = format_time_difference(now - timestamp)
                            summary += f"Outdated {violation_type}: {timestamp_str} (Age: {formatted_difference})\n"
                        
                        if result['eol_violations_hw']:
                            hw_model, hw_eol_date = result['eol_violations_hw']
                            summary += f"EOL Hardware: {hw_model} (EOL Date: {hw_eol_date.strftime('%Y-%m-%d')})\n"
                        
                        if result['eol_violations_sw']:
                            sw_version, sw_eol_version, sw_eol_date = result['eol_violations_sw']
                            summary += f"EOL Software: {sw_version} (EOL Version: {sw_eol_version}, EOL Date: {sw_eol_date.strftime('%Y-%m-%d')})\n"
                        
                        if result['vulnerabilities']:
                            summary += f"Vulnerabilities: {', '.join(result['vulnerabilities'])}\n"
                        
                        summary += "\n"
                                        
                    total_devices_with_issues = len(consolidated_results)
                    summary += f"\nTotal devices with issues: {total_devices_with_issues}\n"
                    
                    print(summary)
                    logger.info(summary)
                
                if save_violations_csv:
                    try:
                        with open(violations_csv_path, 'w', newline='') as csvfile:
                            fieldnames = ['Device Name', 'Device ID', 'Management IP', 'Software Version', 'Model', 'Violations', 'EOL Violations', 'Vulnerabilities']
                            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                            writer.writeheader()
                            
                            for device_id, result in consolidated_results.items():
                                violations_str = '; '.join([f"{v}: {datetime.fromtimestamp(t, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}" for v, t in result['violations']])
                                
                                eol_violations = []
                                if result['eol_violations_hw']:
                                    hw_model, hw_eol_date = result['eol_violations_hw']
                                    eol_violations.append(f"Hardware: {hw_model} (EOL Date: {hw_eol_date.strftime('%Y-%m-%d')})")
                                if result['eol_violations_sw']:
                                    sw_version, sw_eol_version, sw_eol_date = result['eol_violations_sw']
                                    eol_violations.append(f"Software: {sw_version} (EOL Version: {sw_eol_version}, EOL Date: {sw_eol_date.strftime('%Y-%m-%d')})")
                                eol_violations_str = '; '.join(eol_violations)
                                
                                writer.writerow({
                                    'Device Name': result['device_name'],
                                    'Device ID': device_id,
                                    'Management IP': result['management_ip'],
                                    'Software Version': result['sw_version'],
                                    'Model': result['model'],
                                    'Violations': violations_str,
                                    'EOL Violations': eol_violations_str,
                                    'Vulnerabilities': ', '.join(result['vulnerabilities'])
                                })
                        
                        logger.info(f"Consolidated violations saved to {violations_csv_path}")
                    except Exception as e:
                        logger.error(f"Error writing to CSV file: {e}")
                        print(f"Error writing to CSV file: {e}")

                cve_csv_path = 'palo_alto_cve_report.csv'
                with open(cve_csv_path, 'w', newline='') as cvefile:
                    fieldnames = ['CVE ID', 'Description', 'Severity', 'CVSS Score', 'Vendor Advisory', 'Affected Devices']
                    writer = csv.DictWriter(cvefile, fieldnames=fieldnames)
                    writer.writeheader()
                    for cve_key, devices in cve_details.items():
                        writer.writerow({
                            'CVE ID': cve_key[0],
                            'Description': cve_key[1],
                            'Severity': cve_key[2],
                            'CVSS Score': cve_key[3],
                            'Vendor Advisory': cve_key[4],
                            'Affected Devices': ', '.join(devices)
                        })

                logger.info(f"CVE details saved to {cve_csv_path}")

                if email_enabled and (not smtp_authentication_required or (smtp_authentication_required and smtp_username and smtp_password)):
                    subject = "[FireMon] Outdated Palo Alto Releases and EOL Devices Detected"
                    if send_aggregate_email:
                        try:
                            server = smtplib.SMTP(smtp_server, smtp_port)
                            if use_tls:
                                server.starttls()
                            if smtp_authentication_required:
                                server.login(smtp_username, smtp_password)

                            message = MIMEMultipart()
                            message['Subject'] = subject
                            message['From'] = sender_email
                            message['To'] = recipient_email
                            message.attach(MIMEText(summary, 'plain'))

                            attachments = [violations_csv_path, cve_csv_path]
                            for attachment_path in attachments:
                                with open(attachment_path, 'rb') as attachment:
                                    part = MIMEBase('application', 'octet-stream')
                                    part.set_payload(attachment.read())
                                    encoders.encode_base64(part)
                                    part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
                                    message.attach(part)

                            server.sendmail(sender_email, recipient_email, message.as_string())
                            logger.info("Aggregate email alert sent with out of date Palo Alto releases and EOL devices")
                            print("Aggregate email alert sent with out of date Palo Alto releases and EOL devices")
                        except Exception as e:
                            logger.error(f"Failed to send aggregate email alert: {e}")
                            print(f"Failed to send aggregate email alert: {e}")
                    else:
                        for device_id, result in consolidated_results.items():
                            device_name = result['device_name']
                            management_ip = result['management_ip']
                            sw_version = result['sw_version']
                            model = result['model']
                            
                            individual_subject = f"[FireMon] Palo Alto Issues Detected for {device_name}"
                            individual_body = f"FireMon Device ID: {device_id}\n"
                            individual_body += f"Device Name: {device_name}\n"
                            individual_body += f"Management IP: {management_ip}\n"
                            individual_body += f"Software Version: {sw_version}\n"
                            individual_body += f"Model: {model}\n\n"
                            
                            for violation_type, timestamp in result['violations']:
                                timestamp_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
                                formatted_difference = format_time_difference(now - timestamp)
                                individual_body += f"Outdated {violation_type}: {timestamp_str} (Age: {formatted_difference})\n"
                            
                            if result['eol_violations_hw']:
                                hw_model, hw_eol_date = result['eol_violations_hw']
                                individual_body += f"EOL Hardware: {hw_model} (EOL Date: {hw_eol_date.strftime('%Y-%m-%d')})\n"
                            
                            if result['eol_violations_sw']:
                                sw_version, sw_eol_version, sw_eol_date = result['eol_violations_sw']
                                individual_body += f"EOL Software: {sw_version} (EOL Version: {sw_eol_version}, EOL Date: {sw_eol_date.strftime('%Y-%m-%d')})\n"
                            
                            if result['vulnerabilities']:
                                individual_body += f"Vulnerabilities: {', '.join(result['vulnerabilities'])}\n"
                            
                            try:
                                server = smtplib.SMTP(smtp_server, smtp_port)
                                if use_tls:
                                    server.starttls()
                                if smtp_authentication_required:
                                    server.login(smtp_username, smtp_password)

                                message = MIMEMultipart()
                                message['Subject'] = individual_subject
                                message['From'] = sender_email
                                message['To'] = recipient_email
                                message.attach(MIMEText(individual_body, 'plain'))

                                attachments = [violations_csv_path, cve_csv_path]
                                for attachment_path in attachments:
                                    with open(attachment_path, 'rb') as attachment:
                                        part = MIMEBase('application', 'octet-stream')
                                        part.set_payload(attachment.read())
                                        encoders.encode_base64(part)
                                        part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
                                        message.attach(part)
                                server.sendmail(sender_email, recipient_email, message.as_string())
                                logger.info(f"Email alert sent for Device: {device_name}")
                                print(f"Email alert sent for Device: {device_name}")
                            except Exception as e:
                                logger.error(f"Failed to send email alert for {device_name}: {e}")
                                print(f"Failed to send email alert for {device_name}: {e}")
                else:
                    if send_aggregate_email:
                        print(summary)
                        logger.info("No email sent. Summary output to console.")
                    else:
                        print("Outdated Releases:\n")
                        print(summary)
                        logger.info("No email sent. Individual summaries output to console.")
            else:
                logger.info("No issues found.")
                if not email_enabled and send_aggregate_email:
                    print("No issues found.")
                elif not violations:
                    print("No issues found.")
        else:
            logger.error(f"API request failed with status code: {response.status_code}")
            logger.debug(f"API Response: {response.text}")
            print(f"API request failed with status code: {response.status_code}")
    else:
        logger.error(f"Authentication request failed with status code: {auth_response.status_code}")
        logger.debug(f"Authentication Response: {auth_response.text}")
        print(f"Authentication request failed with status code: {auth_response.status_code}")
except requests.exceptions.RequestException as e:
    logger.critical(f"An error occurred during the request: {e}")
    print(f"An error occurred during the request: {e}")
except ValueError as e:
    logger.error(f"Failed to parse JSON response: {e}")
    print(f"Failed to parse JSON response: {e}")
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    print(f"Unexpected error: {e}")
