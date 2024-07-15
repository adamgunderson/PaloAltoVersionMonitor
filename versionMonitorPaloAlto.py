#!/usr/bin/python

######################################################################################################
##                                                                                                  ##
##                                                                                                  ##
##                                                                                                  ##
##             ,FFFFFFF   ,II   ;RRRRR?    ;EEEEEEE  ,MM,    .MM     :OOOO:    :N,    :N            ##
##             :FF`````   :II   :R````R?   :E;`````  :MM?    +MM   :OO?``+OO   :NN:   :N            ##
##             :FF        :II   :R,  .?R   :E;       :MMM    MMM  :OO:    OO,  :NNN,  :N            ##
##             :FF        :II   :R,  .?R   :E;       :MMM:  :MMM  :OO     :OO  :N,NN  :N            ##
##             :FFFFFFF   :II   :R+;;*R+   :EEEEEEE  :MM:M::M;MM  :OO     :OO  :N `N: :N            ##
##             :FF`````   :II   :RR`RR;    :E;`````  :MM ?MM% MM  :O*     :OO  :N  `N::N            ##
##             :FF        :II   :R,  R+    :E;       :MM :MM: MM  'OO,    OO`  :N   `NNN            ##
##             :FF        :II   :R,  `R;   :E;       :MM  ``  MM   :OO+,;OO,   :N    :NN            ##
##             :FF        :II   :R,   RR;  :EEEEEEE  :MM      MM    `OOOOO ##  :N    'NN            ##
##              ``         ``    ``   ```   ```````   ``      ``      ```       `     ``            ##
##                                                                           ##                     ##
##                                                                                                  ##
##                         Palo Alto Version Alerting for FireMon              ##                   ##
##                         Version 0.57                                                             ##
##                                                                                                  ##
##                         By Adam Gunderson                                                        ##
##                         Adam.Gunderson@FireMon.com                                               ##
##                                                                                                  ##
##    This script uses a regex conrol that checks timestamps for av-release-date,                   ##
##    wildfire-release-date, and threat-release-date from api_system_info. It also checks for EOL   ##
##    hardware and software versions.                                                               ##
##                                                                                                  ##
##    An import of the control can be downloaded here:                                              ##
##    https://firemon.xyz/imports/PaloAltoVersionsMonitor.export.json                               ##
##                                                                                                  ##
##                                                                                                  ##
##    DISCLAIMER:                                                                                   ##
##    The following Python script is provided "AS IS" without warranty of any kind.                 ##
##    Users should use this script at their own risk. The author assumes no responsibility          ##
##    for any potential damages or losses that may arise from its use.                              ##
##    This script may not be suitable for all types of data or use cases,                           ##
##    and it is up to the user to determine its applicability to their specific needs.              ##
##                                                                                                  ##
######################################################################################################

# Import standard modules
import sys
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')  # Adjust this path based on your version of FMOS.

import requests
import re
import csv
from datetime import datetime, timedelta, timezone  # Import the timezone object
from dateutil import parser  # Import the parser from dateutil
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import time
import urllib3
import logging

#################################################
##             START CONFIGURATION             ##
#################################################

# FireMon Host (Replace with your host URL)
host_url = 'https://localhost'

# Security Manager Username and Password for authentication
username = 'firemon'
password = 'firemon'

# Control UUID (Replace with your control UUID)
control_uuid = '14d888ce-22d6-4942-95c0-9f393731fb5e'

# Device group to check against
device_group_id = 1

# Email configuration
email_enabled = True  # Set to True to enable email sending
smtp_server = 'localhost'
smtp_port = 25  # 25 for non-TLS, 587 for TLS
use_tls = False  # Set to True to use TLS when sending emails
smtp_username = ''  # Leave empty if not using authentication
smtp_password = ''  # Leave empty if not using authentication
sender_email = 'PaloAltoVersionMon@firemon.com'
recipient_email = 'adam.gunderson@firemon.com'

# Combine alerts into a single email (True) or individual (False)
send_aggregate_email = True

# Define time thresholds for WildFire, AV, Threat, and App update timestamps.
now = time.time()
WildfireMaxAge = now - 2 * 3600  # 2 hours in seconds
AVMaxAge = now - 2 * 24 * 3600  # 2 days in seconds
ThreatMaxAge = now - 8 * 24 * 3600  # 8 days in seconds
AppMaxAge = now - 8 * 24 * 3600  # 8 days in seconds

# Define the maximum age for device revision (in seconds, default to 2 hours). This prevents false positives for devices that FireMon hasn't recently connected to.
RevisionMaxAge = 2 * 3600  # 2 hours in seconds

# Define the maximum age for device revision specifically for EOL checks (in seconds, set to None for unlimited/disabled).
EOLRevisionMaxAge = None  # Unlimited/disabled

# Option to ignore certificate validation for FireMon (set to True to ignore validation, helpful if using self-signed certs)
ignore_certificate = True

# Enable logging and set the log file path
logging_enabled = True
log_file_path = 'palo_alto_version_monitor.log'

# Option to save violations as CSV
save_violations_csv = True
violations_csv_path = 'violations.csv'

# Option to only check EOL violations
check_eol_only = False

# Option to attach CSV to email
attach_csv_to_email = True

# Option to only alert for EOL violations in the next X months
eol_alert_window_months = 6

# Define a mapping of timezone abbreviations to UTC offsets.
timezone_offsets = {
    'PST': '-0800',  # Pacific Standard Time
    'PDT': '-0700',  # Pacific Daylight Time
    'CAT': '+0200',  # Central Africa Time
    'EET': '+0200',  # Eastern European Time
    'IDT': '+0300',  # Israel Daylight Time
    'GET': '+0400',  # Georgia Standard Time
    'AFT': '+0430',  # Afghanistan Time
    'TMT': '+0500',  # Turkmenistan Time
    'JST': '+0900',  # Japan Standard Time
    'EDT': '-0400',  # Eastern Daylight Time
    'CDT': '-0500',  # Central Daylight Time
    'EST': '-0500',  # Eastern Standard Time
    'CST': '-0600',  # Central Standard Time
    'MDT': '-0600',  # Mountain Daylight Time
    'MST': '-0700',  # Mountain Standard Time
    'PDT': '-0700',  # Pacific Daylight Time
    'PST': '-0800',  # Pacific Standard Time
    'HST': '-1000',  # Hawaii Standard Time
    'UTC': '+0000',  # Coordinated Universal Time
    'GMT': '+0000',  # Greenwich Mean Time
    'CET': '+0100',  # Central European Time
    'CEST': '+0200',  # Central European Summer Time
    'MSK': '+0300',  # Moscow Standard Time
    'IST': '+0530',  # Indian Standard Time
    'NPT': '+0545',  # Nepal Time
    'SGT': '+0800',  # Singapore Time
    'AWST': '+0800',  # Australian Western Standard Time
    'AEST': '+1000',  # Australian Eastern Standard Time
    'NZST': '+1200',  # New Zealand Standard Time
    'ART': '-0300',  # Argentina Time
    'BRT': '-0300',  # Brasília Time
    'CLT': '-0400',  # Chile Standard Time
    'EAST': '+1000',  # Eastern Australia Standard Time
    'FJT': '+1300',  # Fiji Time
    'GST': '+0400',  # Gulf Standard Time
    'HKT': '+0800',  # Hong Kong Time
    'NAT': '-0330',  # Newfoundland Standard Time
    'NST': '-0330',  # Newfoundland Standard Time
    'PET': '-0500',  # Peru Time
    'SAST': '+0200',  # South Africa Standard Time
    'UYT': '-0300',  # Uruguay Standard Time
    'WAT': '+0100',  # West Africa Time
    'WET': '+0000',  # Western European Time
    'WIT': '+0900',  # Eastern Indonesian Time
    # Add more timezones as needed
}

# Paths to the CSV files containing EOL dates
hw_eol_file_path = 'palo_alto_eol_hw_dates.csv'
sw_eol_file_path = 'palo_alto_eol_sw_dates.csv'

#################################################
##               END CONFIGURATION             ##
#################################################

# Disable InsecureRequestWarning (ignore certificate warnings)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

smtp_authentication_required = bool(smtp_username)  # True if username is provided

# Setup logging
if logging_enabled:
    logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the authentication URL
auth_url = f'{host_url}/securitymanager/api/authentication/login'

# Function to check postNormalizationCompleteDate and return True if the device is current, False otherwise
def is_device_current(device_id, max_age):
    if max_age is None:
        return True  # If max_age is None, consider the device as current regardless of age
    
    device_info_url = f'{host_url}/securitymanager/api/domain/1/device/{device_id}/rev/latest'
    device_info_response = requests.get(device_info_url, headers=headers, verify=not ignore_certificate)

    if device_info_response.status_code == 200:
        device_info_data = device_info_response.json()
        postNormalizationCompleteDate = device_info_data.get('postNormalizationCompleteDate')

        if postNormalizationCompleteDate:
            postNormalizationCompleteDate_timestamp = datetime.strptime(postNormalizationCompleteDate, '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
            age = now - postNormalizationCompleteDate_timestamp
            return age <= max_age

    # If there's an issue with the API request, return False (assume device is not current)
    return False

# Function to read EOL dates from a CSV file and return a dictionary
def read_eol_dates(csv_file_path):
    eol_dates = {}
    date_formats = ['%B %d, %Y', '%b %d, %Y']  # Define multiple date formats to handle different date formats
    with open(csv_file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header row
        for row in reader:
            if len(row) < 2:
                continue  # Skip rows that don't have at least 2 columns
            for date_format in date_formats:
                try:
                    eol_dates[row[0]] = datetime.strptime(row[1], date_format)
                    break
                except ValueError:
                    continue
    return eol_dates

# Function to compare sub-versions
def version_compare(device_version, eol_version):
    device_parts = device_version.split('.')
    eol_parts = eol_version.split('.')
    for dp, ep in zip(device_parts, eol_parts):
        if int(dp) > int(ep):
            return False
        elif int(dp) < int(ep):
            return True
    return len(device_parts) >= len(eol_parts)

# Function to check if a date is within the next X months
def within_next_months(date, months):
    future_date = datetime.now() + timedelta(days=months * 30)  # Approximate calculation of months
    return date <= future_date

# Read EOL dates from CSV files
hw_eol_dates = read_eol_dates(hw_eol_file_path)
sw_eol_dates = read_eol_dates(sw_eol_file_path)

try:
    # Authenticate to FireMon
    auth_payload = {
        'username': username,
        'password': password
    }

    auth_response = requests.post(auth_url, json=auth_payload, verify=not ignore_certificate)

    # Check if the authentication request was successful
    if auth_response.status_code == 200:
        auth_data = auth_response.json()

        # Extract the auth token from the response
        auth_token = auth_data.get('token', '')

        # Define the API URL and headers with the obtained auth token
        url = f'{host_url}/securitymanager/api/domain/1/control/{control_uuid}/execute/devicegroup/{device_group_id}?allControlResults=true'
        headers = {
            'accept': 'application/json',
            'X-FM-AUTH-TOKEN': auth_token
        }

        # Make the API call with certificate validation option
        response = requests.get(url, headers=headers, verify=not ignore_certificate)

        # Check if the API call was successful
        if response.status_code == 200:
            data = response.json()

            # Extract device summaries
            device_summaries = {d['deviceId']: d['deviceName'] for d in data.get('deviceSummaries', [])}

            # Extract timestamps and device IDs from regexMatches
            timestamps = {}
            violations = []  # Store violations to check if there are any
            eol_violations = set()  # Store EOL violations, use a set to avoid duplicates

            for match in data.get('regexMatches', []):
                line = match.get('line', '')
                device_id = match.get('deviceId', None)

                # Check if the device is current for version checks
                current_for_version_check = device_id is not None and is_device_current(device_id, RevisionMaxAge)

                # Check if the device is current for EOL checks
                current_for_eol_check = device_id is not None and is_device_current(device_id, EOLRevisionMaxAge)

                if device_id is not None:
                    # Use regular expressions to extract timestamps and EOL data
                    wildfire_match = re.search(r'<wildfire-release-date>(.*?)</wildfire-release-date>', line)
                    av_match = re.search(r'<av-release-date>(.*?)</av-release-date>', line)
                    app_match = re.search(r'<app-release-date>(.*?)</app-release-date>', line)
                    threat_match = re.search(r'<threat-release-date>(.*?)</threat-release-date>', line)
                    sw_version_match = re.search(r'<sw-version>(.*?)</sw-version>', line)
                    model_match = re.search(r'<model>(.*?)</model>', line)

                    # Create a dictionary for the device if it doesn't exist
                    if device_id not in timestamps:
                        timestamps[device_id] = {}

                    if not check_eol_only and current_for_version_check:
                        # Store the timestamps in the dictionary if found
                        if wildfire_match:
                            timestamp_str = wildfire_match.group(1)
                            timestamp = parser.parse(timestamp_str).timestamp()
                            timestamps[device_id]['wildfire-release-date'] = timestamp
                            if timestamp < WildfireMaxAge:
                                violations.append((device_id, 'wildfire-release-date'))
                        if av_match:
                            timestamp_str = av_match.group(1)
                            timestamp = parser.parse(timestamp_str).timestamp()
                            timestamps[device_id]['av-release-date'] = timestamp
                            if timestamp < AVMaxAge:
                                violations.append((device_id, 'av-release-date'))
                        if app_match:
                            timestamp_str = app_match.group(1)
                            timestamp = parser.parse(timestamp_str).timestamp()
                            timestamps[device_id]['app-release-date'] = timestamp
                            if timestamp < AppMaxAge:
                                violations.append((device_id, 'app-release-date'))
                        if threat_match:
                            timestamp_str = threat_match.group(1)
                            timestamp = parser.parse(timestamp_str).timestamp()
                            timestamps[device_id]['threat-release-date'] = timestamp
                            if timestamp < ThreatMaxAge:
                                violations.append((device_id, 'threat-release-date'))

                    # Check EOL for software version
                    if sw_version_match and current_for_eol_check:
                        sw_version = sw_version_match.group(1)
                        for version, eol_date in sw_eol_dates.items():
                            if version_compare(sw_version, version):
                                if within_next_months(eol_date, eol_alert_window_months) or eol_date.timestamp() < now:
                                    eol_violations.add((device_id, 'software', sw_version, eol_date))
                                    break

                    # Check EOL for hardware model
                    if model_match and current_for_eol_check:
                        model = model_match.group(1)
                        eol_date = hw_eol_dates.get(model)
                        if eol_date and (within_next_months(eol_date, eol_alert_window_months) or eol_date.timestamp() < now):
                            eol_violations.add((device_id, 'hardware', model, eol_date))

                    # Log each device's data regardless of violations
                    if logging_enabled:
                        logging.info(f"Checked device {device_id}: {device_summaries.get(device_id, 'Unknown Device')}, "
                                     f"Wildfire Date: {timestamps.get(device_id, {}).get('wildfire-release-date', 'N/A')}, "
                                     f"AV Date: {timestamps.get(device_id, {}).get('av-release-date', 'N/A')}, "
                                     f"App Date: {timestamps.get(device_id, {}).get('app-release-date', 'N/A')}, "
                                     f"Threat Date: {timestamps.get(device_id, {}).get('threat-release-date', 'N/A')}, "
                                     f"Software Version: {sw_version_match.group(1) if sw_version_match else 'N/A'}, "
                                     f"Model: {model_match.group(1) if model_match else 'N/A'}")

            # Check if there are any violations
            if violations or eol_violations:
                summary = "Outdated Palo Alto Releases and EOL Devices Detected:\n"
                for device_id, timestamp_name in violations:
                    timestamp_value = timestamps[device_id][timestamp_name]
                    device_name = device_summaries.get(device_id, 'Unknown Device')
                    timestamp_difference = now - timestamp_value
                    timestamp_str = datetime.fromtimestamp(timestamp_value, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
                    summary += f"FireMon Device ID: {device_id}, Device Name: {device_name}, " \
                               f"Violation: {timestamp_name}\n" \
                               f"Timestamp: {timestamp_str}\n" \
                               f"Difference: {timedelta(seconds=timestamp_difference)}\n\n"
                for device_id, violation_type, value, eol_date in eol_violations:
                    device_name = device_summaries.get(device_id, 'Unknown Device')
                    eol_date_str = eol_date.strftime('%Y-%m-%d')
                    summary += f"FireMon Device ID: {device_id}, Device Name: {device_name}, " \
                               f"EOL Violation: {violation_type}\n" \
                               f"Value: {value}\n" \
                               f"EOL Date: {eol_date_str}\n\n"

                print(summary)  # Output the summary

                if logging_enabled:
                    logging.info(summary)

                # Save violations to CSV if enabled
                if save_violations_csv:
                    with open(violations_csv_path, 'w', newline='') as csvfile:
                        fieldnames = ['Device Name', 'Device ID', 'Violation Type', 'Details', 'EOL Date']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()

                        for device_id, timestamp_name in violations:
                            device_name = device_summaries.get(device_id, 'Unknown Device')
                            timestamp_value = timestamps[device_id][timestamp_name]
                            timestamp_str = datetime.fromtimestamp(timestamp_value, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
                            writer.writerow({
                                'Device Name': device_name,
                                'Device ID': device_id,
                                'Violation Type': timestamp_name,
                                'Details': timestamp_str,
                                'EOL Date': ''
                            })

                        for device_id, violation_type, value, eol_date in eol_violations:
                            device_name = device_summaries.get(device_id, 'Unknown Device')
                            eol_date_str = eol_date.strftime('%Y-%m-%d')
                            writer.writerow({
                                'Device Name': device_name,
                                'Device ID': device_id,
                                'Violation Type': violation_type,
                                'Details': value,
                                'EOL Date': eol_date_str
                            })

                    if logging_enabled:
                        logging.info(f"Violations saved to {violations_csv_path}")

                # Send email alert(s) if email_enabled is True and SMTP authentication is not required or provided
                if email_enabled and (not smtp_authentication_required or (smtp_authentication_required and smtp_username and smtp_password)):
                    subject = "[FireMon] Outdated Palo Alto Releases and EOL Devices Detected"
                    if send_aggregate_email:
                        try:
                            # Connect to the SMTP server
                            server = smtplib.SMTP(smtp_server, smtp_port)

                            # Optionally enable TLS encryption
                            if use_tls:
                                server.starttls()

                            # Log in to the email server if authentication is required
                            if smtp_authentication_required:
                                server.login(smtp_username, smtp_password)

                            # Create the email message
                            message = MIMEMultipart()
                            message['Subject'] = subject
                            message['From'] = sender_email
                            message['To'] = recipient_email

                            # Attach the text part
                            message.attach(MIMEText(summary, 'plain'))

                            # Attach the CSV file if enabled
                            if save_violations_csv and attach_csv_to_email:
                                with open(violations_csv_path, 'rb') as attachment:
                                    part = MIMEBase('application', 'octet-stream')
                                    part.set_payload(attachment.read())
                                    encoders.encode_base64(part)
                                    part.add_header('Content-Disposition', f'attachment; filename={violations_csv_path}')
                                    message.attach(part)

                            # Send the email
                            server.sendmail(sender_email, recipient_email, message.as_string())
                            print("Aggregate email alert sent with out of date Palo Alto releases and EOL devices")
                        except Exception as e:
                            print(f"Failed to send aggregate email alert: {e}")
                            if logging_enabled:
                                logging.error(f"Failed to send aggregate email alert: {e}")
                    else:
                        # Send individual email alerts for each violation
                        for device_id, timestamp_name in violations:
                            timestamp_value = timestamps[device_id][timestamp_name]
                            device_name = device_summaries.get(device_id, 'Unknown Device')
                            timestamp_difference = now - timestamp_value
                            timestamp_str = datetime.fromtimestamp(timestamp_value, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
                            individual_subject = f"[FireMon] Palo Alto {timestamp_name} outdated on {device_name}"
                            individual_body = f"FireMon Device ID: {device_id}\nDevice Name: {device_name}\nViolation: {timestamp_name}\nTimestamp: {timestamp_str}\nDifference: {timedelta(seconds=timestamp_difference)}"
                            try:
                                # Connect to the SMTP server
                                server = smtplib.SMTP(smtp_server, smtp_port)

                                # Optionally enable TLS encryption
                                if use_tls:
                                    server.starttls()

                                # Log in to the email server if authentication is required
                                if smtp_authentication_required:
                                    server.login(smtp_username, smtp_password)

                                # Create the email message
                                message = MIMEMultipart()
                                message['Subject'] = individual_subject
                                message['From'] = sender_email
                                message['To'] = recipient_email

                                # Attach the text part
                                message.attach(MIMEText(individual_body, 'plain'))

                                # Attach the CSV file if enabled
                                if save_violations_csv and attach_csv_to_email:
                                    with open(violations_csv_path, 'rb') as attachment:
                                        part = MIMEBase('application', 'octet-stream')
                                        part.set_payload(attachment.read())
                                        encoders.encode_base64(part)
                                        part.add_header('Content-Disposition', f'attachment; filename={violations_csv_path}')
                                        message.attach(part)

                                # Send the email
                                server.sendmail(sender_email, recipient_email, message.as_string())
                                print(f"Email alert sent for Device: {device_name} - {timestamp_name}")
                                if logging_enabled:
                                    logging.info(f"Email alert sent for Device: {device_name} - {timestamp_name}")
                            except Exception as e:
                                print(f"Failed to send email alert: {e}")
                                if logging_enabled:
                                    logging.error(f"Failed to send email alert: {e}")
                else:
                    if send_aggregate_email:
                        print(summary)  # Output the summary if email_enabled is False
                        if logging_enabled:
                            logging.info("No email sent. Summary output to console.")
                    else:
                        print("Outdated Releases:\n")
                        print(summary)  # Output the summary if email_enabled is False
                        if logging_enabled:
                            logging.info("No email sent. Individual summaries output to console.")
            else:
                if not email_enabled and send_aggregate_email:
                    print("No violations found.")
                elif not violations:
                    print("No violations found.")
                if logging_enabled:
                    logging.info("No violations found.")
        else:
            print(f"API request failed with status code: {response.status_code}")
            if logging_enabled:
                logging.error(f"API request failed with status code: {response.status_code}")
    else:
        print(f"Authentication request failed with status code: {auth_response.status_code}")
        if logging_enabled:
            logging.error(f"Authentication request failed with status code: {auth_response.status_code}")
except requests.exceptions.RequestException as e:
    print(f"An error occurred during the request: {e}")
    if logging_enabled:
        logging.error(f"An error occurred during the request: {e}")
except ValueError as e:
    print(f"Failed to parse JSON response: {e}")
    if logging_enabled:
        logging.error(f"Failed to parse JSON response: {e}")
