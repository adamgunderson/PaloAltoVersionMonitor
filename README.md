# Palo Alto Version Monitor for FireMon

This tool monitors Palo Alto Networks devices managed by FireMon for End-of-Life (EOL) software and hardware, as well as outdated releases for Antivirus, WildFire, Threat, and Application content updates. It provides comprehensive version checking and alerting capabilities to ensure your network devices are up-to-date and supported.

## Features

- Checks for outdated Antivirus, WildFire, Threat, and Application content updates
- Identifies EOL hardware models and software versions
- Performs vulnerability checks against known CVEs
- Generates detailed reports and email alerts
- Supports CSV output for easy integration with other tools
- Configurable thresholds for update age and EOL notifications

## Components

### 1. versionMonitorPaloAlto.py

This is the main script that performs the version monitoring and alerting. It uses a regex control to check timestamps for various content updates and compares software and hardware versions against EOL data.

#### Setup

1. Import the FireMon control:
   Download and import the control file from [PaloAltoVersionsMonitor.export.json](https://github.com/adamgunderson/PaloAltoVersionMonitor/blob/main/PaloAltoVersionsMonitor.export.json) into your FireMon Security Manager.

2. Configure FireMon:
   Ensure that Device Retrievals in FireMon Security Manager are scheduled relative to the lowest alert threshold. The script uses a `RevisionMaxAge` variable as a fail-safe to prevent false positives when FireMon doesn't have a recent revision to check.

3. Prepare EOL data:
   Place the CSV files containing EOL data for hardware models and software versions in the same directory as the script. You can generate these files using the `scrape-eol-dates.py` script (see below).

4. Configure the script:
   Update the `config.yaml` file with your FireMon server details, email settings, and alert thresholds.

#### Usage

Run the script manually:

```bash
python3 versionMonitorPaloAlto.py
```

Or set up a cron job for automatic execution. For example, to run hourly:

```
0 * * * * /usr/bin/python3 /path/to/versionMonitorPaloAlto.py > /dev/null 2>&1
```

### 2. scrape-eol-dates.py (optional)
This script generates two CSV files: `palo_alto_eol_hw_dates.csv` and `palo_alto_eol_sw_dates.csv`, containing EOL dates for hardware models and software versions respectively. It scrapes this information from Palo Alto Networks' official documentation. As an alternative to running this script, you can use the pre-generated CSV files provided in this repository.

#### Setup

1. Create a Python virtual environment (recommended):

```bash
python3 -m venv palo-alto-monitor-env
source palo-alto-monitor-env/bin/activate
```

2. Install required libraries:

```bash
pip install requests beautifulsoup4 chardet
```

#### Usage

Run the script to generate the EOL CSV files:

```bash
python3 scrape-eol-dates.py
```

Consider setting up a monthly cron job to keep the EOL data up-to-date:

```
0 0 1 * * cd /path/to/script/directory && /path/to/palo-alto-monitor-env/bin/python /path/to/scrape-eol-dates.py > /dev/null 2>&1
```

## Configuration

The `config.yaml` file contains all the configurable parameters for the version monitor script. Key settings include:

- FireMon server details (URL, credentials)
- Email notification settings
- Alert thresholds for content updates
- EOL notification window
- Logging preferences

Refer to the comments in the `config.yaml` file for detailed explanations of each setting.

## Output

The script generates the following outputs:

1. Console output with a summary of findings
2. Detailed log file (configurable location)
3. CSV file with violation details (optional)
4. Email alerts (if configured)

## Troubleshooting

- Check the log file for detailed information about script execution and any errors encountered.
- Ensure that the FireMon API is accessible and that the provided credentials have the necessary permissions.
- Verify that the EOL CSV files are present and up-to-date.
- If email alerts are not being received, check your SMTP server configuration and any firewall rules that might be blocking outgoing email.

## Future Enhancements

- Add check for URL filtering version
- Implement automatic timezone handling
- Support additional alerting methods (e.g., syslog, webhooks)
- Enhance vulnerability checking with more detailed CVE information

## Contributing

Contributions to improve the script are welcome! Please submit pull requests or open issues on the GitHub repository.
