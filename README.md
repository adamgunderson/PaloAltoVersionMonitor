# Palo Alto Version Monitor for FireMon
Monitors for EOL software, hardware, as well as out of date releases for Antivirus, Wildfire and Threat.

## versionMonitorPaloAlto.py
This script uses a regex conrol that checks timestamps for av-release-date, wildfire-release-date, and threat-release-date from api_system_info. It also checks for EOL hardware and software versions. 

An import of the control can be downloaded here:
https://firemon.xyz/imports/PaloAltoVersionsMonitor.export.json 

Device Retrievals in FireMon Security Manager must be scheduled relative to the lowest alert threshold. The script variable for RevisionMaxAge as a fail-safe to prevent false positives in cases where FireMon does not have a recent revision to check.

EOL models and dates stored in CSV files that this script references. Use **scrape-eol-dates.py** to generate the CSV's.

This script can be ran on automatically on a schedule using cron. An example cron expression to run this script every hour is below. 
> 0 * * * * /usr/bin/python3.9 /home/admin/versionMonitorPaloAlto.py > /dev/null 2>&1 

TO DO:
- Add check for url-filtering-version.
- Handle timezones automatically (required additional Python modules in a virtual environment.
- Additional alerting methods (syslog, webhooks, etc).

## scrape-eol-dates.py
This script generates CSV's of hardware models, software versions, and their EOL dates for use with versionMonitor.py 

Additional Python libraries are needed to run this script. They can be installed using the following commands: 
```console
pip install requests
```
```console
pip install beautifulsoup4
```
```console
pip install chardet
```
### Running in FMOS ###
Installing these additional libraries on FMOS requires the use of a python virtual environment (venv). Follow the instructions below to create a a python virtual environment and set the script to run on the cron schedule.

Create the venv
```console
/usr/lib/firemon/devpackfw/bin/python -m venv eol-scrape
```
Activate venv.
```console
source eol-scrape/bin/activate
```
Install pip.
```console
python3 eol-scrape/bin/pip install -U pip
```
Now we can install the required libraries.
```console
python3 eol-scrape/bin/pip install requests
```
```console
python3 eol-scrape/bin/pip install BeautifulSoup4
```
```console
python3 eol-scrape/bin/pip install chardet 
```
Test that the script now runs successfully.
```console
python3 scrape-hw-eol.py 
```
Create the cronjob for the script to run. The EOL pages likely don't update very often so it would be reasonable for the cron run infrequently. The following cron example will run the script once per month. 
Check your home directory path.
```console
pwd
```
> /home/firemon/ 
 
Set the cron expression
```console
crontab -e
```
> 0 0 1 * * cd /home/firemon $$ /home/firemon/eol-scrape/bin/python /home/firemon/scrape-eol-dates.py

To exit the python virtual environemnt type:
```console
deactivate
```
