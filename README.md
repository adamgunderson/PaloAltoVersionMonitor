# Palo Alto Version Monitor for FireMon
Monitors for EOL software, hardware, as well as out of date releases for Antivirus, Wildfire and Threat.



# scrape-eol-dates.py
This script generates CSV's of hardware models, software versions, and their EOL dates for use with versionMonitor.py 

Additional Python libraries are needed to run this script. They can be installed using the 
following commands: 
```console
$ pip install requests
$ pip install beautifulsoup4
$ pip install chardet
```
Installing these additional libraries on FMOS requires the use of a python virtual
environment (venv). Follow the instructions below to create a a python virtual environment 
and set the script to run on the cron schedule.

Create the venv
```console
$ /usr/lib/firemon/devpackfw/bin/python -m venv eol-scrape
```
Activate venv.
```console
$ source ~/eol-scrape/bin/activate
```
Install pip.
```console
$ python3 ~/eol-scrape/bin/pip install -U pip
```
Now we can install the required libraries.
```console
$ python3 ~/eol-scrape/bin/pip install requests
$ python3 eol-scrape/bin/pip install BeautifulSoup4
$ python3 eol-scrape/bin/pip install chardet 
```
Test that the script now runs successfully.
```console
$ python3 scrape-hw-eol.py 
```
Create the cronjob for the script to run. The EOL pages likely don't update very often 
so it would be reasonable for the cron run infrequently. The following cron example will 
run the script once per month. 
Check your home directory path.
```console
$ pwd
```
> /home/firemon/ 
 
Set the cron expression
$ crontab -e 
> 0 0 1 * * cd /home/firemon $$ /home/firemon/eol-scrape/bin/python /home/firemon/scrape-eol-dates.py

 
CSV Generation as of July 10 2024: https://firemon.xyz/imports/palo_alto_eol_hw_dates.csv 
