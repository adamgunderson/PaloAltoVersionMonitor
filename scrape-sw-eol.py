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
##                                                                             ##                   ##
##                                                                                                  ##
##                                                                                                  ##
##                   Scrape Palo Alto's Website for EOL Software Versions and Dates.                ##
##                         Version 1.0 (July 10th 2024)                                             ##
##                                                                                                  ##
##                         By Adam Gunderson                                                        ##
##                         Adam.Gunderson@FireMon.com                                               ##
##                                                                                                  ##
##    This script generates CSV of software versions and dates for use with versionMonitor.py       ##
##                                                                                                  ##
##    Additional Python libraries are needed to run this script. They can be installed using the    ##
##    following commands:                                                                           ##
##                                                                                                  ##
##    $ pip install requests                                                                        ##
##    $ pip install beautifulsoup4                                                                  ##
##                                                                                                  ##
##    CSV generation as of July 10th 2024: https://firemon.xyz/imports/palo_alto_eol_sw_dates.csv   ##
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

import requests
from bs4 import BeautifulSoup
import csv

# URL of the page to scrape
url = "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary"

# Send a request to the URL
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    # Parse the HTML content
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find all tables on the page
    tables = soup.find_all('table')
    
    # Initialize variables to store the data
    version_eol_data = []
    
    # Use the first table found on the page
    if tables:
        table = tables[0]  # Get the first table
        
        # Extract data from each row
        rows = table.find_all('tr')
        for row in rows:
            cols = row.find_all('td')
            if len(cols) == 3:  # Assuming three columns in the table
                version = cols[0].text.strip().replace('+', '').split(' ')[0]  # Remove '+' and extra info
                eol_date = cols[2].text.strip()
                version_eol_data.append([version, eol_date])
        
        # Save the data to a CSV file without an initial header line
        with open('palo_alto_eol_sw_dates.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(version_eol_data)
            
        print("Data has been successfully scraped and saved to 'palo_alto_eol_sw_dates.csv'")
    else:
        print("No tables found on the page")
else:
    print(f"Failed to retrieve the page. Status code: {response.status_code}")
