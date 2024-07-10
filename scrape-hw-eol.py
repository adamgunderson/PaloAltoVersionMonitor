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
##                   Scrape Palo Alto's Website for EOL Hardware Models and Dates.                  ##
##                         Version 1.0 (July 10th 2024)                                             ##
##                                                                                                  ##
##                         By Adam Gunderson                                                        ##
##                         Adam.Gunderson@FireMon.com                                               ##
##                                                                                                  ##
##    This script generates CSV of hardware models and dates for use with versionMonitor.py         ##
##                                                                                                  ##
##    Additional Python libraries are needed to run this script. They can be installed using the     ##
##    following commands:                                                                           ##
##                                                                                                  ##
##    $ pip install requests                                                                        ##
##    $ pip install beautifulsoup4                                                                  ##
##                                                                                                  ##
##    CSV Generation as of July 10 2024: https://firemon.xyz/imports/palo_alto_eol_hw_dates.csv     ##
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
url = "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/hardware-end-of-life-dates"

# Send a request to the URL
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    # Parse the HTML content
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find the table containing the EOL dates
    table = soup.find('table')

    if table:
        # Find all rows in the table
        rows = table.find_all('tr')

        # Determine the correct index for the "End-of-Life Date" column
        headers = rows[0].find_all('th')
        eol_index = None
        for i, header in enumerate(headers):
            if "End-of-Life Date" in header.text:
                eol_index = i
                break

        if eol_index is not None:
            # Open a CSV file to write the data
            with open('palo_alto_eol_hw_dates.csv', 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Model', 'End-of-Life Date'])

                # Loop through the rows and extract the model and EOL date
                for row in rows[1:]:  # Skip the header row
                    cols = row.find_all('td')
                    if len(cols) > eol_index:
                        model = cols[0].text.strip()
                        eol_date = cols[eol_index].text.strip()

                        # Clean the model text and split by new lines and commas
                        models = model.replace(')', '').replace('(', ',').replace('\n', ',').split(',')
                        for mod in models:
                            clean_model = mod.strip()
                            if clean_model:
                                writer.writerow([clean_model, eol_date])

            print("Data has been successfully scraped and saved to 'palo_alto_eol_hw_dates.csv'")
        else:
            print("End-of-Life Date column not found")
    else:
        print("Table not found on the page")
else:
    print(f"Failed to retrieve the page. Status code: {response.status_code}")

