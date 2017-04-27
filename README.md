# mail_to_misp

Connect your mail client to [MISP](https://github.com/MISP/MISP) in order to create events based on the information contained within mails.

## Features

- Extraction of URLs and IP addresses (and port numbers) from free text emails
- Extraction of hostnames from URLs
- DNS expansion 
- Custom filter list for lines containing specific words
- Subject filters
- Respecting TLP classification mentioned in free text (including optional spelling robustness)
- Refanging of URLs ('hxxp://...')
- Add tags automatically based on key words (configurable)
- Add tags automatically depending on the presence of other tags (configurable)
- Ignore 'whitelisted' domains (configurable)
- Automatically create 'external analysis' links based on filter list (e.g. VirusTotal, malwr.com)

## Implementation

For the moment, the implemented workflow is:

1. `Email -> Apple Mail -> Mail rule -> AppleScript -> python script -> PyMISP -> MISP`

Thunderbird will be targeted soon.

## Installation

### Apple Mail

1. Mail rule script
- git clone this repository
- open the AppleScript file MUA/Apple/Mail/MISP Mail Rule Action.txt in Apple's 'Script Editor'
- adjust the path to the python installation and location of the mail_to_misp.py script
- save it in ~/Library/Application Scripts/com.apple.mail/
2. Create a mail rule based on your needs, executing the AppleScript defined before
3. Configure mail_to_misp_config.py

You should be able to create MISP events now.



## Requirements

- mail_to_misp requires access to a MISP instance (via API).
- urlmarker from https://github.com/rcompton/ryancompton.net/blob/master/assets/praw_drugs/urlmarker.py (contained in this project)
- defang from https://bitbucket.org/johannestaas/defang
- Optionally patch defang/defang/__init__.py and add dirty_line = dirty_line.replace('hXXp', 'http') at line 47


