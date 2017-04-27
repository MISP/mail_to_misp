# mail_to_misp

Connect your mail client to [MISP](https://github.com/MISP/MISP) in order to create events based on the information contained within mails.

For the moment, the implemented workflow is:

1. `Email -> Apple Mail -> Mail rule -> AppleScript -> python script -> PyMISP -> MISP`

Thunderbird will be targeted soon.



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

## Requirements

mail_to_misp requires access to a MISP instance (via API).


