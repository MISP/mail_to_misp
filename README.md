# mail_to_misp

Connect your mail client to [MISP](https://github.com/MISP/MISP) in order to create events based on the information contained within mails.

## Features

- Extraction of URLs and IP addresses (and port numbers) from free text emails
- Extraction of hostnames from URLs
- Extraction of hashes (MD5, SHA1, SHA256)
- DNS expansion 
- Custom filter list for lines containing specific words
- Subject filters
- Respecting TLP classification mentioned in free text (including optional spelling robustness)
- Refanging of URLs ('hxxp://...')
- Add tags automatically based on key words (configurable)
- Add tags automatically depending on the presence of other tags (configurable)
- Ignore 'whitelisted' domains (configurable)
- Configurable list of attributes not to enable the IDS flag
- Automatically create 'external analysis' links based on filter list (e.g. VirusTotal, malwr.com)

## Implementation

For the moment, the implemented workflow is:

1. Apple Mail

`Email -> Apple Mail -> Mail rule -> AppleScript -> python script -> PyMISP -> MISP`

2. Mozilla Thunderbird

`Email -> Thunderbird -> Mail rule -> filterscript -> thunderbird_wrapper -> python script -> PyMISP -> MISP`

## Installation

### Apple Mail

1. Mail rule script
- git clone this repository
- open the AppleScript file MUA/Apple/Mail/MISP Mail Rule Action.txt in Apple's 'Script Editor'
- adjust the path to the python installation and location of the mail_to_misp.py script
- save it in ~/Library/Application Scripts/com.apple.mail/
2. Create a mail rule based on your needs, executing the AppleScript defined before
3. Configure mail_to_misp_config.py

### Thunderbird

1. Git clone https://github.com/rommelfs/filterscript and install plugin (instructions within the project description)
2. Mail rule script
- git clone this repository
- open the bash script MUA/Mozilla/Thunderbird/thunderbird_wrapper.sh and adujst the paths
- adjust the path to the python installation and location of the mail_to_misp.py script
3. Create a mail rule based on your needs, executing the thunderbird_wrapper.sh script
4. Configure mail_to_misp_config.py

You should be able to create MISP events now.

### Outlook

Outlook is not implemented due to lack of test environment. However, it should be feasible to do it this way:

```
import win32com.client
import pythoncom
 
class Handler_Class(object):
    def OnNewMailEx(self, receivedItemsIDs):
        for ID in receivedItemsIDs.split(","):
            # Microsoft.Office.Interop.Outlook _MailItem properties:
            # https://msdn.microsoft.com/en-us/library/microsoft.office.interop.outlook._mailitem_properties.aspx
            mailItem = outlook.Session.GetItemFromID(ID)
            print "Subj: " + mailItem.Subject
            print "Body: " + mailItem.Body.encode( 'ascii', 'ignore' )
            print "========"
         
outlook = win32com.client.DispatchWithEvents("Outlook.Application", Handler_Class)
pythoncom.PumpMessages()
```
(from: https://blog.matthewurch.ca/?p=236)

Obviously, you would like to filter mails based on subject or from address and pass subject and body to mail_to_misp.py in order to do something useful. Pull-requests welcome for actual implementations :) 


## Requirements

### General

- mail_to_misp requires access to a MISP instance (via API).
- urlmarker from https://github.com/rcompton/ryancompton.net/blob/master/assets/praw_drugs/urlmarker.py (contained in this project)
- defang from https://bitbucket.org/johannestaas/defang
- Optionally patch defang/defang/__init__.py and add dirty_line = dirty_line.replace('hXXp', 'http') at line 47

### Thunderbird

- https://github.com/rommelfs/filterscript (modified fork from https://github.com/adamnew123456/filterscript)
