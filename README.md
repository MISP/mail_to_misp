# mail_to_misp

Connect your mail infrastructure to [MISP](https://github.com/MISP/MISP) in order to create events based on the information contained within mails.

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
- Add tags automatically depending on presence of hashes (e.g. for automatic expansion)
- Ignore 'whitelisted' domains (configurable)
- Specify a stop word term to no further process input
- Configurable list of attributes not to enable the IDS flag
- Automatically create 'external analysis' links based on filter list (e.g. VirusTotal, malwr.com)
- Automatically create 'internal reference' links based on filter list
- Detection of forwarded messages
- Process attachments as malware samples or specify that they are processed as benign files (`m2m_attachment_keyword`)

You can send mails with attachments to mail_to_misp and tell it, to treat the attachment as a benign document (in contrast to the default behaviour: treating it as a malware sample). You need to set a keyword in the configuration:
`m2m_attachment_keyword = 'attachment:benign'`
- Logging to syslog
- Remove "[tags]", "Re:" and "Fwd:" from subjects
- Optionally attach entire mail to event
- Contains now a fake-smtpd spamtrap which delivers IoCs/mails to MISP
- Automatically filter out attributes that are on a server side warning list (`enforcewarninglist=True`)
- Support for value sighting (`sighting=True`, `sighting_source="YOUR_MAIL_TO_MISP_IDENTIFIER"`)
- Auto-publish when `key:yourkey` is specified in mail (configurable, `m2m_key`, `m2m_auto_distribution`)
The `m2m_key configuration` is used to specify a secret only you and your users know. If you know the key, you can send a mail to your mail_to_misp instance, and when this key is present in the body of the message, it will automatically publish the event. So let's assume your config says: `m2m_key = 'ABCDEFGHIJKLMN0PQRSTUVWXYZ'`
If you send a mail to mail_to_misp containing: `key:ABCDEFGHIJKLMN0PQRSTUVWXYZ` the event is automatically published.
If you don't want to use this feature, just don't put it in the message body.
The distribution is defined in the configuration as well: `m2m_auto_distribution = '3' # 3 = All communities`


## Implementation

The implemented workflow is mainly for mail servers like Postfix. Client side implementations exist but are no longer supported:

1. Postfix and others

`Email -> mail_to_misp`

2. Apple Mail [deprecated]

`Email -> Apple Mail -> Mail rule -> AppleScript -> mail_to_misp -> PyMISP -> MISP`

3. Mozilla Thunderbird [deprecated]

`Email -> Thunderbird -> Mail rule -> filterscript -> thunderbird_wrapper -> mail_to_misp -> PyMISP -> MISP`
 

## Installation

### Postfix (or other MTA) - preferred method

1. Setup a new email address in the aliases file (e.g. /etc/aliases) and configure the correct path:

`misp_handler: "|/path/to/mail_to_misp.py"`

2. Rebuild the DB:

`$ sudo newaliases`

3. Configure mail_to_misp_config.py

You should now be able to send your IoC-containing mails to misp_handler@YOURDOMAIN.

#### Bonus: Fake-SMTPD spamtrap

If you want to process all incoming junk mails automatically and collect the contained information in a (separate?) MISP instance, you could use the fake_smtp.py script. It listens on port 25, accepts all mails and pushes them through mail_to_misp to a MISP instance.

1. Configure mail_to_misp_config.py

2. ln -s  mail_to_misp_config.py fake_smtp_config.py

3. Run fake_smtp.py (as root)

`$ sudo python3 fake_smtp.py`

### Apple Mail [deprecated]

1. Mail rule script
- git clone this repository
- open the AppleScript file MUA/Apple/Mail/MISP Mail Rule Action.txt in Apple's 'Script Editor'
- adjust the path to the python installation and location of the mail_to_misp.py script
- save it in ~/Library/Application Scripts/com.apple.mail/
2. Create a mail rule based on your needs, executing the AppleScript defined before
3. Configure mail_to_misp_config.py

### Thunderbird [deprecated]

1. Git clone https://github.com/rommelfs/filterscript and install plugin (instructions within the project description)
2. Mail rule script
- git clone this repository
- open the bash script MUA/Mozilla/Thunderbird/thunderbird_wrapper.sh and adujst the paths
- adjust the path to the python installation and location of the mail_to_misp.py script
3. Create a mail rule based on your needs, executing the thunderbird_wrapper.sh script
4. Configure mail_to_misp_config.py

You should be able to create MISP events now.

### Outlook [deprecated]

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
- Python 3
- dnspython
- hashlib
- faup from https://github.com/stricaud/faup
- urlmarker from https://github.com/rcompton/ryancompton.net/blob/master/assets/praw_drugs/urlmarker.py (contained in this project)
- ftfy from https://github.com/LuminosoInsight/python-ftfy (to fix unicode text)
- defang from https://bitbucket.org/johannestaas/defang
- Patch defang/defang/__init__.py by commenting out the following line (not used && not compatible with Python 3):
`from urllib2 import urlparse`
- Optionally patch defang/defang/__init__.py and add at line 47:
```
    dirty_line = dirty_line.replace('hxxp', 'http')
    dirty_line = dirty_line.replace('purr', 'http')
    dirty_line = dirty_line.replace('meow', 'http')
```

### Thunderbird [deprecated]

- https://github.com/rommelfs/filterscript (modified fork from https://github.com/adamnew123456/filterscript)

## License

This software is licensed under [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html)

* Copyright (C) 2017, 2018 Sascha Rommelfangen
* Copyright (C) 2017, 2018 CIRCL - Computer Incident Response Center Luxembourg
