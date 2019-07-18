#!/usr/bin/env python3
# -*- coding: utf-8 -*-

misp_url = 'YOUR_MISP_URL'
misp_key = 'YOUR_KEY_HERE'  # The MISP auth key can be found on the MISP web interface under the automation section
misp_verifycert = True
spamtrap = True
default_distribution = 0
default_threat_level = 3
default_analysis = 1

body_config_prefix = 'm2m'  # every line in the body starting with this value will be skipped from the IOCs
m2m_key = 'YOUSETYOURKEYHERE'
m2m_benign_attachment_keyword = 'benign'

debug = True
nameservers = ['8.8.8.8']
email_subject_prefix = 'M2M'
attach_original_mail = True

excludelist = ('google.com', 'microsoft.com')
externallist = ('virustotal.com', 'malwr.com', 'hybrid-analysis.com', 'emergingthreats.net')
internallist = ('internal.system.local')
noidsflaglist = ('myexternalip.com', 'ipinfo.io', 'icanhazip.com', 'wtfismyip.com', 'ipecho.net',
                 'api.ipify.org', 'checkip.amazonaws.com', 'whatismyipaddress.com', 'google.com',
                 'dropbox.com'
                 )

# Stop parsing when this term is found
stopword = 'Whois & IP Information'

# Ignore lines in body of message containing:
ignorelist = ("From:", "Sender:", "Received:", "Sender IP:", "Reply-To:", "Registrar WHOIS Server:",
              "Registrar:", "Domain Status:", "Registrant Email:", "IP Location:",
              "X-Get-Message-Sender-Via:", "X-Authenticated-Sender:")

# Ignore (don't add) attributes that are on server side warning list
enforcewarninglist = True

# Add a sighting for each value
sighting = False
sighting_source = "YOUR_MAIL_TO_MISP_IDENTIFIER"

# Remove "Re:", "Fwd:" and {Spam?} from subject
# add: "[\(\[].*?[\)\]]" to remove everything between [] and (): i.e. [tag]
removelist = (r'Re:', r'Fwd:', r'\{Spam\?\}')

# TLP tag setup
# Tuples contain different variations of spelling
tlptags = {'tlp:amber': ['tlp:amber', 'tlp: amber', 'tlp amber'],
           'tlp:green': ['tlp:green', 'tlp: green', 'tlp green'],
           'tlp:white': ['tlp:white', 'tlp: white', 'tlp white']
           }
tlptag_default = sorted(tlptags.keys())[0]

malwaretags = {'locky': ['ecsirt:malicious-code="ransomware"', 'misp-galaxy:ransomware="Locky"'],
               'jaff': ['ecsirt:malicious-code="ransomware"', 'misp-galaxy:ransomware="Jaff"'],
               'dridex': ['misp-galaxy:tool="dridex"'],
               'netwire': ['Netwire RAT'],
               'Pony': ['misp-galaxy:tool="Hancitor"'],
               'ursnif': ['misp-galaxy:tool="Snifula"'],
               'NanoCore': ['misp-galaxy:tool="NanoCoreRAT"'],
               'trickbot': ['misp-galaxy:tool="Trick Bot"']
               }

# Tags to be set depending on the presence of other tags
dependingtags = {'tlp:white': ['circl:osint-feed']
                 }

# Known identifiers for forwarded messages
forward_identifiers = {'-------- Forwarded Message --------', 'Begin forwarded message:'}

# Tags to add when hashes are found (e.g. to do automatic expansion)
hash_only_tags = {'TODO:VT-ENRICHMENT'}

# If an attribute is on any MISP server side `warning list`, skip the creation of the attribute
skip_item_on_warninglist = True

vt_key = None
