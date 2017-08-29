#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os

misp_url = 'YOUR_MISP_URL'
misp_key = 'YOUR_KEY_HERE' # The MISP auth key can be found on the MISP web interface under the automation section
misp_verifycert = True

debug = False
nameservers = ['149.13.33.69']
email_subject_prefix = b'M2M - '
attach_original_mail = True

# Paths (should be automatic)
bindir = os.path.dirname(os.path.realpath(__file__))
cfgdir = os.path.dirname(os.path.realpath(__file__))
scriptname = 'mail_to_misp.py'
binpath = os.path.join(bindir, scriptname)

# for the SPAM trap
smtp_addr = "127.0.0.1"
smtp_port = 25

excludelist = ('google.com', 'microsoft.com')
externallist = ('virustotal.com', 'malwr.com', 'hybrid-analysis.com', 'emergingthreats.net')
internallist = ('internal.system.local')
noidsflaglist = (   'myexternalip.com', 'ipinfo.io', 'icanhazip.com', 'wtfismyip.com', 'ipecho.net', 
                    'api.ipify.org', 'checkip.amazonaws.com', 'whatismyipaddress.com', 'google.com', 
                    'dropbox.com'
                )

# Stop parsing when this term is found
stopword = 'Whois & IP Information'

# Ignore lines in body of message containing:
ignorelist = (".*From: .*\n?", ".*Sender: .*\n?", ".*Received: .*\n?", ".*Sender IP: .*\n?",
                    ".*Reply-To: .*\n?", ".*Registrar WHOIS Server: .*\n?", ".*Registrar: .*\n?",
                    ".*Domain Status: .*\n?", ".*Registrant Email: .*\n?", ".*IP Location: .*\n?",
                    ".*X-Get-Message-Sender-Via: .*\n?", ".*X-Authenticated-Sender: .*\n")

# Remove "[tags]", "Re: ", "Fwd: " from subject
removelist = ("[\(\[].*?[\)\]]", "Re: ", "Fwd: ")

# TLP tag setup
# Tuples contain different variations of spelling
tlptags = { 'tlp:amber': [ 'tlp:amber', 'tlp: amber', 'tlp amber' ],
            'tlp:green': [ 'tlp:green', 'tlp: green', 'tlp green' ],
            'tlp:white': [ 'tlp:white', 'tlp: white', 'tlp white' ]
          }
tlptag_default = sorted(tlptags.keys())[0]

malwaretags = { 'locky':    [ 'ecsirt:malicious-code="ransomware"', 'misp-galaxy:ransomware="Locky"' ],
                'jaff':     [ 'ecsirt:malicious-code="ransomware"', 'misp-galaxy:ransomware="Jaff"' ],
                'dridex':   [ 'misp-galaxy:tool="dridex"' ],
                'netwire':  [ 'Netwire RAT' ],
                'Pony':     [ 'misp-galaxy:tool="Hancitor"' ],
                'ursnif':   [ 'misp-galaxy:tool="Snifula"' ],
                'NanoCore': [ 'misp-galaxy:tool="NanoCoreRAT"' ],
                'trickbot': [ 'misp-galaxy:tool="Trick Bot"' ]
              }

# Tags to be set depending on the presence of other tags
dependingtags = { 'tlp:white': [ 'circl:osint-feed' ]
                }

# Known identifiers for forwarded messages 
forward_identifiers = { '-------- Forwarded Message --------', 'Begin forwarded message:' }

# Tags to add when hashes are found (e.g. to do automatic expansion)
hash_only_tags = { 'TODO:VT-ENRICHMENT' }

