#!/usr/bin/python

import urlmarker
import sys
import re
from pyfaup.faup import Faup
from pymisp import PyMISP
from defang import refang
import dns.resolver
import mail_to_misp_config as config

debug = config.debug
if debug:
    debug_out_file = config.debug_out_file
    target = open(debug_out_file, 'w')
    target.write("New debug session opened")
try:
    email_data = str(sys.argv[1])
    email_subject = str(sys.argv[2])
except:
    if debug:
        target.write("FATAL ERROR: Not all required input received")
    sys.exit(1)

if debug:    
    target.write(email_subject)
    target.write(email_data)

misp_url = config.misp_url
misp_key = config.misp_key
misp_verifycert = config.misp_verifycert

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = config.nameservers

excludelist = config.excludelist
externallist = config.externallist

malwaretags = config.malwaretags
dependingtags = config.dependingtags

# Ignore lines in body of message
email_data = re.sub(".*From: .*\n?","", email_data)
email_data = re.sub(".*Sender: .*\n?","", email_data)
email_data = re.sub(".*Sender IP: .*\n?","", email_data)
email_data = re.sub(".*Reply-To: .*\n?","", email_data)
email_data = re.sub(".*Registrar WHOIS Server: .*\n?","", email_data)
email_data = re.sub(".*Registrar: .*\n?","", email_data)
email_data = re.sub(".*Domain Status: .*\n?","", email_data)
email_data = re.sub(".*Registrant Email: .*\n?","", email_data)
email_data = re.sub(".*IP Location: .*\n?","", email_data)

# Remove tags from subject
email_subject = re.sub("[\(\[].*?[\)\]]", "", email_subject)
# Remove "Re: " from subject
email_subject = re.sub("Re: ", "", email_subject)


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

# Evaluate classification
tlptags = config.tlptags
for tag in tlptags:
    for alternativetag in tlptags[tag]:
        if alternativetag in email_data.lower():
            tlp_tag = tag

# Create the MISP event
misp = init(misp_url, misp_key)
new_event = misp.new_event(info=email_subject, distribution=0, threat_level_id=3, analysis=1)
misp.add_tag(new_event, tlp_tag)

# Add additional tags depending on others
for tag in dependingtags:
    if tag in tlp_tag:
        for dependingtag in dependingtags[tag]:
            misp.add_tag(new_event, dependingtag)

# Extract IOCs
email_data = refang(email_data)
urllist = re.findall(urlmarker.WEB_URL_REGEX,email_data)
urllist += re.findall(urlmarker.IP_REGEX,email_data)
if debug:
    target.write(str(urllist))

# Init Faup
f = Faup()

# Add tags according to configuration
for malware in malwaretags:
    if malware in email_subject.lower():
        for tag in malwaretags[malware]:
            misp.add_tag(new_event, tag)

# Add IOCs and expanded information to MISP
for entry in urllist:
    f.decode(entry)
    domainname = f.get_domain().lower()
    if debug:
        target.write(domainname + "\n")
    if domainname not in excludelist:
        if domainname in externallist:
            misp.add_named_attribute(new_event, 'link', entry, category='External analysis', to_ids=False)
        else:
            if debug:
                target.write(entry + "\n")
            misp.add_url(new_event, entry, category='Network activity', to_ids=True)
            hostname = f.get_host().lower()
            if debug:
                target.write(hostname + "\n")
            port = f.get_port()
            comment = ""
            if port:
                comment = "on port: " + str(port)
            misp.add_hostname(new_event, hostname, comment=comment, category='Network activity', to_ids=True)
            try:
                for rdata in dns.resolver.query(hostname, 'A'):
                    if debug:
                        target.write(str(rdata) + "\n")
                    misp.add_ipdst(new_event, str(rdata), category='Network activity', to_ids=True, comment=hostname)
            except:
                if debug:
                    target.write("DNS unsuccessful\n")
if debug:
    target.close()
  
