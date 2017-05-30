#!/usr/bin/python3
# -*- coding: utf-8 -*-

import urlmarker
import hashmarker
import sys
import re
from pyfaup.faup import Faup
from pymisp import PyMISP
from defang import refang
import dns.resolver
import mail_to_misp_config as config
import email
from email.generator import Generator
import tempfile
import socket
import syslog

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

debug = config.debug
stdin_used = False

email_subject = config.email_subject_prefix
try:
    if not sys.stdin.isatty():
        email_data = b''
        mailcontent = "".join(sys.stdin)
        msg = email.message_from_string(mailcontent)
        mail_subject = msg.get('Subject').encode()
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get_content_maintype() == 'text':
                email_data += part.get_payload(decode=True)
        email_subject += mail_subject
        stdin_used = True
except Exception as e:
    print(e)
    pass

try:
    if not stdin_used:
        email_data = sys.argv[1].encode()
        email_subject = sys.argv[2].encode()
except:
    if debug:
        syslog.syslog("FATAL ERROR: Not all required input received")
    sys.exit(1)

if debug:    
    syslog.syslog(str(email_subject))
    syslog.syslog(str(email_data))

misp_url = config.misp_url
misp_key = config.misp_key
misp_verifycert = config.misp_verifycert

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = config.nameservers

excludelist = config.excludelist
externallist = config.externallist
internallist = config.internallist
noidsflaglist = config.noidsflaglist
malwaretags = config.malwaretags
dependingtags = config.dependingtags
tlptag_default = config.tlptag_default
stopword = config.stopword
hash_only_tags = config.hash_only_tags
forward_identifiers = config.forward_identifiers

# Ignore lines in body of message
email_data = re.sub(b".*From: .*\n?",b"", email_data)
email_data = re.sub(b".*Sender: .*\n?",b"", email_data)
email_data = re.sub(b".*Received: .*\n?",b"", email_data)
email_data = re.sub(b".*Sender IP: .*\n?",b"", email_data)
email_data = re.sub(b".*Reply-To: .*\n?",b"", email_data)
email_data = re.sub(b".*Registrar WHOIS Server: .*\n?",b"", email_data)
email_data = re.sub(b".*Registrar: .*\n?",b"", email_data)
email_data = re.sub(b".*Domain Status: .*\n?",b"", email_data)
email_data = re.sub(b".*Registrant Email: .*\n?",b"", email_data)
email_data = re.sub(b".*IP Location: .*\n?",b"", email_data)

# Remove "[tags]" from subject
email_subject = re.sub(b"[\(\[].*?[\)\]]", b"", email_subject)
# Remove "Re: " from subject
email_subject = re.sub(b"Re: ", b"", email_subject)
# Remove "Fwd: " from subject
email_subject = re.sub(b"Fwd: ", b"", email_subject)


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

# Evaluate classification
tlp_tag = tlptag_default
tlptags = config.tlptags
for tag in tlptags:
    for alternativetag in tlptags[tag]:
        if alternativetag.encode() in email_data.lower():
            tlp_tag = tag

# Create the MISP event
misp = init(misp_url, misp_key)
new_event = misp.new_event(info=email_subject.decode('utf-8', 'ignore'), distribution=0, threat_level_id=3, analysis=1)
misp.add_tag(new_event, tlp_tag)

# Add additional tags depending on others
for tag in dependingtags:
    if tag in tlp_tag:
        for dependingtag in dependingtags[tag]:
            misp.add_tag(new_event, dependingtag)

## Prepare extraction of IOCs

# Limit the input if the stopword is found
email_data = email_data.split(stopword, 1)[0]

# Find the first forwarding message and use that content
position = 99999
t_email_data = email_data
for identifier in forward_identifiers:
    new_position = email_data.find(identifier)
    if new_position == -1:
        new_position = position
    if new_position < position:
        t_before, t_split, t_email_data = email_data.partition(identifier)
        position = new_position
email_data = t_email_data

# Refang email data
email_data = refang(email_data.decode('utf-8', 'ignore'))


## Extract various IOCs

urllist = list() 
urllist += re.findall(urlmarker.WEB_URL_REGEX, email_data)
urllist += re.findall(urlmarker.IP_REGEX, email_data)
if debug:
    syslog.syslog(str(urllist))

# Init Faup
f = Faup()

# Add tags according to configuration
for malware in malwaretags:
    if malware.encode() in email_subject.lower():
        for tag in malwaretags[malware]:
            misp.add_tag(new_event, tag)

# Extract and add hashes
hashlist_md5 = re.findall(hashmarker.MD5_REGEX, email_data)
hashlist_sha1 = re.findall(hashmarker.SHA1_REGEX, email_data)
hashlist_sha256 = re.findall(hashmarker.SHA256_REGEX, email_data)

for h in hashlist_md5:
    misp.add_hashes(new_event, md5=h)
for h in hashlist_sha1:
    misp.add_hashes(new_event, sha1=h)
for h in hashlist_sha256:
    misp.add_hashes(new_event, sha256=h)

if (len(hashlist_md5) > 0) or (len(hashlist_sha1) > 0) or (len(hashlist_sha256) > 0):
    for tag in hash_only_tags:
        misp.add_tag(new_event, tag)

# Add IOCs and expanded information to MISP
for entry in urllist:
    ids_flag = True
    f.decode(entry)
    domainname = f.get_domain()
    hostname = f.get_host()
    if debug:
        syslog.syslog(domainname.decode("utf-8", "ignore"))
    if domainname not in excludelist:
        if domainname in internallist:
            misp.add_named_attribute(new_event, 'link', entry, category='Internal reference', to_ids=False, distribution=0)
        elif domainname in externallist:
            misp.add_named_attribute(new_event, 'link', entry, category='External analysis', to_ids=False)
        else:
            if (domainname in noidsflaglist) or (hostname in noidsflaglist):
                ids_flag = False
            if debug:
                syslog.syslog(str(entry))
            if hostname:
                if is_valid_ipv4_address(entry):
                    misp.add_url(new_event, entry, category='Network activity', to_ids=False)
                else:
                    misp.add_url(new_event, entry, category='Network activity', to_ids=ids_flag)
                if debug:
                    syslog.syslog(hostname.decode("utf-8", "ignore"))
                port = f.get_port()
                comment = ""
                if port:
                    comment = "on port: " + str(port)
                if is_valid_ipv4_address(hostname.decode('utf-8', 'ignore')):
                    misp.add_ipdst(new_event, hostname.decode('utf-8', 'ignore'), comment=comment, category='Network activity', to_ids=False)
                else:
                    misp.add_hostname(new_event, hostname.decode('utf-8', 'ignore'), comment=comment, category='Network activity', to_ids=ids_flag)
                try:
                    for rdata in dns.resolver.query(hostname.decode('utf-8', 'ignore'), 'A'):
                        if debug:
                            syslog.syslog(str(rdata))
                        misp.add_ipdst(new_event, rdata.to_text(), category='Network activity', to_ids=False, comment=hostname.decode('utf-8', 'ignore'))
                except Exception as e:
                    print (e)
                    if debug:
                        syslog.syslog("DNS unsuccessful")
 
# Try to add attachments
if stdin_used:
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get_content_maintype() != 'text':
            filename = part.get_filename()
            _, output_path = tempfile.mkstemp()
            output = open(output_path, 'wb')
            output.write(part.get_payload(decode=True))
            misp.upload_sample(filename, output_path, new_event, distribution=None, to_ids=True, category=None, comment=None, info='My Info', analysis=None, threat_level_id=None) 
            output.close()
