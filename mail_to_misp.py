#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
try:
    configfile = os.path.basename(sys.argv[0]).split(".py")[0] + "_config"
except Exception as e:
    print("Couldn't locate config file {0}".format(configfile))
    sys.exit(-1)
try:
    import urlmarker
    import hashmarker
    import re
    from pyfaup.faup import Faup
    from pymisp import PyMISP, MISPEvent
    from defang import refang
    import dns.resolver
    import email
    from email.generator import Generator
    import tempfile
    import socket
    import syslog
    import ftfy
    import hashlib
    config = __import__(configfile)
except ImportError as e:
    print("(!) Problem loading module:")
    print(e)
    sys.exit(-1)

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

# Add a sighting
def sight(sighting, value):
    if sighting:
        d = {'value': value, 'source': sighting_source}
        misp.set_sightings(d)

# Add named attribute and sight if configured
def add_attribute(event, attribute_type, value, category, ids_flag, warninglist, sighting, comment=None):
    syslog.syslog("Event " + event['Event']['id'] + ": Adding attribute (" + attribute_type + ") " + value)
    misp.add_named_attribute(event, attribute_type, value, category, distribution=5, 
        comment=comment, to_ids=ids_flag, enforceWarninglist=warninglist)
    sight(sighting, value)

syslog.syslog("Job started.")
debug = config.debug
stdin_used = False

email_subject = config.email_subject_prefix
mail_subject = ""
#try:
    #if not sys.stdin.isatty():
if len(sys.argv) == 1:
    mailcontent = sys.stdin.buffer.read().decode("utf-8", "ignore")
else:
    # read from tempfile
    if sys.argv[1] == "-r":
        tempfilename = sys.argv[2]
        tf = open(tempfilename, 'r')
        mailcontent = tf.read()
        tf.close()
    # receive data and subject through arguments
    else:
        mailcontent = sys.argv[1]
        if debug:
            syslog.syslog(mailcontent)
        if len(sys.argv) >= 3:
            mail_subject = sys.argv[2].encode("utf-8", "ignore")
email_data = b''
msg = email.message_from_string(mailcontent)
if not mail_subject:
    try:
        mail_subject = msg.get('Subject').encode("utf-8", "ignore")
    except:
        pass
for part in msg.walk():
    if part.get_content_charset() is None:
        # This could probably be detected
        charset = 'utf-8' 
    else:
        charset = part.get_content_charset()
    if part.get_content_maintype() == 'multipart':
        continue
    if part.get_content_maintype() == 'text':
        part.set_charset(charset)
        if debug:
            syslog.syslog(str(part.get_payload(decode=True)))
        email_data += part.get_payload(decode=True)        
try:
    email_subject += mail_subject
except Exception as e:
    syslog.syslog(str(e))
stdin_used = True

#if debug:
#    syslog.syslog("Encoding of subject: {0}".format(ftfy.guess_bytes(email_subject)[1]))
#    syslog.syslog("Encoding of body: {0}".format(ftfy.guess_bytes(email_data)[1]))

try:
    email_data = ftfy.fix_text(email_data.decode("utf-8", "ignore"))
except:
    email_data = ftfy.fix_text(email_data)
try:
    email_subject = ftfy.fix_text(email_subject.decode("utf-8", "ignore"))
except:
    email_subject = ftfy.fix_text(email_subject)

if debug:    
    syslog.syslog(email_subject)
    syslog.syslog(email_data)

misp_url = config.misp_url
misp_key = config.misp_key
misp_verifycert = config.misp_verifycert

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = config.nameservers

excludelist = config.excludelist
externallist = config.externallist
internallist = config.internallist
noidsflaglist = config.noidsflaglist
ignorelist = config.ignorelist
enforcewarninglist = config.enforcewarninglist
sighting = config.sighting
sighting_source = config.sighting_source
removelist = config.removelist
malwaretags = config.malwaretags
dependingtags = config.dependingtags
tlptag_default = config.tlptag_default
stopword = config.stopword
hash_only_tags = config.hash_only_tags
forward_identifiers = config.forward_identifiers
attach_original_mail = config.attach_original_mail

original_email_data = email_data

# Ignore lines in body of message
for ignoreline in ignorelist:
    email_data = re.sub(ignoreline, "", email_data)

# Remove words from subject
for removeword in removelist:
    email_subject = re.sub(removeword, "", email_subject)
    
def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', debug=True)


# Evaluate classification
tlp_tag = tlptag_default
tlptags = config.tlptags
for tag in tlptags:
    for alternativetag in tlptags[tag]:
        if alternativetag in email_data.lower():
            tlp_tag = tag

# Create the MISP event
misp = init(misp_url, misp_key)
new_event = misp.new_event(info=email_subject, distribution=0, threat_level_id=3, analysis=1)
misp_event = MISPEvent()
misp_event.load(new_event)

misp.tag(misp_event.uuid, tlp_tag)

if attach_original_mail and original_email_data:
#    misp.add_named_attribute(new_event, 'email-body', original_email_data, category='Payload delivery', 
#                                to_ids=False, enforceWarninglist=enforcewarninglist)
    add_attribute(new_event, 'email-body', original_email_data, 'Payload delivery', False, enforcewarninglist)

# Add additional tags depending on others
for tag in dependingtags:
    if tag in tlp_tag:
        for dependingtag in dependingtags[tag]:
            misp.tag(misp_event.uuid, dependingtag)

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
email_data = refang(email_data)


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
    if malware in email_subject.lower():
        for tag in malwaretags[malware]:
            misp.tag(misp_event.uuid, tag)

# Extract and add hashes
hashlist_md5 = re.findall(hashmarker.MD5_REGEX, email_data)
hashlist_sha1 = re.findall(hashmarker.SHA1_REGEX, email_data)
hashlist_sha256 = re.findall(hashmarker.SHA256_REGEX, email_data)

for h in hashlist_md5:
    add_attribute(new_event, 'md5', h, 'Payload delivery', True, enforcewarninglist, sighting)
for h in hashlist_sha1:
    add_attribute(new_event, 'sha1', h, 'Payload delivery', True, enforcewarninglist, sighting)
for h in hashlist_sha256:
    add_attribute(new_event, 'sha256', h, 'Payload delivery', True, enforcewarninglist, sighting)

if (len(hashlist_md5) > 0) or (len(hashlist_sha1) > 0) or (len(hashlist_sha256) > 0):
    for tag in hash_only_tags:
        misp.tag(misp_event.uuid, tag)

# Add IOCs and expanded information to MISP
for entry in urllist:
    ids_flag = True
    f.decode(entry)
    domainname = f.get_domain().decode('utf-8', 'ignore')
    hostname = f.get_host().decode('utf-8', 'ignore')
    try:
        schema = f.get_scheme().decode('utf-8', 'ignore')
    except:
        schema = False
    try:
        resource_path = f.get_resource_path().decode('utf-8', 'ignore')
    except:
        resource_path = False
    if debug:
        syslog.syslog(domainname)
    if domainname not in excludelist:
        if domainname in internallist:
            add_attribute(new_event, 'link', entry, 'Internal reference', False, enforcewarninglist, sighting)
        elif domainname in externallist:
            add_attribute(new_event, 'link', entry, 'External analysis', False, enforcewarninglist, sighting)
        else:
            comment = ""
            if (domainname in noidsflaglist) or (hostname in noidsflaglist):
                ids_flag = False
                comment = "Known host (mostly for connectivity test or IP lookup)"
            if debug:
                syslog.syslog(str(entry))
            if hostname:
                if schema:
                    if is_valid_ipv4_address(hostname):
                        add_attribute(new_event, 'url', entry, 'Network activity', False, enforcewarninglist, sighting)
                    else:
                        if resource_path:
                            add_attribute(new_event, 'url', entry, 'Network activity', ids_flag, False,
                                sighting, comment=comment)
                        else:
                            add_attribute(new_event, 'url', entry, 'Network activity', ids_flag, enforcewarninglist, 
                                sighting, comment=comment)
                if debug:
                    syslog.syslog(hostname)
                try:
                    port = f.get_port().decode('utf-8', 'ignore')
                except:
                    port = None 
                if port:
                    comment = "on port: " + port
                if is_valid_ipv4_address(hostname):
                    add_attribute(new_event, 'ip-dst', hostname, 'Network activity', ids_flag, enforcewarninglist, 
                        sighting, comment=comment)
                else:
                    add_attribute(new_event, 'hostname', hostname, 'Network activity', ids_flag, enforcewarninglist, 
                        sighting, comment=comment)
                try:
                    for rdata in dns.resolver.query(hostname, 'A'):
                        if debug:
                            syslog.syslog(str(rdata))
                        add_attribute(new_event, 'ip-dst', rdata.to_text(), 'Network activity', False, enforcewarninglist, 
                            sighting, comment=hostname)
                except Exception as e:
                    if debug:
                        syslog.syslog(str(e))
 
# Try to add attachments
if stdin_used:
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get_content_maintype() != 'text' and part.get_payload(decode=True) is not None:
            filename = part.get_filename()
            _, output_path = tempfile.mkstemp()
            output = open(output_path, 'wb')
            output.write(part.get_payload(decode=True))
            output.close()
            attachment = part.get_payload(decode=True)
            if debug:
                syslog.syslog(str(attachment)[:200])
            event_id = misp_event.id
            misp.upload_sample(filename, output_path, event_id, distribution=5, to_ids=True)
            file_hash = hashlib.sha256(open(output_path, 'rb').read()).hexdigest()
            sight(sighting, file_hash)

syslog.syslog("Job finished.")
