#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import re
import syslog
from pathlib import Path
import html
from io import BytesIO
from ipaddress import ip_address
from email import message_from_bytes, policy
import importlib
try:
    import urlmarker
    import hashmarker
    from pyfaup.faup import Faup
    from pymisp import PyMISP, MISPEvent, MISPObject, MISPSighting
    from pymisp.tools import EMailObject, make_binary_objects
    from defang import refang
    import dns.resolver
except ImportError as e:
    print("(!) Problem loading module:")
    print(e)
    sys.exit(-1)


def is_ip(address):
    try:
        ip_address(address)
    except ValueError:
        return False
    return True


class Mail2MISP():

    def __init__(self, misp_url, misp_key, verifycert, config):
        self.misp = PyMISP(misp_url, misp_key, verifycert, debug=config.debug)
        self.config = config
        self.debug = self.config.debug
        self.config_from_email_body = {}
        # Init Faup
        self.f = Faup()

    def load_email(self, pseudofile):
        self.pseudofile = pseudofile
        self.original_mail = message_from_bytes(self.pseudofile.getvalue(), policy=policy.default)
        self.subject = self.original_mail.get('Subject')
        # Remove words from subject
        for removeword in self.config.removelist:
            self.subject = re.sub(removeword, "", self.subject).strip()

        # Initialize the MISP event
        self.misp_event = MISPEvent()
        self.misp_event.info = f'{config.email_subject_prefix} - {self.subject}'
        self.misp_event.distribution = self.config.default_distribution
        self.misp_event.threat_level_id = self.config.default_threat_level
        self.misp_event.analysis = self.config.default_analysis

    def sighting(self, value, source):
        '''Add a sighting'''
        s = MISPSighting()
        s.from_dict(value=value, source=source)
        self.misp.set_sightings(s)

    def _find_inline_forward(self):
        '''Does the body contains a forwarded email?'''
        for identifier in self.config.forward_identifiers:
            if identifier in self.clean_email_body:
                self.clean_email_body, fw_email = self.clean_email_body.split(identifier)
                return self.forwarded_email(pseudofile=BytesIO(fw_email.encode()))

    def _find_attached_forward(self):
        forwarded_emails = []
        for attachment in self.original_mail.iter_attachments():
            # Search for email forwarded as attachment
            # I could have more than one, attaching everything.
            if attachment.get_filename() and attachment.get_filename().endswith('.eml'):
                forwarded_emails.append(self.forwarded_email(pseudofile=BytesIO(attachment.get_content().as_bytes())))
            else:
                filename = attachment.get_filename()
                if not filename:
                    filename = 'missing_filename'
                if self.config_from_email_body.get('attachment') == self.config.m2m_benign_attachment_keyword:
                    # Attach sane file
                    self.misp_event.add_attribute('attachment', value=filename, data=BytesIO(attachment.get_content()))
                else:
                    f_object, main_object, sections = make_binary_objects(pseudofile=BytesIO(attachment.get_content()), filename=filename, standalone=False)
                    self.misp_event.add_object(f_object)
                    if main_object:
                        self.misp_event.add_object(main_object)
                        [self.misp_event.add_object(section) for section in sections]
        return forwarded_emails

    def email_from_spamtrap(self):
        '''The email comes from a spamtrap and should be attached as-is.'''
        raw_body = self.original_mail.get_body(preferencelist=('html', 'plain'))
        if raw_body:
            self.clean_email_body = html.unescape(raw_body.get_payload(decode=True).decode('utf8', 'surrogateescape'))
        else:
            self.clean_email_body = ''
        return self.forwarded_email(self.pseudofile)

    def forwarded_email(self, pseudofile: BytesIO):
        '''Extracts all possible indicators out of an email and create a MISP event out of it.
        * Gets all relevant Headers
        * Attach the body
        * Create MISP file objects (uses lief if possible)
        * Set all references
        '''
        email_object = EMailObject(pseudofile=pseudofile, attach_original_mail=True, standalone=False)
        if email_object.attachments:
            # Create file objects for the attachments
            for attachment_name, attachment in email_object.attachments:
                if not attachment_name:
                    attachment_name = 'NameMissing.txt'
                f_object, main_object, sections = make_binary_objects(pseudofile=attachment, filename=attachment_name, standalone=False)
                self.misp_event.add_object(f_object)
                if main_object:
                    self.misp_event.add_object(main_object)
                    for section in sections:
                        self.misp_event.add_object(section)
                email_object.add_reference(f_object.uuid, 'related-to', 'Email attachment')
        self.process_body_iocs(email_object)
        if self.config.spamtrap or self.config.attach_original_mail or self.config_from_email_body.get('attach_original_mail'):
            self.misp_event.add_object(email_object)
        return email_object

    def process_email_body(self):
        mail_as_bytes = self.original_mail.get_body(preferencelist=('html', 'plain')).get_payload(decode=True)
        if mail_as_bytes:
            self.clean_email_body = html.unescape(mail_as_bytes.decode('utf8', 'surrogateescape'))
            # Check if there are config lines in the body & convert them to a python dictionary:
            #   <config.body_config_prefix>:<key>:<value> => {<key>: <value>}
            self.config_from_email_body = {k.strip(): v.strip() for k, v in re.findall(f'{config.body_config_prefix}:(.*):(.*)', self.clean_email_body)}
            if self.config_from_email_body:
                # ... remove the config lines from the body
                self.clean_email_body = re.sub(rf'^{config.body_config_prefix}.*\n?', '',
                                               html.unescape(self.original_mail.get_body(preferencelist=('html', 'plain')).get_payload(decode=True).decode('utf8', 'surrogateescape')), flags=re.MULTILINE)

            # Check if autopublish key is present and valid
            if self.config_from_email_body.get('m2mkey') == self.config.m2m_key:
                if self.config_from_email_body.get('distribution'):
                    self.misp_event.distribution = self.config_from_email_body.get('distribution')
                if self.config_from_email_body.get('threat_level'):
                    self.misp_event.threat_level_id = self.config_from_email_body.get('threat_level')
                if self.config_from_email_body.get('analysis'):
                    self.misp_event.analysis = self.config_from_email_body.get('analysis')
                if self.config_from_email_body.get('publish'):
                    self.misp_event.publish()

            self._find_inline_forward()
        else:
            self.clean_email_body = ''
        self._find_attached_forward()

    def process_body_iocs(self, email_object=None):
        if email_object:
            body = html.unescape(email_object.email.get_body(preferencelist=('html', 'plain')).get_payload(decode=True).decode('utf8', 'surrogateescape'))
        else:
            body = self.clean_email_body

        # Cleanup body content
        # Depending on the source of the mail, there is some cleanup to do. Ignore lines in body of message
        for ignoreline in self.config.ignorelist:
            body = re.sub(rf'^{ignoreline}.*\n?', '', body, flags=re.MULTILINE)

        # Remove everything after the stopword from the body
        body = body.split(self.config.stopword, 1)[0]

        # Add tags to the event if keywords are found in the mail
        for tag in self.config.tlptags:
            if any(alternativetag in body.lower() for alternativetag in self.config.tlptags[tag]):
                self.misp_event.add_tag(tag)

        # Prepare extraction of IOCs
        # Refang email data
        body = refang(body)

        # Extract and add hashes
        contains_hash = False
        for h in set(re.findall(hashmarker.MD5_REGEX, body)):
            contains_hash = True
            attribute = self.misp_event.add_attribute('md5', h, enforceWarninglist=config.enforcewarninglist)
            if email_object:
                email_object.add_reference(attribute.uuid, 'contains')
            if self.config.sighting:
                self.sighting(h, self.config.sighting_source)
        for h in set(re.findall(hashmarker.SHA1_REGEX, body)):
            contains_hash = True
            attribute = self.misp_event.add_attribute('sha1', h, enforceWarninglist=config.enforcewarninglist)
            if email_object:
                email_object.add_reference(attribute.uuid, 'contains')
            if self.config.sighting:
                self.sighting(h, self.config.sighting_source)
        for h in set(re.findall(hashmarker.SHA256_REGEX, body)):
            contains_hash = True
            attribute = self.misp_event.add_attribute('sha256', h, enforceWarninglist=config.enforcewarninglist)
            if email_object:
                email_object.add_reference(attribute.uuid, 'contains')
            if self.config.sighting:
                self.sighting(h, self.config.sighting_source)

        if contains_hash:
            [self.misp_event.add_tag(tag) for tag in self.config.hash_only_tags]

        # # Extract network IOCs
        urllist = []
        urllist += re.findall(urlmarker.WEB_URL_REGEX, body)
        urllist += re.findall(urlmarker.IP_REGEX, body)
        if self.debug:
            syslog.syslog(str(urllist))

        hostname_processed = []

        # Add IOCs and expanded information to MISP
        for entry in set(urllist):
            ids_flag = True
            self.f.decode(entry)

            domainname = self.f.get_domain().decode()
            if domainname in self.config.excludelist:
                # Ignore the entry
                continue

            hostname = self.f.get_host().decode()

            scheme = self.f.get_scheme()
            if scheme:
                scheme = scheme.decode()

            resource_path = self.f.get_resource_path()
            if resource_path:
                resource_path = resource_path.decode()

            if debug:
                syslog.syslog(domainname)

            if domainname in self.config.internallist:  # Add link to internal reference
                attribute = self.misp_event.add_attribute('link', entry, category='Internal reference',
                                                          to_ids=False, enforceWarninglist=False)
                if email_object:
                    email_object.add_reference(attribute.uuid, 'contains')
            elif domainname in self.config.externallist:  # External analysis
                attribute = self.misp_event.add_attribute('link', entry, category='External analysis',
                                                          to_ids=False, enforceWarninglist=False)
                if email_object:
                    email_object.add_reference(attribute.uuid, 'contains')
            else:  # The URL is probably an indicator.
                comment = ""
                if (domainname in self.config.noidsflaglist) or (hostname in self.config.noidsflaglist):
                    ids_flag = False
                    comment = "Known host (mostly for connectivity test or IP lookup)"
                if debug:
                    syslog.syslog(str(entry))

                if scheme:
                    if is_ip(hostname):
                        attribute = self.misp_event.add_attribute('url', entry, to_ids=False,
                                                                  enforceWarninglist=config.enforcewarninglist)
                        if email_object:
                            email_object.add_reference(attribute.uuid, 'contains')
                    else:
                        if resource_path:  # URL has path, ignore warning list
                            attribute = self.misp_event.add_attribute('url', entry, to_ids=ids_flag,
                                                                      enforceWarninglist=False, comment=comment)
                            if email_object:
                                email_object.add_reference(attribute.uuid, 'contains')
                        else:  # URL has no path
                            attribute = self.misp_event.add_attribute('url', entry, to_ids=ids_flag,
                                                                      enforceWarninglist=config.enforcewarninglist, comment=comment)
                            if email_object:
                                email_object.add_reference(attribute.uuid, 'contains')
                    if self.config.sighting:
                        self.sighting(entry, self.config.sighting_source)

                if hostname in hostname_processed:
                    # Hostname already processed.
                    continue

                hostname_processed.append(hostname)
                if self.config.sighting:
                    self.sighting(hostname, self.config.sighting_source)

                if debug:
                    syslog.syslog(hostname)

                comment = ''
                port = self.f.get_port()
                if port:
                    port = port.decode()
                    comment = f'on port: {port}'

                if is_ip(hostname):
                    attribute = self.misp_event.add_attribute('ip-dst', hostname, to_ids=ids_flag,
                                                              enforceWarninglist=config.enforcewarninglist,
                                                              comment=comment)
                    if email_object:
                        email_object.add_reference(attribute.uuid, 'contains')
                else:
                    related_ips = []
                    try:
                        syslog.syslog(hostname)
                        for rdata in dns.resolver.query(hostname, 'A'):
                            if debug:
                                syslog.syslog(str(rdata))
                            related_ips.append(rdata.to_text())
                    except Exception as e:
                        if debug:
                            syslog.syslog(str(e))

                    if related_ips:
                        hip = MISPObject(name='ip-port')
                        hip.add_attribute('hostname', value=hostname, to_ids=ids_flag,
                                          enforceWarninglist=config.enforcewarninglist, comment=comment)
                        for ip in set(related_ips):
                            hip.add_attribute('ip', type='ip-dst', value=ip, to_ids=False,
                                              enforceWarninglist=config.enforcewarninglist)
                        self.misp_event.add_object(hip)
                        if email_object:
                            email_object.add_reference(hip.uuid, 'contains')
                    else:
                        attribute = self.misp_event.add_attribute('hostname', value=hostname,
                                                                  to_ids=ids_flag, enforceWarninglist=config.enforcewarninglist,
                                                                  comment=comment)
                        if email_object:
                            email_object.add_reference(attribute.uuid, 'contains')

    def add_event(self):
        '''Add event on the remote MISP instance.'''

        # Add additional tags depending on others
        tags = []
        for tag in [t.name for t in self.misp_event.tags]:
            if self.config.dependingtags.get(tag):
                tags += self.config.dependingtags.get(tag)

        # Add additional tags according to configuration
        for malware in self.config.malwaretags:
            if malware.lower() in self.subject.lower():
                tags += self.config.malwaretags.get(malware)
        if tags:
            [self.misp_event.add_tag(tag) for tag in tags]

        has_tlp_tag = False
        for tag in [t.name for t in self.misp_event.tags]:
            if tag.lower().startswith('tlp'):
                has_tlp_tag = True
        if not has_tlp_tag:
            self.misp_event.add_tag(config.tlptag_default)

        self.misp.add_event(self.misp_event)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Push a Mail into a MISP instance')
    parser.add_argument("-r", "--read", help="Read from tempfile.")
    parser.add_argument("-t", "--trap", action='store_true', default=False, help="Import the Email as-is.")
    parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'))
    args = parser.parse_args()

    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)
    syslog.syslog("Job started.")

    os.chdir(Path(__file__).parent)

    configmodule = Path(__file__).name.replace('.py', '_config')
    if Path(f'{configmodule}.py').exists():
        config = importlib.import_module(configmodule)
        try:
            misp_url = config.misp_url
            misp_key = config.misp_key
            misp_verifycert = config.misp_verifycert
            debug = config.debug
        except Exception as e:
            syslog.syslog(str(e))
            print("There is a problem with the configuration. A mandatory configuration variable is not set.")
            print("Did you just update? mail_to_misp might have new configuration variables.")
            print("Please compare with the configuration example.")
            print("\nTrace:")
            print(e)
            sys.exit(-2)
    else:
        print("Couldn't locate config file {0}".format(f'{configmodule}.py'))
        sys.exit(-1)

    if args.infile:
        pseudofile = BytesIO(args.infile.read().encode('utf8', 'surrogateescape'))
    elif args.read:
        # read from tempfile
        with open(args.read, 'rb') as f:
            pseudofile = BytesIO(f.read())
    else:
        # receive data and subject through arguments
        raise Exception('This is not implemented anymore.')

    mail2misp = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config)
    mail2misp.load_email(pseudofile)

    if debug:
        syslog.syslog(f'Working on {mail2misp.subject}')

    if args.trap or config.spamtrap:
        mail2misp.email_from_spamtrap()
    else:
        mail2misp.process_email_body()

    mail2misp.process_body_iocs()

    mail2misp.add_event()
    syslog.syslog("Job finished.")
