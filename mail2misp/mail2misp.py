#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import re
import syslog
import html
import os
from io import BytesIO
from ipaddress import ip_address
from email import message_from_bytes, policy, message
from email.parser import BytesParser

from . import urlmarker, hashmarker
from pyfaup.faup import Faup  # type: ignore
from pymisp import ExpandedPyMISP, MISPEvent, MISPObject, MISPSighting, InvalidMISPObject
from pymisp.tools import EMailObject, make_binary_objects, VTReportObject
from defang import refang  # type: ignore

from datetime import datetime
from O365 import Account
from O365.message import Message
from O365.utils import AWSS3Backend, AWSSecretsBackend, EnvTokenBackend, FileSystemTokenBackend, FirestoreBackend
from typing import Iterator, List, Optional, Union
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def is_ip(address):
    try:
        ip_address(address)
    except ValueError:
        return False
    return True


class Mail2MISP():

    def __init__(self, misp_url, misp_key, verifycert, config, offline=False, urlsonly=False):
        self.offline = offline
        if not self.offline:
            self.misp = ExpandedPyMISP(misp_url, misp_key, verifycert, debug=config.debug)
        self.config = config
        self.urlsonly = urlsonly
        if not hasattr(self.config, 'enable_dns'):
            setattr(self.config, 'enable_dns', True)
        if self.urlsonly is False:
            setattr(self.config, 'enable_dns', False)
        self.debug = self.config.debug
        self.config_from_email_body = {}
        if not hasattr(self.config, 'ignore_nullsize_attachments'):
            setattr(self.config, 'ignore_nullsize_attachments', False)
        self.ignore_nullsize_attachments = self.config.ignore_nullsize_attachments
        # Init Faup
        self.f = Faup()
        self.sightings_to_add = []

    def load_email(self, pseudofile):
        self.pseudofile = pseudofile
        self.original_mail = message_from_bytes(self.pseudofile.getvalue(), policy=policy.default)

        try:
            self.sender = self.original_mail.get('From')
        except Exception:
            self.sender = "<unknown sender>"

        try:
            self.subject = self.original_mail.get('Subject')
            # Remove words from subject
            for removeword in self.config.removelist:
                self.subject = re.sub(removeword, "", self.subject).strip()
        except Exception as ex:
            self.subject = "<subject could not be retrieved>"
            if self.debug:
                syslog.syslog(ex)

        # Initialize the MISP event
        self.misp_event = MISPEvent()
        self.misp_event.info = f'{self.config.email_subject_prefix} - {self.subject}'
        self.misp_event.distribution = self.config.default_distribution
        self.misp_event.threat_level_id = self.config.default_threat_level
        self.misp_event.analysis = self.config.default_analysis
        self.misp_event.add_tag(self.config.id_tag)

    def load_o365_email(self, msg: Message):
        self.msg = msg

        try:
            self.sender = self.msg.sender.address
        except Exception as ex:
            self.sender = "<unknown sender>"
            if self.debug:
                syslog.syslog(ex)

        try:
            self.reply_to = self.msg.reply_to[0].address
        except Exception as ex:
            self.reply_to = None
            if self.debug:
                syslog.syslog(ex)

        try:
            self.subject = self.msg.subject
            # remove words from subject
            for removeword in self.config.removelist:
                self.subject = re.sub(removeword, "", self.subject).strip()
        except Exception as ex:
            self.subject = "<subject could not be retrieved>"
            if self.debug:
                syslog.syslog(ex)

        # initialize the MISP event
        self.misp_event = MISPEvent()
        self.misp_event.info = self.subject
        self.misp_event.distribution = self.config.default_distribution
        self.misp_event.threat_level_id = self.config.default_threat_level
        self.misp_event.analysis = self.config.default_analysis
        self.misp_event.add_tag(self.config.id_tag)

    def sighting(self, value, source):
        if self.offline:
            raise Exception('The script is running in offline mode, ')
        '''Add a sighting'''
        s = MISPSighting()
        s.from_dict(value=value, source=source)
        self.misp.add_sighting(s)

    def _find_inline_forward(self):
        '''Does the body contains a forwarded email?'''
        for identifier in self.config.forward_identifiers:
            if identifier in self.clean_email_body:
                self.clean_email_body, fw_email = self.clean_email_body.split(identifier)
                return self.forwarded_email(pseudofile=BytesIO(fw_email.encode()))

    def _find_attached_forward(self):
        forwarded_emails = []
        for attachment in self.original_mail.iter_attachments():
            try:
                attachment_content = attachment.get_content()
            except KeyError:
                # Attachment type has no handler
                continue

            # Search for email forwarded as attachment
            # I could have more than one, attaching everything.
            if isinstance(attachment_content, message.EmailMessage):
                forwarded_emails.append(self.forwarded_email(pseudofile=BytesIO(attachment_content.as_bytes())))
            else:
                if isinstance(attachment_content, str):
                    attachment_content = attachment_content.encode()
                filename = attachment.get_filename()
                if not filename:
                    filename = 'missing_filename'
                if self.config_from_email_body.get('attachment') == self.config.m2m_benign_attachment_keyword:
                    # Attach sane file
                    self.misp_event.add_attribute('attachment', value=filename, data=BytesIO(attachment_content))
                else:
                    f_object, main_object, sections = make_binary_objects(pseudofile=BytesIO(attachment_content), filename=filename, standalone=False)
                    self.misp_event.add_object(f_object)
                    if main_object:
                        self.misp_event.add_object(main_object)
                        [self.misp_event.add_object(section) for section in sections]
        return forwarded_emails

    def _find_o365_attached_forward(self, msg: Message):
        forwarded_emails = []
        if msg.has_attachments:
            if msg.attachments.download_attachments():
                for attachment in msg.attachments:
                    if '.eml' in attachment.name:
                        decoded_attachment = base64.b64decode(attachment.content)
                        pseudofile = BytesIO(decoded_attachment)
                        eml = BytesParser(policy=policy.default).parse(pseudofile)
                        if isinstance(eml, message.EmailMessage):
                            forwarded_emails.append(self.forwarded_email(pseudofile=pseudofile))
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
                if not (self.ignore_nullsize_attachments and attachment.getbuffer().nbytes == 0):
                    if not attachment_name:
                        attachment_name = 'NameMissing.txt'
                    if self.config_from_email_body.get('attachment') == self.config.m2m_benign_attachment_keyword:
                        a = self.misp_event.add_attribute('attachment', value=attachment_name, data=attachment)
                        email_object.add_reference(a.uuid, 'related-to', 'Email attachment')
                    else:
                        f_object, main_object, sections = make_binary_objects(pseudofile=attachment, filename=attachment_name, standalone=False)
                        if self.config.vt_key:
                            try:
                                vt_object = VTReportObject(self.config.vt_key, f_object.get_attributes_by_relation('sha256')[0].value, standalone=False)
                                self.misp_event.add_object(vt_object)
                                f_object.add_reference(vt_object.uuid, 'analysed-with')
                            except InvalidMISPObject as e:
                                print(e)
                                pass
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
            self.config_from_email_body = {k.strip(): v.strip() for k, v in re.findall(f'{self.config.body_config_prefix}:(.*):(.*)', self.clean_email_body)}
            if self.config_from_email_body:
                # ... remove the config lines from the body
                self.clean_email_body = re.sub(rf'^{self.config.body_config_prefix}.*\n?', '',
                                               html.unescape(self.original_mail.get_body(preferencelist=('html', 'plain')).get_payload(decode=True).decode('utf8', 'surrogateescape')), flags=re.MULTILINE)
            # Check if autopublish key is present and valid
            if self.config_from_email_body.get('m2mkey') == self.config.m2m_key:
                if self.config_from_email_body.get('distribution') is not None:
                    self.misp_event.distribution = self.config_from_email_body.get('distribution')
                if self.config_from_email_body.get('threat_level') is not None:
                    self.misp_event.threat_level_id = self.config_from_email_body.get('threat_level')
                if self.config_from_email_body.get('analysis') is not None:
                    self.misp_event.analysis = self.config_from_email_body.get('analysis')
                if self.config_from_email_body.get('publish'):
                    self.misp_event.publish()

            self._find_inline_forward()
        else:
            self.clean_email_body = ''
        self._find_attached_forward()

    def process_o365_email_body(self):
        if self.msg:
            self.clean_email_body = html.unescape(self.msg.body)
            if re.search(r"<div>You don't often get email from .*?</div>", self.clean_email_body):
                self.clean_email_body = re.sub(r"<div>You don't often get email from .*?</div>", "", html.unescape(self.msg.body))
            # Check if there are config lines in the body & convert them to a python dictionary:
            #  <config.body_config_prefix>:<key>:<value> => {<key>: <value>}
            self.config_from_email_body = {k.strip(): v.strip() for k, v in re.findall(f'{self.config.body_config_prefix}:(.*):(.*)', self.clean_email_body)}
            if self.config_from_email_body:
                # ... remove the config lines from the body
                self.clean_email_body = re.sub(rf'^{self.config.body_config_prefix}.*\n?', '', html.unescape(self.msg.body), flags=re.MULTILINE)
            # Check if autopublish key is present and valid
            if self.config_from_email_body.get('m2mkey') == self.config.m2m_key:
                if self.config_from_email_body.get('distribution') is not None:
                    self.misp_event.distribution = self.config_from_email_body.get('distribution')
                if self.config_from_email_body.get('threat_level') is not None:
                    self.misp_event.threat_level_id = self.config_from_email_body.get('threat_level')
                if self.config_from_email_body.get('analysis') is not None:
                    self.misp_event.analysis = self.config_from_email_body.get('analysis')
                if self.config_from_email_body.get('publish'):
                    self.misp_event.publish()
        else:
            self.clean_email_body = ''
        self._find_o365_attached_forward(self.msg)

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
            for alternativetag in self.config.tlptags[tag]:
                if alternativetag in body.lower():
                    self.misp_event.add_tag(tag)

        # Prepare extraction of IOCs
        # Refang email data
        body = refang(body)

        # Extract and add hashes
        contains_hash = False
        for h in set(re.findall(hashmarker.MD5_REGEX, body)):
            contains_hash = True
            attribute = self.misp_event.add_attribute('md5', h, enforceWarninglist=self.config.enforcewarninglist)
            if email_object:
                email_object.add_reference(attribute.uuid, 'contains')
            if self.config.sighting:
                self.sightings_to_add.append((h, self.config.sighting_source))
        for h in set(re.findall(hashmarker.SHA1_REGEX, body)):
            contains_hash = True
            attribute = self.misp_event.add_attribute('sha1', h, enforceWarninglist=self.config.enforcewarninglist)
            if email_object:
                email_object.add_reference(attribute.uuid, 'contains')
            if self.config.sighting:
                self.sightings_to_add.append((h, self.config.sighting_source))
        for h in set(re.findall(hashmarker.SHA256_REGEX, body)):
            contains_hash = True
            attribute = self.misp_event.add_attribute('sha256', h, enforceWarninglist=self.config.enforcewarninglist)
            if email_object:
                email_object.add_reference(attribute.uuid, 'contains')
            if self.config.sighting:
                self.sightings_to_add.append((h, self.config.sighting_source))

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

            domainname = self.f.get_domain()
            if domainname in self.config.excludelist:
                # Ignore the entry
                continue

            hostname = self.f.get_host()

            scheme = self.f.get_scheme()
            if scheme:
                scheme = scheme

            resource_path = self.f.get_resource_path()
            if resource_path:
                resource_path = resource_path

            if self.debug:
                syslog.syslog(domainname)

            if domainname in self.config.internallist and self.urlsonly is False:  # Add link to internal reference unless in urlsonly mode
                attribute = self.misp_event.add_attribute('link', entry, category='Internal reference',
                                                          to_ids=False, enforceWarninglist=False)
                if email_object:
                    email_object.add_reference(attribute.uuid, 'contains')
            elif domainname in self.config.externallist and self.urlsonly is False:  # External analysis
                attribute = self.misp_event.add_attribute('link', entry, category='External analysis',
                                                          to_ids=False, enforceWarninglist=False)
                if email_object:
                    email_object.add_reference(attribute.uuid, 'contains')
            elif domainname in self.config.externallist or self.urlsonly:  # External analysis
                if self.urlsonly:
                    comment = self.subject + f" (from: {self.sender})"
                else:
                    comment = ""
                attribute = self.misp.add_attribute(self.urlsonly, {"type": 'link', "value": entry, "category": 'External analysis',
                                                    "to_ids": False, "comment": comment})
                for tag in self.config.tlptags:
                    for alternativetag in self.config.tlptags[tag]:
                        if alternativetag in self.subject.lower():
                            self.misp.tag(attribute["uuid"], tag)
                            new_subject = comment.replace(alternativetag, '')
                            self.misp.change_comment(attribute["uuid"], new_subject)

            else:  # The URL is probably an indicator.
                comment = ""
                if (domainname in self.config.noidsflaglist) or (hostname in self.config.noidsflaglist):
                    ids_flag = False
                    comment = "Known host (mostly for connectivity test or IP lookup)"
                if self.debug:
                    syslog.syslog(str(entry))

                if scheme:
                    if is_ip(hostname):
                        attribute = self.misp_event.add_attribute('url', entry, to_ids=False,
                                                                  enforceWarninglist=self.config.enforcewarninglist)
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
                                                                      enforceWarninglist=self.config.enforcewarninglist, comment=comment)
                            if email_object:
                                email_object.add_reference(attribute.uuid, 'contains')
                    if self.config.sighting:
                        self.sightings_to_add.append((entry, self.config.sighting_source))

                if hostname in hostname_processed:
                    # Hostname already processed.
                    continue

                hostname_processed.append(hostname)
                if self.config.sighting:
                    self.sightings_to_add.append((hostname, self.config.sighting_source))

                if self.debug:
                    syslog.syslog(hostname)

                comment = ''
                port = self.f.get_port()
                if port:
                    port = port
                    comment = f'on port: {port}'

                if is_ip(hostname):
                    attribute = self.misp_event.add_attribute('ip-dst', hostname, to_ids=ids_flag,
                                                              enforceWarninglist=self.config.enforcewarninglist,
                                                              comment=comment)
                    if email_object:
                        email_object.add_reference(attribute.uuid, 'contains')
                else:
                    related_ips = []
                    if HAS_DNS and self.config.enable_dns:
                        try:
                            syslog.syslog(hostname)
                            for rdata in dns.resolver.query(hostname, 'A'):
                                if self.debug:
                                    syslog.syslog(str(rdata))
                                related_ips.append(rdata.to_text())
                        except Exception as e:
                            if self.debug:
                                syslog.syslog(str(e))

                    if related_ips:
                        hip = MISPObject(name='ip-port')
                        hip.add_attribute('hostname', value=hostname, to_ids=ids_flag,
                                          enforceWarninglist=self.config.enforcewarninglist, comment=comment)
                        for ip in set(related_ips):
                            hip.add_attribute('ip', type='ip-dst', value=ip, to_ids=False,
                                              enforceWarninglist=self.config.enforcewarninglist)
                        self.misp_event.add_object(hip)
                        if email_object:
                            email_object.add_reference(hip.uuid, 'contains')
                    else:
                        if self.urlsonly is False:
                            attribute = self.misp_event.add_attribute('hostname', value=hostname,
                                                                      to_ids=ids_flag, enforceWarninglist=self.config.enforcewarninglist,
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
            self.misp_event.add_tag(self.config.tlptag_default)

        if self.offline:
            return self.misp_event.to_json()
        event = self.misp.add_event(self.misp_event, pythonify=True)
        if self.config.sighting:
            for value, source in self.sightings_to_add:
                self.sighting(value, source)
        if self.config.freetext:
            if self.config.o365_freetext:
                self.misp.freetext(event, string=self.clean_email_body, adhereToWarninglists=self.config.enforcewarninglist)
            else:
                self.misp.freetext(event, string=self.original_mail.get_body(preferencelist=('html', 'plain')), adhereToWarninglists=self.config.enforcewarninglist)
        return event

    def get_attached_emails(self, pseudofile):

        if self.debug:
            syslog.syslog("get_attached_emails Job started.")

        forwarded_emails = []
        self.pseudofile = pseudofile
        self.original_mail = message_from_bytes(self.pseudofile.getvalue(), policy=policy.default)
        for attachment in self.original_mail.iter_attachments():
            attachment_content = attachment.get_content()
            filename = attachment.get_filename()
            if self.debug:
                syslog.syslog(f'get_attached_emails: filename = {filename}')
            # Search for email forwarded as attachment
            # I could have more than one, attaching everything.
            if isinstance(attachment, message.EmailMessage) and os.path.splitext(filename)[1] == '.eml':
                # all attachments are identified as message.EmailMessage so filtering on extension for now.
                forwarded_emails.append(BytesIO(attachment_content))
        return forwarded_emails

    class O365MISPClient:
        """
        A client (MUA) to allow mail_to_misp to interact with Microsoft Graph and Office 365 API to get email messages.
        """
        def __init__(
                self,
                client_id: str,
                client_secret: str,
                tenant_id: str,
                resource: str,
                scopes: List[str],
                token_backend: Optional[
                    Union[AWSS3Backend, AWSSecretsBackend, EnvTokenBackend, FileSystemTokenBackend, FirestoreBackend]
                ] = None,
        ):
            """
            Init O365MISPClient
            :param client_id: OAuth Client ID
            :param client_secret: OAuth Client Secret
            :param tenant_id: Your Tenant ID
            :param resource: The email address you want to access
            :param scopes: The permission scopes for the resource
            :param token_backend: The backend used for storing OAuth token
            """
            self.scopes = scopes
            self.resource = resource
            self.o365_acct = Account(
                credentials=(client_id, client_secret),
                auth_flow_type='authorization',
                tenant_id=tenant_id,
                token_backend=token_backend
            )
            if not self.o365_acct.is_authenticated:
                self.o365_acct.authenticate(scopes=self.scopes)
            self.mailbox = self.o365_acct.mailbox(resource=self.resource)
            self.inbox = self.mailbox.inbox_folder()
            self.query_properties = [
                'internet_message_headers',
                'subject',
                'body',
                'unique_body',
                'from',
                'reply_to',
                'is_read',
                'is_draft',
                'received_date_time',
                'has_attachments',
                'attachments'
            ]

        def get_email_messages(self, from_time: datetime, to_time: datetime, folder: Optional[str] = None) -> Iterator[Message]:
            """
            Get messages for a certain timeframe. Defaults to looking for messages in the Inbox folder, however by
            supplying a folder name as a parameter you can change where to get the messages from.

            :param from_time: start time to search for
            :param to_time: end time to search for
            :param folder: specific folder to get messages from (don't supply if getting from the inbox folder)
            :return: an iterator of O365.messages.Message from the resource
            """
            query = self.mailbox.new_query().select(*self.query_properties)
            # https://learn.microsoft.com/en-us/graph/api/resources/message?view=graph-rest-1.0#properties
            query = query.chain('and').on_attribute('received_date_time').greater(from_time)
            query = query.chain('and').on_attribute('received_date_time').less(to_time)

            if folder:
                messages = self.mailbox.get_folder(folder_name=folder).get_messages(query=query)
            else:
                messages = self.inbox.get_messages(query=query)

            return messages

