#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import syslog
from pathlib import Path
from io import BytesIO
import importlib

from mail2misp import Mail2MISP

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Push a Mail into a MISP instance')
    parser.add_argument("-r", "--read", help="Read from tempfile.")
    parser.add_argument("-t", "--trap", action='store_true', default=False, help="Import the Email as-is.")
    parser.add_argument("-e", "--event", default=False, help="Add indicators to this MISP event.")
    parser.add_argument("-u", "--urlsonly", default=False, action='store_true', help="Extract only URLs.")
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
            ignore_carrier_mail = config.ignore_carrier_mail
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

    syslog.syslog("About to create a mail2misp object.")
    mail2misp = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config, urlsonly=args.event)
    attached_emails = mail2misp.get_attached_emails(pseudofile)
    syslog.syslog(f"found {len(attached_emails)} attached emails")
    if ignore_carrier_mail and len(attached_emails) !=0:
        syslog.syslog("Ignoring the carrier mail.")
        while len(attached_emails) !=0:
            pseudofile = attached_emails.pop()
            #Throw away the Mail2MISP object of the carrier mail and create a new one for each e-mail attachment
            mail2misp = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config, urlsonly=args.event)
            mail2misp.load_email(pseudofile)
            
            if debug:
                syslog.syslog(f'Working on {mail2misp.subject}')
        
            if args.trap or config.spamtrap:
                mail2misp.email_from_spamtrap()
            else:
                mail2misp.process_email_body()
        
            mail2misp.process_body_iocs()
        
            if not args.event:
                mail2misp.add_event()
            
        syslog.syslog("Job finished.")
    else:
        syslog.syslog("Running standard mail2misp")
        mail2misp = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config, urlsonly=args.event)
        mail2misp.load_email(pseudofile)

        if debug:
            syslog.syslog(f'Working on {mail2misp.subject}')

        if args.trap or config.spamtrap:
            mail2misp.email_from_spamtrap()
        else:
            mail2misp.process_email_body()
    
        mail2misp.process_body_iocs()
    
        if not args.event:
            mail2misp.add_event()
        syslog.syslog("Job finished.")

