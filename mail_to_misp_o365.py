#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import importlib
import os
import sys
import syslog
from datetime import datetime, timedelta, timezone
from itertools import tee
from pathlib import Path

from mail2misp import Mail2MISP


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Push mail from O365 into a MISP instance')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-nd', '--days', help='Number of days to search back in inbox')
    group.add_argument('-nh', '--hours', help='Number of hours to search back in inbox')
    parser.add_argument('-f', '--folder', help='Folder name that contains email messages to parse')
    args = parser.parse_args()

    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)
    syslog.syslog("[+] O365 job started.")

    # import config module
    os.chdir(Path(__file__).parent)

    configmodule = Path(__file__).name.replace('o365.py', 'config')
    if Path(f"{configmodule}.py").exists():
        config = importlib.import_module(configmodule)
        try:
            misp_url = config.misp_url
            misp_key = config.misp_key
            misp_verifycert = config.misp_verifycert
            o365_client_id = config.o365_client_id
            o365_client_secret = config.o365_client_secret
            o365_tenant_id = config.o365_tenant_id
            o365_resource = config.o365_resource
            o365_scopes = config.o365_scopes
            debug = config.debug
        except Exception as ex:
            print("There is a problem with the configuration. A mandatory configuration variable is not set.")
            print("Did you just update? mail_to_misp might have new configuration variables.")
            print("Please compare with the configuration example.")
            print("\nTrace:")
            print(ex)
            sys.exit(-2)
    else:
        print(f"Couldn't locate config file {configmodule}.py")
        sys.exit(-1)

    # set message search period to look for emails
    to_time = datetime.now(timezone.utc)

    if args.days:
        from_time = (to_time - timedelta(days=int(args.days)))
    else:
        from_time = (to_time - timedelta(hours=int(args.hours)))

    # initialize Mail2MISP
    m2m = Mail2MISP(misp_url, misp_key, misp_verifycert, config=config)

    # initialize O365MISPClient
    o365 = m2m.O365MISPClient(
        client_id=o365_client_id,
        client_secret=o365_client_secret,
        tenant_id=o365_tenant_id,
        resource=o365_resource,
        scopes=o365_scopes,
        token_backend=None  # if not supplied will default to using FileSystemTokenBackend, which stores the token in a
                            # txt file on disk in the directory the script is executed from
    )

    messages = o365.get_email_messages(
        from_time=from_time,
        to_time=to_time,
        folder=args.folder if args.folder else None  # defaults to searching the resource's inbox folder if None
    )

    messages1, messages2 = tee(messages, 2)

    syslog.syslog(f"[*] Found {len(list(messages1))} messages to process and send to MISP!")

    for msg in messages2:
        m2m.load_o365_email(msg)
        if debug:
            syslog.syslog(f"[*] Processing email with subject: {m2m.subject}")
        m2m.process_o365_email_body()
        m2m.process_body_iocs()
        m2m.add_event()
    syslog.syslog("[-] O365 job finished.")
