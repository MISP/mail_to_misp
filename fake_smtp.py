#!/usr/bin/env python
import sys
from pathlib import Path
import importlib
from subprocess import run, PIPE
import aiosmtpd.controller


class CustomSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        print(f'Receiving message from: {session.peer}')
        print(f'Message addressed from: {envelope.mail_from}')
        print(f'Message addressed to  : {envelope.rcpt_tos}')
        print(f'Message length        : {len(envelope.content)}')
        p = run([binpath, "-"], stdout=PIPE, input=envelope.content)
        print(p)
        return '250 OK'


if __name__ == '__main__':
    configmodule = Path(__file__).as_posix().replace('.py', '_config')
    if Path(f'{configmodule}.py').exists():
        config = importlib.import_module(configmodule)
    else:
        print("Couldn't locate config file {0}".format(f'{configmodule}.py'))
        sys.exit(-1)

    smtp_addr = config.smtp_addr
    smtp_port = config.smtp_port
    binpath = config.binpath

    print("Starting Fake-SMTP-to-MISP server")

    handler = CustomSMTPHandler()
    server = aiosmtpd.controller.Controller(handler, hostname=smtp_addr, port=smtp_port)
    server.start()
    input("Server started. Press Return to quit.")
    server.stop()
