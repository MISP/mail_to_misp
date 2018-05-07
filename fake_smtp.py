#!/usr/bin/env python
import sys
import ssl
from pathlib import Path
import importlib
from subprocess import run, PIPE
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
import subprocess

key_path = Path('certs', 'key.pem')
cert_path = Path('certs', 'cert.pem')


# Pass SSL context to aiosmtpd
class ControllerStarttls(Controller):
    def factory(self):
        return SMTP(self.handler, require_starttls=False, tls_context=context)


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

    if not cert_path.exists() and not key_path.exists():
        subprocess.call(f'openssl req -x509 -newkey rsa:4096 -keyout {key_path.as_posix()} -out {cert_path.as_posix()} -days 365 -nodes -subj "/CN=localhost"', shell=True)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_path.as_posix(), key_path.as_posix())

    print("Starting Fake-SMTP-to-MISP server")

    handler = CustomSMTPHandler()
    server = ControllerStarttls(handler, hostname=smtp_addr, port=smtp_port)
    server.start()
    input("Server started. Press Return to quit.")
    server.stop()
