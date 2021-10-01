#!/usr/bin/env python3
import ssl
from pathlib import Path
import importlib
from subprocess import run, PIPE
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
import subprocess
import argparse


def get_context():
    key_path = Path('certs', 'key.pem')
    cert_path = Path('certs', 'cert.pem')

    if not cert_path.exists() and not key_path.exists():
        subprocess.call(f'openssl req -x509 -newkey rsa:4096 -keyout {key_path.as_posix()} -out {cert_path.as_posix()} -days 365 -nodes -subj "/CN=localhost"', shell=True)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_path.as_posix(), key_path.as_posix())


# Pass SSL context to aiosmtpd
class ControllerSSL(Controller):
    def factory(self):
        return SMTP(self.handler, ssl_context=get_context())


# Pass SSL context to aiosmtpd
class ControllerSTARTTLS(Controller):
    def factory(self):
        return SMTP(self.handler, require_starttls=False, tls_context=get_context())


class CustomSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        print(f'Receiving message from: {session.peer}')
        print(f'Message addressed from: {envelope.mail_from}')
        print(f'Message addressed to  : {envelope.rcpt_tos}')
        print(f'Message length        : {len(envelope.content)}')
        if email_forward in envelope.rcpt_tos:
            p = run([binpath_forward, "-"], stdout=PIPE, input=envelope.content)
        else:
            p = run([binpath, "-"], stdout=PIPE, input=envelope.content)
        print(p)
        return '250 OK'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Launch a fake SMTP server to push SPAMs to a MISP instance')
    parser.add_argument("--path", default='./mail_to_misp.py', help="Path to the mail_to_misp.py script.")
    parser.add_argument("--path_forward", default='./mail_to_misp.py', help="Path to the mail_to_misp.py script.")
    parser.add_argument("--email_forward", default='mail2misp@example.com', help="Path to the mail_to_misp.py script.")
    parser.add_argument("--host", default='127.0.0.1', help="IP to attach the SMTP server to.")
    parser.add_argument("--port", default='2525', help="Port of the SMTP server")
    parser.add_argument("--ssl", action='store_true', help="Pure SMTPs.")
    parser.add_argument("--ident", default='Python SMTPd', help="SMTPd ident string")
    args = parser.parse_args()

    configmodule = Path(__file__).as_posix().replace('.py', '_config')
    if Path(f'{configmodule}.py').exists():
        config = importlib.import_module(configmodule)
        binpath = config.binpath
        binpath_forward = config.binpath_forward
        email_forward = config.email_forward
        smtp_addr = config.smtp_addr
        smtp_port = config.smtp_port
        smtps = config.ssl
        ident = config.ident
    else:
        binpath = args.path
        binpath_forward = args.path_forward
        email_forward = args.email_forward
        smtp_addr = args.host
        smtp_port = args.port
        smtps = args.ssl
        ident = args.ident

    print("Starting Fake-SMTP-to-MISP server")

    handler = CustomSMTPHandler()
    if smtps:
        server = ControllerSSL(handler, hostname=smtp_addr, port=smtp_port, ident=ident)
    else:
        server = ControllerSTARTTLS(handler, hostname=smtp_addr, port=smtp_port, ident=ident)
    server.start()
    input("Server started. Press Return to quit.")
    server.stop()
