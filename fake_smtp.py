#!/usr/bin/python3
import os
import sys
import tempfile
try:
    configfile = os.path.basename(sys.argv[0]).split(".py")[0] + "_config"
except Exception as e:
    print("Couldn't locate config file {0}".format(configfile))
    sys.exit(-1)
try:
    import smtpd
    import asyncore
    import subprocess
    config = __import__(configfile)
except ImportError as e:
    print("(!) Problem loading module:")
    print(e)
    sys.exit(-1)

smtp_addr = config.smtp_addr
smtp_port = config.smtp_port
binpath   = config.binpath

print("Starting Fake-SMTP-to-MISP server")

class CustomSMTPServer(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data):
        print('Receiving message from: {0}'.format(peer))
        print('Message addressed from: {0}'.format(mailfrom))
        print('Message addressed to  : {0}'.format(rcpttos))
        print('Message length        : {0}'.format(len(data)))
        tf = tempfile.NamedTemporaryFile(mode='w', delete=False)
        tf.write(data)
        tf.close()
        subprocess.call([binpath, "-r", tf.name])
        os.unlink(tf.name)
        return

server = CustomSMTPServer((smtp_addr, smtp_port), None)

asyncore.loop()
