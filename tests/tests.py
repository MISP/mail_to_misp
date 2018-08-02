#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import importlib
import sys
from io import BytesIO
sys.path.insert(0, ".")

from mail2misp import Mail2MISP


class TestMailToMISP(unittest.TestCase):

    def test_spamtrap(self):
        config = importlib.import_module('tests.config_spamtrap')
        self.mail2misp = Mail2MISP('', '', '', config=config, offline=True)
        with open('tests/mails/simple_spamtrap.eml', 'rb') as f:
            self.mail2misp.load_email(BytesIO(f.read()))
        self.mail2misp.email_from_spamtrap()
        self.mail2misp.process_body_iocs()
        event = self.mail2misp.add_event()
        print(event)

    def test_spamtrap_attachment(self):
        config = importlib.import_module('tests.config_spamtrap')
        self.mail2misp = Mail2MISP('', '', '', config=config, offline=True)
        with open('tests/mails/attachment_spamtrap.eml', 'rb') as f:
            self.mail2misp.load_email(BytesIO(f.read()))
        self.mail2misp.email_from_spamtrap()
        self.mail2misp.process_body_iocs()
        event = self.mail2misp.add_event()
        print(event)

    def test_forward(self):
        config = importlib.import_module('tests.config_forward')
        self.mail2misp = Mail2MISP('', '', '', config=config, offline=True)
        with open('tests/mails/simple_forward.eml', 'rb') as f:
            self.mail2misp.load_email(BytesIO(f.read()))
        self.mail2misp.process_email_body()
        self.mail2misp.process_body_iocs()
        event = self.mail2misp.add_event()
        print(event)

    def test_forward_attachment(self):
        config = importlib.import_module('tests.config_forward')
        self.mail2misp = Mail2MISP('', '', '', config=config, offline=True)
        with open('tests/mails/attachment_forward.eml', 'rb') as f:
            self.mail2misp.load_email(BytesIO(f.read()))
        self.mail2misp.process_email_body()
        self.mail2misp.process_body_iocs()
        event = self.mail2misp.add_event()
        print(event)

    def test_benign(self):
        config = importlib.import_module('tests.config_forward')
        self.mail2misp = Mail2MISP('', '', '', config=config, offline=True)
        with open('tests/mails/test_benign.eml', 'rb') as f:
            self.mail2misp.load_email(BytesIO(f.read()))
        self.mail2misp.process_email_body()
        self.mail2misp.process_body_iocs()
        self.assertTrue('attachment' in [a.type for a in self.mail2misp.misp_event.attributes])

if __name__ == '__main__':
    unittest.main()
