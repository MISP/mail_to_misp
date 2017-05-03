#!/bin/bash
MESSAGE=`cat $1`
SUBJECT=`head -n 1 $1`
/opt/local/bin/python2.7 /Users/rommelfs/Scripts/mail_to_misp/mail_to_misp.py "$MESSAGE" "$SUBJECT"

