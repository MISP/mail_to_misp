#!/bin/bash
MESSAGE=`cat $1`
SUBJECT=`head -n 1 $1`
/Library/Frameworks/Python.framework/Versions/3.4/bin/python3 /Users/rommelfs/Scripts/mail_to_misp/mail_to_misp.py "$MESSAGE" "$SUBJECT"

