#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# putmail_enqueue.py    Read mail from standard input and save message and
#           program arguments to a mail queue.
#
# (c)   Ricardo García González
#   sarbalap-sourceforge _at_ yahoo _dot_ es
#
# This tiny script is distributed under the X Consortium License. See
# LICENSE file for more details.
#

import sys
import tempfile
import os
import os.path
import gettext
import pickle

### Initialize ###
try:
    gettext.install("putmail_enqueue.py")   # Always before using _()
except Exception:
    _ = lambda s: s

### Constants ###
PUTMAIL_DIR = ".putmail"
QUEUE_SUBDIR = "queue"
HOME_EV = "HOME"
ERROR_HOME_UNSET = _("Error: %s environment variable not set") % HOME_EV
ERROR_CREATE_TEMPFILE = _("Error: unable to create file in queue")
ERROR_MESSAGE_STDIN = _("Error: unable to read message from standard input")
ERROR_DATA_OUTPUT = _("Error: unable to write data to queue file")

### Main program ###
if not HOME_EV in os.environ:
    sys.exit(ERROR_HOME_UNSET)

queue_dir = os.path.join(os.getenv(HOME_EV), PUTMAIL_DIR, QUEUE_SUBDIR)

try:
    (msgfd, msgfname) = tempfile.mkstemp("", "", queue_dir)
except OSError:
    sys.exit(ERROR_CREATE_TEMPFILE)

try:
    with os.fdopen(msgfd, "wb") as msgfile:
        try:
            message = sys.stdin.read()
        except IOError:
            sys.exit(ERROR_MESSAGE_STDIN)
        try:
            pickle.dump((sys.argv, message), msgfile)
        except IOError:
            sys.exit(ERROR_DATA_OUTPUT)
except SystemExit:
    try:
        os.unlink(msgfname)
    except OSError:
        pass
    raise
