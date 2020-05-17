# Authors:
#     Rob Crittenden <rcrit@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import logging
import sys

from ipahealthcheck.core import constants
from ipahealthcheck.core.core import RunChecks

logging.basicConfig(format='%(message)s')
logger = logging.getLogger()


class PKIChecks(RunChecks):

    def add_options(self):
        parser = self.parser
        parser.add_argument('--input-file', dest='infile',
                            help='File to read as input')
        parser.add_argument('--failures-only', dest='failures_only',
                            action='store_true', default=False,
                            help='Exclude SUCCESS results on output')
        parser.add_argument('--severity', dest='severity', action="append",
                            help='Include only the selected severity(s)',
                            choices=[key for key in constants._nameToLevel])


def main():
    checks = PKIChecks(['pkihealthcheck.registry'],
                       '/etc/pki/healthcheck.conf')
    sys.exit(checks.run_healthcheck())
