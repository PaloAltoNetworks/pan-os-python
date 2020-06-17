#!/usr/bin/env python

# Copyright (c) 2020, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
log_forwarding_profile.py
==========================

Ensure that all security rules have the same log forwarding profile assigned.

This script checks if any rules are missing the specified log forwarding profile
and applies the profile if it is missing. This is done with as few API calls as
possible.

Environment variables required:
  PAN_HOSTNAME: The hostname or IP of the Firewall
  PAN_USERNAME: The username of a firewall admin
  PAN_PASSWORD: The password of a firewall admin
  PAN_LOG_PROFILE: The name of the log forwarding profile to apply

"""

import os

from pandevice.firewall import Firewall
from pandevice.policies import Rulebase, SecurityRule

HOSTNAME = os.environ["PAN_HOSTNAME"]
USERNAME = os.environ["PAN_USERNAME"]
PASSWORD = os.environ["PAN_PASSWORD"]
LOG_PROFILE = os.environ["PAN_LOG_PROFILE"]


def main():
    # Create a connection to a firewall and a rulebase to work inside
    fw = Firewall(HOSTNAME, USERNAME, PASSWORD)
    rulebase = fw.add(Rulebase())

    # Fetch all the security rules from the firewall into a list
    rules = SecurityRule.refreshall(rulebase, add=False)

    print(f"Checking {len(rules)} rules...")

    # Iterate over the list and collect names of rules that are
    # missing the log forwarding profile
    for rule in rules:
        if rule.log_setting != LOG_PROFILE:
            print(f"Found rule to configure: {rule.name}")
            rulebase.add(SecurityRule(rule.name, log_setting=LOG_PROFILE))

    # At this point, we've added SecurityRule objects to the Firewall
    # for each rule that doesn't have the right log forwarding profile.
    # The next step is to push all that configuration to the live device
    # at once using the 'create_similar()' method.

    # This takes the first SecurityRule to change and calls 'create_similar()'.
    # When 'create_similar()' is called, all the SecurityRules are pushed
    # to the firewall at once. The method is additive, so the existing security
    # rules will not change, except for the 'log_setting' parameter which
    # contains the log forwarding profile name.
    if len(rulebase.children) == 0:
        print("No changes needed")
        return

    rulebase.children[0].create_similar()

    # Now, trigger a commit
    # In this case, we'll wait for the commit to finish and trigger an exception
    # if the commit finished with any errors.
    print("Starting commit")
    fw.commit(sync=True, exception=True)
    print("Commit finished successfully")


if __name__ == "__main__":
    main()
