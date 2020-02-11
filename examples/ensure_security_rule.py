#!/usr/bin/env python

# Copyright (c) 2017, Palo Alto Networks
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
ensure_security_rule.py
==========================

Ensure that specified security rule is on the firewall.

Note: Please update the hostname / auth credentials variables before running.

This script prints all the security rules connected to the firewall, then
checks to make sure that the desired rule is present.  If it is there, then
the script ends.  If not, it is created, and then a commit is performed.
"""

import sys

import pandevice
import pandevice.firewall
import pandevice.policies


HOSTNAME = "127.0.0.1"
USERNAME = "admin"
PASSWORD = "admin"


def main():
    # Before we begin, you'll need to use the pandevice documentation both
    # for this example and for any scripts you may write for yourself.  The
    # docs can be found here:
    #
    # http://pandevice.readthedocs.io/en/latest/reference.html
    #
    # Here's the security rule parameters we want for our new rule.  You can
    # check policies.SecurityRule to see all of the parameters you could
    # possibly give, but we'll just set a few for our example.
    desired_rule_params = {
        "name": "Block ssh",
        "description": "Prevent ssh usage",
        "fromzone": "any",
        "tozone": "any",
        "application": "ssh",
        "action": "deny",
        "log_end": True,
    }

    # First, let's create the firewall object that we want to modify.
    fw = pandevice.firewall.Firewall(HOSTNAME, USERNAME, PASSWORD)

    # You can determine the parent/child relationships by checking the
    # various "CHILDTYPES" of each object in the various modules.
    #
    # In our case, we see that the firewall.Firewall has a child of
    # policies.Rulebase, which in turn has a child type of
    # policies.SecurityPolicy.  This means that in order to get all the
    # current security policies, we need to recreate this hierarchy in our
    # object structure.
    #
    # Security policies are attached to policies.Rulebase, and there is only
    # ever one unnamed rulebase in PANOS.  So we have two options at this
    # point: 1) create our own Rulebase, attach it to the firewall object, and
    # use that to refresh only the security policies, or 2) get all the
    # Rulebase objects (and children) from the firewall and then work with
    # that.  Since we only care about the security policies, we'll go with the
    # former option (which will also make our script faster).
    #
    # Now, let's create our unnamed Rulebase object.
    rulebase = pandevice.policies.Rulebase()

    # Next, we attach it to our firewall object.
    fw.add(rulebase)

    # Then we can refresh just the security policies.  All "refreshall"
    # functions take the parent as a first parameter, and return a list of
    # what's on the firewall.  In our case, the parent is our rulebase
    # object, so we'll use that as the first parameter, and we'll save the
    # current security policies to a new variable: current_security_rules.
    current_security_rules = pandevice.policies.SecurityRule.refreshall(rulebase)

    # You'll notice that we never called any "login()" or similar function
    # before we refreshed.  This is because pandevice does the API key
    # retrieval for you when you attempt to do something that would require
    # access to the live device.  In our case, this was the above call
    # to "refreshall()".
    #
    # Since we're looking for the existance of a single policy, let's create
    # a boolean variable (or flag) to keep track of this for us.
    is_present = False

    # We're about to loop over all of the rules, but let's print a quick
    # one liner letting us know how many security rules we found.
    print("Current security rule(s) ({0} found):".format(len(current_security_rules)))

    # Now we're ready to check all the security policies that we got back from
    # the firewall.  We'll loop over each one, one by one, and print out the
    # name of the policy.
    for rule in current_security_rules:
        print("- {0}".format(rule.name))
        # Next, we need to check and see if this name matches the name of
        # the security policy we want to ensure the existance of.  If the names
        # match, then we'll set our flag to True.
        if rule.name == desired_rule_params["name"]:
            is_present = True

    # To format the output a bit better, we'll just print an empty line here
    # to help distinguish the end of printing all the rules from the logic
    # of the rest of this script.
    print()

    # At this point, we've looped over all the rules on the firewall.  So we
    # check our flag to see if it was set.  If it was set, then print out a
    # message saying that we found the rule, then exit out of this function.
    if is_present:
        print('Rule "{0}" already exists'.format(desired_rule_params["name"]))
        return

    # If the function got to this point, then the rule is not present, so we
    # print out a little message saying as much, then continue on!
    print('Rule "{0}" not present, adding it'.format(desired_rule_params["name"]))

    # At this point, we know the rule doesn't exist, so let's create it!  Doing
    # that is a three step process.
    #
    # First is to make all necessary new object(s).  In our example, we only
    # have one object to create, which is the rule itself.
    new_rule = pandevice.policies.SecurityRule(**desired_rule_params)

    # Second is to configure the object hierarchy using the .add() method.  As
    # we already know, security rules are children of the rulebase, which in
    # turn are children of the firewall.  Our object hierarchy is already setup
    # as "firewall > rulebase", so we need to add our new rule to the rulebase.
    rulebase.add(new_rule)

    # Last is to invoke the .create() function to create it.  Since it is the
    # new security rule we want to create and not the rulebase, we will
    # invoke create() on the new rule and not the rule base.  When we call
    # create(), both the object we are calling it on and all the children
    # connected will be created.  In our example, there are no children
    # attached to the security rule, so it's just the rule itself that gets
    # created.
    print("Creating rule...")
    new_rule.create()
    print("Done!")

    # Now we just have to commit.  I will ask commit() to wait for the commit
    # to finish completely before executing the next line of my script by
    # using "sync=True".
    print("Performing commit...")
    fw.commit(sync=True)

    # As a further exercise, you could try modifying this script:  we are
    # currently only checking that the names match, but what about the
    # contents of the rule?  Modify this script to verify that the contents
    # of the rule are also as expected.  If the rule is different from what
    # is desired, update the rule, and apply & commit it to the firewall.
    #
    # At this point, we've finished our script!
    print("Done!")


if __name__ == "__main__":
    # This script doesn't take command line arguments.  If any are passed in,
    # then print out the script's docstring and exit.
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        # No CLI args, so run the main function.
        main()
