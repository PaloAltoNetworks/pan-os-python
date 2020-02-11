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
bulk_address_objects.py
==========================

Use bulk operations to create / delete hundreds of firewall Address Objects.

NOTE: Please update the hostname and auth credentials variables
      before running.

This script will create a large number of address objects on the firewall
and then delete them.  The intent is to show how to use the new bulk
operations available in pandevice, both how to properly use them and what
to be careful of.
"""

import datetime
import sys

import pandevice
import pandevice.firewall
import pandevice.objects


HOSTNAME = "127.0.0.1"
USERNAME = "admin"
PASSWORD = "admin"
PREFIX = "BulkAddressObject"


def num_as_ip(num, offset=0):
    """Returns a number as a 192.168 IP address."""
    return "192.168.{0}.{1}".format(num // 200 + 1 + offset, num % 200 + 2)


def main():
    # Before we begin, you'll need to use the pandevice documentation both
    # for this example and for any scripts you may write for yourself.  The
    # docs can be found here:
    #
    # http://pandevice.readthedocs.io/en/latest/reference.html
    #
    # First, let's create the firewall object that we want to modify.
    fw = pandevice.firewall.Firewall(HOSTNAME, USERNAME, PASSWORD)
    print("Firewall system info: {0}".format(fw.refresh_system_info()))

    # Get the list of current address objects, as we'll need this later.  We
    # don't want these address objects in our firewall tree yet, so let's set
    # the `add` flag in the refreshall method to False.
    original_objects = pandevice.objects.AddressObject.refreshall(fw, add=False)

    # As a sanity check, make sure no currently configured address objects
    # have the same name prefix as what this script uses.  If so, quit.
    for x in original_objects:
        if x.uid.startswith(PREFIX):
            print(
                "Error: prefix {0} shared with address object {1}".format(PREFIX, x.uid)
            )
            return

    # Just print out how many address objects were there beforehand.
    print("* There are {0} address object(s) currently *".format(len(original_objects)))

    # Create each address object and add it to the firewall.  You'll notice
    # that we don't call `create()` on each object as you'd expect.  This is
    # because we'll do a bulk create after we've finished creating everything.
    bulk_objects = []
    for num in range(1, 601):
        ao = pandevice.objects.AddressObject(
            "{0}{1:03}".format(PREFIX, num), num_as_ip(num)
        )
        bulk_objects.append(ao)
        fw.add(ao)

    # Now we can bulk create all the address objects.  This is accomplished by
    # invoking `create_similar()` on any of the address objects in our tree,
    # turning what would have been 600 individual API calls and condensing it
    # into a single API call.
    start = datetime.datetime.now()
    bulk_objects[0].create_similar()
    print(
        "Creating {0} address objects took: {1}".format(
            len(bulk_objects), datetime.datetime.now() - start
        )
    )

    # We've done a bulk create, now let's look at bulk apply.
    #
    # Some care is needed when using apply with pandevice.  All "apply" methods
    # are doing a PANOS API `type=edit` under the hood, which does a replace of
    # the current config with what is specified.
    #
    # So what does this mean?  This means that if we wanted to do a mass
    # update of the address objects we just created, we need to make sure that
    # our object tree contains the address objects that existed before this
    # script started.  So let's add in the pre-existing address objects to
    # the firewall's object tree.  We'll do this first so we don't forget
    # later on.
    for x in original_objects:
        fw.add(x)

    # With that out of the way, we're ready to update or bulk address objects
    # by incrementing the third octet of each IP address by 10.
    for num, x in enumerate(bulk_objects, 1):
        x.value = num_as_ip(num, 10)

    # Now we can do our bulk apply, invoking `apply_similar()`.  As before,
    # we invoke this on any of the related children in our pandevice
    # object tree.  Most important of all, since our firewall object has all
    # the pre-existing address objects in its tree, we won't accidentally
    # truncate them from the firewall config.
    start = datetime.datetime.now()
    bulk_objects[0].apply_similar()
    print(
        "Bulk apply {0} address objects took: {1}".format(
            len(bulk_objects) + len(original_objects), datetime.datetime.now() - start
        )
    )

    # We've done create, we've done edit, that leaves bulk delete.  We only
    # want to delete the bulk address objects we created in this script, so
    # let's remove all the pre-existing address objects from the firewall
    # object.
    for x in original_objects:
        fw.remove(x)

    # Finally, let's invoke `delete_similar()` from the firewall.  As should be
    # expected, we invoke this from any of the objects currently in our
    # pandevice object tree.
    start = datetime.datetime.now()
    bulk_objects[0].delete_similar()
    print(
        "Deleting {0} address objects took: {1}".format(
            len(bulk_objects), datetime.datetime.now() - start
        )
    )

    # At this point, we've now used all the bulk operations.  If performance
    # is a bottleneck for you, consider if any of your automation could be
    # refactored to use any of the bulk operations pandevice offers.
    print("Done!")


if __name__ == "__main__":
    # This script doesn't take command line arguments.  If any are passed in,
    # then print out the script's docstring and exit.
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        # No CLI args, so run the main function.
        main()
