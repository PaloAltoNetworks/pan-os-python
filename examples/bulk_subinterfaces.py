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
bulk_subinterfaces.py
=====================

Use bulk operations to create / delete hundreds of firewall interfaces.

NOTE: Please update the hostname and auth credentials variables
      before running.

The purpose of this script is to use and explain both the bulk operations
as it relates to subinterfaces as well as the new function that organizes
objects into vsys.  This script will show how the new bulk operations
correctly handle when subinterface objects are in separate vsys trees.

"""

import datetime
import random
import sys

from pandevice import device
from pandevice import firewall
from pandevice import network


HOSTNAME = "127.0.0.1"
USERNAME = "admin"
PASSWORD = "admin"
INTERFACE = "ethernet1/5"


def main():
    # Before we begin, you'll need to use the pandevice documentation both
    # for this example and for any scripts you may write for yourself.  The
    # docs can be found here:
    #
    # http://pandevice.readthedocs.io/en/latest/reference.html
    #
    # First, let's create the firewall object that we want to modify.
    fw = firewall.Firewall(HOSTNAME, USERNAME, PASSWORD)
    print("Firewall system info: {0}".format(fw.refresh_system_info()))

    print("Desired interface: {0}".format(INTERFACE))

    # Sanity Check #1: the intent here is that the interface we
    # specified above should not already be in use.  If the interface is
    # already in use, then just quit out.
    print("Making sure interface is not currently in use...")
    interfaces = network.EthernetInterface.refreshall(fw, add=False)
    for eth in interfaces:
        if eth.name == INTERFACE:
            print(
                "Interface {0} already in use! Please choose another".format(INTERFACE)
            )
            return

    # Sanity Check #2: this has to be a multi-vsys system.  So let's make
    # sure that we have multiple vsys to work with.  If there is only one
    # vsys, quit out.
    #
    # Pulling the entire vsys config from each vsys is going to be large amount
    # of XML, so we'll specify that we only need the names of the different
    # vsys, not their entire subtrees.
    vsys_list = device.Vsys.refreshall(fw, name_only=True)
    print("Found the following vsys: {0}".format(vsys_list))
    if len(vsys_list) < 2:
        print("Only {0} vsys present, need 2 or more.".format(len(vsys_list)))
        return

    # Let's make our base interface that we're going to make subinterfaces
    # out of.
    print("Creating base interface {0} in layer2 mode".format(INTERFACE))
    base = network.EthernetInterface(INTERFACE, "layer2")

    # Like normal, after creating the object, we need to add it to the
    # firewall, then finally invoke "create()" to create it.
    fw.add(base)
    base.create()

    # Now let's go ahead and make all of our subinterfaces.
    eth = None
    for tag in range(1, 601):
        name = "{0}.{1}".format(INTERFACE, tag)
        eth = network.Layer2Subinterface(name, tag)
        # Choose one of the vsys at random to put it into.
        vsys = random.choice(vsys_list)
        # Now add the subinterface to that randomly chosen vsys.
        vsys.add(eth)

    # You'll notice that we didn't invoke "create()" on the subinterfaces like
    # you would expect.  This is because we're going to use the bulk create
    # function to create all of the subinterfaces in one shot, which has huge
    # performance gains from doing "create()" on each subinterface one-by-one.
    #
    # The function we'll use is "create_similar()".  Create similar is saying,
    # "I want to create all objects similar to this one in my entire pandevice
    # object tree."  In this case, since we'd be invoking it on a subinterface
    # of INTERFACE (our variable above), we are asking pandevice to create all
    # subinterfaces of INTERFACE, no matter which vsys it exists in.
    #
    # We just need any subinterface to do this.  Since our last subinterface
    # was saved to the "eth" variable in the above loop, we can just use that
    # to invoke "create_similar()".
    print("Creating subinterfaces...")
    start = datetime.datetime.now()
    eth.create_similar()
    print("Creating subinterfaces took: {0}".format(datetime.datetime.now() - start))

    # Now let's explore updating them.  Let's say this is a completely
    # different script, and we want to update all of the subinterfaces
    # for INTERFACE.  Since this is a completely new script, we don't have any
    # information other than the firewall and the interface INTERFACE.  So
    # let's start from scratch at this point, and remake the firewall object
    # and connect.
    print("\n--------\n")
    fw = firewall.Firewall(HOSTNAME, USERNAME, PASSWORD)
    print("Firewall system info: {0}".format(fw.refresh_system_info()))

    print("Desired interface: {0}".format(INTERFACE))

    # Make the base interface object and connect it to our pandevice tree.
    base = network.EthernetInterface(INTERFACE, "layer2")
    fw.add(base)

    # Now let's get all the subinterfaces for INTERFACE.  Since our firewall's
    # default vsys is "None", this will get all subinterfaces of INTERFACE,
    # regardless of which vsys it exists in.
    print("Refreshing subinterfaces...")
    subinterfaces = network.Layer2Subinterface.refreshall(base)
    print("Found {0} subinterfaces".format(len(subinterfaces)))

    # Now let's go ahead and update all of them.
    for eth in subinterfaces:
        eth.comment = "Tagged {0} and in vsys {1}".format(eth.tag, eth.vsys)

    # Now that we have updated all of the subinterfaces, we need to save
    # the changes to the firewall.  But hold on a second, the vsys for these
    # subinterfaces is currently "None".  We first need to organize these
    # subinterfaces into the vsys they actually exist in before we can
    # apply these changes to the firewall.
    #
    # This is where you can use the function "organize_into_vsys()".  This
    # takes all objects currently attached to your pandevice object tree
    # and organizes them into the vsys they belong to.
    #
    # We haven't gotten the current vsys yet (this is a new script, remember),
    # but the function can take care of that for us.  So let's just invoke it
    # to organize our pandevice object tree into vsys.
    print("Organizing subinterfaces into vsys...")
    fw.organize_into_vsys()

    # Now we're ready to save our changes.  We'll use "apply_similar()",
    # and it behaves similarly to "create_similar()" in that you can invoke
    # it from any subinterface of INTERFACE and it will apply all of the
    # changes to subinterfaces of INTERFACE only.
    #
    # We just need one subinterface to invoke this function.  Again, we'll
    # simply use the subinterface currently saved in the "eth" variable
    # from our update loop we did just above.
    #
    # NOTE:  As an "apply()" function, apply does a replace of config, not
    # a simple update.  So you must be careful that all other objects are
    # currently attached to your pandevice object tree when using apply
    # functions.  In our case, we have already refreshed all layer2
    # subinterfaces, and we are the only ones working with INTERFACE, so we
    # are safe to use this function.
    print("Updating all subinterfaces...")
    start = datetime.datetime.now()
    eth.apply_similar()
    print("Updating subinterfaces took: {0}".format(datetime.datetime.now() - start))

    # Finally, all that's left is to delete all of the subinterfaces.  This
    # is just like you think:  we first need to refresh all of the
    # subinterfaces of INTERFACE, organize them into their appropriate vsys,
    # then invoke "delete_similar()" to delete everything.
    print("Deleting all subinterfaces...")
    start = datetime.datetime.now()
    eth.delete_similar()
    print("Deleting subinterfaces took: {0}".format(datetime.datetime.now() - start))

    # Lastly, let's just delete the base interface INTERFACE.
    print("Deleting base interface...")
    base.delete()

    # And now we're done!  If performance is a bottleneck in your automation,
    # or dealing with vsys is troublesome, consider using the vsys organizing
    # and/or bulk functions!
    print("Done!")


if __name__ == "__main__":
    # This script doesn't take command line arguments.  If any are passed in,
    # then print out the script's docstring and exit.
    if len(sys.argv) != 1:
        print(__doc__)
    else:
        # No CLI args, so run the main function.
        main()
