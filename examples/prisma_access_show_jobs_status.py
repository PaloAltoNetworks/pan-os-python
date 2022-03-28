#!/usr/bin/env python

# Copyright (c) 2022, Palo Alto Networks
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
# ACTION OF CONTRACT, NEGLIGENCE OR OTpHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Bastien Migette <bmigette@paloaltonetworks.com>

"""
prisma_access_show_jobs_status.py
==========

This script is an example on how to retrieve list of prisma access 
jobs (commit and push), and how to get details of a specific job

"""
__author__ = "bmigette"


import logging
import os
import sys

# This is needed to import module from parent folder
curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]


from panos.base import PanDevice
from panos.panorama import Panorama
from panos.plugins import CloudServicesPlugin

curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]


HOSTNAME = os.environ["PAN_HOSTNAME"]
USERNAME = os.environ["PAN_USERNAME"]
PASSWORD = os.environ["PAN_PASSWORD"]


def main():
    # Setting logging to debug the PanOS SDK
    logging_format = "%(levelname)s:%(name)s:%(message)s"
    # logging.basicConfig(
    #    format=logging_format, level=logging.DEBUG - 2
    # )  # Use this to be even more verbose
    logging.basicConfig(format=logging_format, level=logging.DEBUG)
    # First, let's create the panorama  object that we want to modify.
    pan = Panorama(HOSTNAME, USERNAME, PASSWORD)
    csp = pan.add(CloudServicesPlugin())

    csp.opstate.jobs.refresh()

    # get only failed for mobile-users
    # csp.opstate.jobs.refresh(servicetype='mobile-users',  success=False, pending=False)
    # get only failed for mobile-users and remote networks
    # csp.opstate.jobs.refresh(servicetype=['mobile-users', 'remote-networks'],  success=False, pending=False)

    ### Print jobs ###

    print(csp.opstate.jobs.status)
    svcs = [
        "mobile-users",
        "remote-networks",
        "clean-pipe",
        "service-connection",
    ]
    for svc in svcs:
        print(f" -- {svc} Jobs --")
        print(csp.opstate.jobs.status[svc])

    ### Showing a job details ###
    failed_job_id = csp.opstate.jobs.status["mobile-users"]["failed"][-1]
    failed_details = csp.opstate.jobs_details.refresh(failed_job_id, "mobile-users")

    print(f"Details for job {failed_job_id}: {failed_details}")
    print(csp.opstate.jobs_details.details)


if __name__ == "__main__":
    main()
