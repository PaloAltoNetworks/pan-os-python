"""
NOTE: Please update the hostname and auth credentials variables
      before running.

"""

import os

from panos.firewall import Firewall
from panos.network import (
    RedistributionProfile,
    Rip,
    RipAuthProfile,
    RipAuthProfileMd5,
    RipExportRules,
    RipInterface,
    VirtualRouter,
)

HOSTNAME = os.environ["PAN_HOSTNAME"]
USERNAME = os.environ["PAN_USERNAME"]
PASSWORD = os.environ["PAN_PASSWORD"]

VR_NAME = "vr_1"
REDIST_NAME = "redist_1"
VR_INTERFACES = ["ethernet1/1"]
REDIST_INTERFACE = "ethernet1/1"


def main():
    fw = Firewall(HOSTNAME, USERNAME, PASSWORD)

    # find or create a virtual router
    vr = fw.find_or_create(VR_NAME, VirtualRouter, interface=VR_INTERFACES)

    # create redist profile
    redist_profile = RedistributionProfile(
        name=REDIST_NAME, priority=1, action="redist"
    )
    vr.add(redist_profile)

    rip_spec = {
        "enable": True,
        "reject_default_route": True,
        "allow_redist_default_route": True,
        "delete_intervals": 121,
        "expire_intervals": 181,
        "interval_seconds": 2,
        "update_intervals": 31,
    }
    rip = Rip(**rip_spec)

    # add rip auth (password)
    rip_auth = RipAuthProfile(
        name="rip_profile_1", type="password", password="#Password1"
    )
    rip.add(rip_auth)

    # add rip auth (md5)
    rip_auth = RipAuthProfile(name="rip_profile_2", type="md5")
    md5 = RipAuthProfileMd5(keyid=1, key="#Password1", preferred=True)
    rip_auth.add(md5)
    rip.add(rip_auth)

    # add rip export rules
    rip_export = RipExportRules(name=REDIST_NAME, metric=10)
    rip.add(rip_export)

    # add rip interfaces
    rip_interface_spec = {
        "name": REDIST_INTERFACE,
        "enable": True,
        "advertise_default_route": 11,
        "auth_profile": "rip_profile_1",
        "mode": "passive",
    }
    rip_interface = RipInterface(**rip_interface_spec)
    rip.add(rip_interface)

    # add rip config to virtual router and apply changes
    vr.add(rip)
    vr.apply()


if __name__ == "__main__":
    main()
