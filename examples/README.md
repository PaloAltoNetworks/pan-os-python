Examples
========

These scripts are full examples that can be run on the CLI. For example:

```shell
$ python dyn_address_group.py "10.0.1.1" "admin" "password" "1.2.3.4" "quarantine"
```

See the top of each script for usage instructions.

**upgrade.py**

Upgrades a Palo Alto Networks firewall or Panorama to the specified version. It
takes care of all intermediate upgrades and reboots.

**userid.py**

Update User-ID by adding or removing a user-to-ip mapping on the firewall

**dyn_address_group.py**

Tag/untag ip addresses for Dynamic Address Groups on a firewall

**ensure_security_rule.py**

Ensure that specified security rule is on the firewall. Prints all the security
rules connected to the firewall, then checks to make sure that the desired rule
is present. If it is there, then the script ends. If not, it is created, and
then a commit is performed.

**log_forwarding_profile.py**

Ensure that all security rules have the same log forwarding profile assigned.

This script checks if any rules are missing the specified log forwarding profile
and applies the profile if it is missing. This is done with as few API calls as
possible.

**bulk_address_objects.py**

Use bulk operations to create / delete hundreds of firewall Address Objects.

**bulk_subinterfaces.py**

Use bulk operations to create / delete hundreds of firewall interfaces.