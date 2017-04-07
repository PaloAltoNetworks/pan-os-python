..
 Copyright (c) 2017 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

============
panlicapi.py
============

--------------------------------------------------
command line interface to the PAN-OS Licensing API
--------------------------------------------------

NAME
====

 panlicapi.py - command line interface to the PAN-OS Licensing API

SYNOPSIS
========
::

 panlicapi.py [options]
    --activate            activate VM license
    --deactivate          deactivate VM license
    --get                 get quantity of VM provisioned
    --authcode code       license auth code
    --cpuid id            VM-Series vm-cpuid
    --uuid id             VM-Series vm-uuid
    --token token         deactivate license token
    --serial serial       get licenses for serial number
    -k                    write license key files
    -x                    write license install PAN-OS XML API documents
    --dst dir             destination directory for keys (default .)
    -t tag                .panrc tagname
    -K api_key            license API key
    -V api_version        license API version (default v1)
    -h hostname           license hostname
    -p                    print JSON response in Python to stdout
    -j                    print JSON to stdout
    -D                    enable debug (multiple up to -DDD)
    --ssl opt             SSL verify option: verify|noverify
    -T seconds            HTTP connect timeout
    --version             display version
    --help                display usage

DESCRIPTION
===========

 **panlicapi.py** is used to perform PAN-OS Licensing API requests.
 It uses the PanLicapi class from the **pan.licapi** module to
 execute API requests.

 The Licensing API can be used to license PAN-OS VM-Series firewalls
 which do not have Internet access.

 The options are:

 ``--activate``
  Activate a VM license or get previously activated licenses.
  The license keys can be saved using the **-k** and **-x** options.

  The action depends on the options passed:

  =====================  ===========
  Options                Action
  =====================  ===========
  authcode, uuid, cpuid  Activate new license and return licenses
  uuid, cpuid            Get previously activated licenses
  serial                 Get previously activated licenses
  =====================  ===========

 ``--deactivate``
  Dectivate a VM license using the license token file or string specified
  with **--token**.

 ``--get``
  Get the quantity of VM provisioned for the license auth code
  specified with **--authcode**.

 ``--authcode`` *code*
  License Auth Code.

 ``--cpuid`` *id*
  VM-Series vm-cpuid.

 ``--uuid`` *id*
  VM-Series vm-uuid.

 ``--token`` *token*
  PAN-OS license token, which can be specified as a string or
  a path to a token file.

  The token file is obtained using the PAN-OS operational command
  ``request license deactivate VM-Capacity mode manual``.

  The token file is exported from the device using ``scp export
  license-token-file`` or ``tftp export license-token-file``.

  Starting with PAN-OS 8.0 you can display the token file using ``show
  license-token-files name``.  This can be used to export the token
  file string using the PAN-OS XML API.

 ``--serial`` *serial*
  Device serial number.

 ``-k``
  Write license key files.  The key file name is the device uuid
  or serial number followed by the license ``partidField``.

 ``-x``
  Write license install PAN-OS XML API documents.  The documents
  contain the PAN-OS XML API ``type=op`` request ``cmd=`` XML argument
  to install the license file.

 ``--dst`` *dir*
  Destination directory for license key files and XML documents.
  The default is the current working directory.

 ``-t`` *tag*
  Specify tagname for .panrc.

 ``-K`` *api_key*
  Specify the **api_key** used in API requests.  This can also be
  specified in a .panrc file using the ``api_key`` *varname*.

 ``-V`` *api_version*
  API version as a string in the form v\ **version** or
  **version** (e.g., *v1*).  The API version is used to determine
  the PanLicapi class implementation to use.

  The default API version can be displayed with ``panlicapi.py -D``.

 ``-h`` *hostname*
  Specify the **hostname** used in API requests.  This can also be
  specified in a .panrc file using the ``hostname`` *varname*.

 ``-p``
  Print JSON response in Python to *stdout*.

 ``-j``
  Print JSON response to *stdout*.

 ``-D``
  Enable debugging.  May be specified multiple times up to 3
  to increase debugging output.

 ``--ssl`` *opt*
  Specify the type of SSL server certificate verification to be
  performed.

  ``verify``
   Perform SSL server certificate verification.  This is the default.

  ``noverify``
   Disable SSL server certificate verification.

 ``-T`` *seconds*
  The HTTP connect ``timeout`` in seconds.

 ``--version``
  Display version.

 ``--help``
  Display command options.

FILES
=====

 ``.panrc``
  .panrc file.

EXIT STATUS
===========

 **panlicapi.py** exits with 0 on success and 1 if an error occurs.

EXAMPLES
========

 Add License API key with tagname *license* to .panrc file.

 The API key is available on the `Palo Alto Networks Support Portal
 <https://support.paloaltonetworks.com>`_ at the *- Go To - -> Licensing API*
 drop-down.
 ::

  $ KEY=b05208f9e641374c90926715e1fdfafac457af13593c2abb5f4a1f904081af95
  $ echo "api_key%license=$KEY" >>.panrc

 Set environment variables for example usage.
 ::

  $ AUTHCODE=I9902646
  $ CPUID=ESX:51030200FFFBAB1F
  $ UUID=564D357F-8B7B-FAB9-1CAB-6C9745E43859

 Get license provisioned count.
 ::

  $ panlicapi.py -t license --get --authcode $AUTHCODE -j
  get: 200 OK 77 0.70secs
  {
      "AuthCode": "I9902646",
      "TotalVMCount": 5,
      "UsedCount": 0,
      "UsedDeviceDetails": []
  }

 Activate license and save license keys.
 ::

  $ panlicapi.py -t license --activate --authcode $AUTHCODE \
  > --cpuid $CPUID --uuid $UUID -k --dst tmp
  activate: 200 OK 4583 4.60secs
  564D357F-8B7B-FAB9-1CAB-6C9745E43859-PAN-VM-50-TP-3YR.key: Threat Prevention
  564D357F-8B7B-FAB9-1CAB-6C9745E43859-PAN-VM-50-GP-3YR.key: GlobalProtect Gateway License
  564D357F-8B7B-FAB9-1CAB-6C9745E43859-PAN-VM-50.key: Standard VM-50
  564D357F-8B7B-FAB9-1CAB-6C9745E43859-PAN-VM-50-URL4-3YR.key: Palo Alto Networks URL Filtering License
  564D357F-8B7B-FAB9-1CAB-6C9745E43859-PAN-VM-50-WF-3YR.key: WildFire signature feed, integrated WildFire logs, WildFire API

 Get new license provisioned count.
 ::

  $ panlicapi.py -t license --get --authcode $AUTHCODE -j
  get: 200 OK 188 0.36secs
  {
      "AuthCode": "I9902646",
      "TotalVMCount": 5,
      "UsedCount": 1,
      "UsedDeviceDetails": [
          {
              "CPUID": "ESX:51030200FFFBAB1F",
              "SerialNumber": "015351000001360",
              "UUID": "564D357F-8B7B-FAB9-1CAB-6C9745E43859"
          }
      ]
  }

 Get previously activated license by serial number and save
 license PAN-OS XML API documents.
 ::

  $ SERIAL=015351000001360

  $ panlicapi.py -t license --activate --serial $SERIAL -x --dst tmp
  activate: 200 OK 4583 3.48secs
  015351000001360-PAN-VM-50-TP-3YR.xml: Threat Prevention
  015351000001360-PAN-VM-50-GP-3YR.xml: GlobalProtect Gateway License
  015351000001360-PAN-VM-50.xml: Standard VM-50
  015351000001360-PAN-VM-50-URL4-3YR.xml: Palo Alto Networks URL Filtering License
  015351000001360-PAN-VM-50-WF-3YR.xml: WildFire signature feed, integrated WildFire logs, WildFire API

 Install VM capacity license key using the **panxapi.py** program.

 .. Note:: Installing a capacity license will cause a reboot on PAN-OS <= 7.1
	   and a restart of management services on PAN-OS >= 8.0.

 ::

  $ panxapi.py -t vm-50 -o tmp/$SERIAL-PAN-VM-50.xml
  op: success: "Successfully installed license key"

 Verify system serial number and show license info.
 ::

  $ (panxapi.py -t vm-50 -Xpro 'show system info'; \
  > echo "print(var1['system']['serial'])") | python
  op: success
  015351000001360

  $ panxapi.py -t vm-50 -Xjro 'request license info'
  op: success
  {
    "licenses": {
      "entry": [
        {
          "authcode": null,
          "description": "Standard VM-50",
          "expired": false,
          "expires": "Never",
          "feature": "PA-VM",
          "issued": "March 24, 2017",
          "serial": "015351000001360"
        }
      ]
    }
  }

 Install feature license keys using the **panxapi.py** program.
 ::

  $ for i in tmp/$SERIAL-PAN-VM-50-*.xml; do
  > echo `basename $i`
  > panxapi.py -t vm-50 -o $i
  > done
  015351000001360-PAN-VM-50-GP-3YR.xml
  op: success: "Successfully installed license key"
  015351000001360-PAN-VM-50-TP-3YR.xml
  op: success: "Successfully installed license key"
  015351000001360-PAN-VM-50-URL4-3YR.xml
  op: success: "Successfully installed license key"
  015351000001360-PAN-VM-50-WF-3YR.xml
  op: success: "Successfully installed license key"

 Deactivate license using CLI.
 ::

  admin@PA-VM> request license deactivate VM-Capacity mode manual

  Successfully deactivated VM. Please issue reboot
  dact_lic.03242017.090853.tok

 Export license token file using ``scp export``.
 ::

  admin@PA-VM> scp export license-token-file from dact_lic.03242017.090853.tok to stevesk@172.25.1.100:.
  stevesk@172.25.1.100's password:
  dact_lic.03242017.090853.tok                                                      100%  678     0.7KB/s   00:00


 Deactivate license using the **panxapi.py** program.
 ::

  $ panxapi.py -t vm-50 -Xjro 'request license deactivate VM-Capacity mode "manual"'
  op: success: "Successfully deactivated VM. Please issue reboot"
  {
    "msg": {
      "line": "Successfully deactivated VM. Please issue reboot"
    },
    "tokenfile": "dact_lic.03242017.090853.tok"
  }

 Export license token file using the **panxapi.py** program (PAN-OS 8.0).
 ::

  $ panxapi.py -t vm-50 -Xjro 'show license-token-files name "dact_lic.03242017.090853.tok"' \
  > >dact_lic.json
  op: success

 Extract license token from JSON object.

 .. Note:: The following uses the **jp.py** program from
	   `JMESPath <http://jmespath.org/>`_.

 ::

  $ jp.py -f dact_lic.json files.entry[0].entry |
  > sed -e 's/^"//' -e 's/"$//' >dact_lic.tok

 Perform deactivate license API request.
 ::

  $ panlicapi.py -t license --deactivate --token dact_lic.tok
  deactivate: 200 OK 1121 0.96secs

 Get license provisioned count.
 ::

  $ panlicapi.py -t license --get --authcode $AUTHCODE -j
  get: 200 OK 77 0.31secs
  {
      "AuthCode": "I9902646",
      "TotalVMCount": 5,
      "UsedCount": 0,
      "UsedDeviceDetails": []
  }

SEE ALSO
========

 pan.licapi, panxapi.py

 VM-Series Deployment Guide
  https://www.paloaltonetworks.com/documentation/80/virtualization/virtualization

 Licensing API
  https://www.paloaltonetworks.com/documentation/80/virtualization/virtualization/license-the-vm-series-firewall/licensing-api

AUTHORS
=======

 Palo Alto Networks, Inc. <techbizdev@paloaltonetworks.com>
