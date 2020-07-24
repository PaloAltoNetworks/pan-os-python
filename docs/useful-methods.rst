.. _useful_methods:

Useful Methods
==============

These methods are the most commonly used and can be called on any object in a
configuration tree.

Configuration Methods
---------------------

Modify the configuration tree or the live device with these methods.

- **C:** Changes the pan-os-python configuration tree
- **L:** Connects to a live device (firewall or Panorama) via the API
- **M:** Modifies the live device by making a change to the device's configuration
- **B:** Bulk operation modifies more than one object in a single API call

+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
|                        Method                         |  C  |  L  |  M  |  B  |                  Description                  |
+=======================================================+=====+=====+=====+=====+===============================================+
| :py:meth:`~panos.base.PanObject.add`                  ||y|  |     |     |     | Add an object as a child of this object       |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.extend`               ||y|  |     |     |     | Add a list of objects as children             |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.insert`               ||y|  |     |     |     | Insert an object as a child at an index       |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.pop`                  ||y|  |     |     |     | Remove a child object at an index             |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.remove`               ||y|  |     |     |     | Remove a child object from this object        |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.remove_by_name`       ||y|  |     |     |     | Remove a child object by its name             |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.removeall`            ||y|  |     |     |     | Remove all children of this object            |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.refresh`              |     ||y|  |     |     | Set params of object from live device         |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.refreshall`           |     ||y|  |     |     | Pull all children from the live device        |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.refresh_variable`     |     ||y|  |     |     | Set a single param from the live device       |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.create`               |     ||y|  ||y|  |     | Push object to the live device (nd)           |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.apply`                |     ||y|  ||y|  |     | Push object to the live device (d)            |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.update`               |     ||y|  ||y|  |     | Push single object param to live device       |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.delete`               ||y|  ||y|  ||y|  |     | Delete from live device and config tree       |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.rename`               ||y|  ||y|  ||y|  |     | Rename on live device and config tree         |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.move`                 ||y|  ||y|  ||y|  |     | Reorder on live device and config tree        |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.create_similar`       |     ||y|  ||y|  ||y|  | Push objects of this type to live device (nd) |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.apply_similar`        |     ||y|  ||y|  ||y|  | Push objects of this type to live device (d)  |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+
| :py:meth:`~panos.base.PanObject.delete_similar`       |     ||y|  ||y|  ||y|  | Delete objects of this type from live device  |
+-------------------------------------------------------+-----+-----+-----+-----+-----------------------------------------------+

- (d):  Destructive     - Method *overwrites* an object on the live device with the same name
- (nd): Non-destructive - Method *combines* object with one on live device with the same name

Navigation Methods
------------------

These methods help you locate objects and information in an existing
configuration tree. These are commonly used when you have used ``refreshall`` to
pull a lot of nested objects and you're either looking for a specific object or
aggregate stats on the objects.

+----------------------------------------------------+----------------------------------------------------------------------+
|                       Method                       |                             Description                              |
+====================================================+======================================================================+
| :py:meth:`~panos.base.PanObject.find`              | Return object by name and type                                       |
+----------------------------------------------------+----------------------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.findall`           | Return all objects of a type                                         |
+----------------------------------------------------+----------------------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.find_index`        | Return the index of a child object                                   |
+----------------------------------------------------+----------------------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.find_or_create`    | Return object by name and type, creates object if not in config tree |
+----------------------------------------------------+----------------------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.findall_or_create` | Return all objects of type, creates an object if none exist          |
+----------------------------------------------------+----------------------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.nearest_pandevice` | Return the nearest parent Firewall or Panorama object in tree        |
+----------------------------------------------------+----------------------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.panorama`          | Return the nearest parent Panorama object                            |
+----------------------------------------------------+----------------------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.devicegroup`       | Return the nearest parent DeviceGroup object                         |
+----------------------------------------------------+----------------------------------------------------------------------+
| :py:attr:`~panos.base.PanObject.vsys`              | Return the vsys that contains this object                            |
+----------------------------------------------------+----------------------------------------------------------------------+

Informational Methods
---------------------

These methods provide information about an object in the configuration tree.

+----------------------------------------------+-----------------------------------------------------------+
|                    Method                    |                        Description                        |
+==============================================+===========================================================+
| :py:meth:`~panos.base.PanObject.about`       | Return all the params set on this object and their values |
+----------------------------------------------+-----------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.equal`       | Test if two objects are equal and return a boolean        |
+----------------------------------------------+-----------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.xpath`       | Return the XPath of this object                           |
+----------------------------------------------+-----------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.element`     | Return the XML of this object as an ElementTree           |
+----------------------------------------------+-----------------------------------------------------------+
| :py:meth:`~panos.base.PanObject.element_str` | Return the XML of this object as a string                 |
+----------------------------------------------+-----------------------------------------------------------+

Device Methods
--------------

These methods can be called on a PanDevice object (a Firewall or Panorama), but
not on any other PanObject.

+------------------------------------------------------+---------------------------------------------------------------+
|                        Method                        |                          Description                          |
+======================================================+===============================================================+
| :py:meth:`~panos.base.PanDevice.refresh_system_info` | Return and retain important information about the device      |
+------------------------------------------------------+---------------------------------------------------------------+
| :py:meth:`~panos.base.PanDevice.commit`              | Trigger a commit on a Firewall or Panorama                    |
+------------------------------------------------------+---------------------------------------------------------------+
| :py:meth:`~panos.panorama.Panorama.commit_all`       | Trigger a configuration push from Panorama to the Firewalls   |
+------------------------------------------------------+---------------------------------------------------------------+
| :py:meth:`~panos.base.PanDevice.syncjob`             | Wait for a job on the device to finish                        |
+------------------------------------------------------+---------------------------------------------------------------+
| :py:meth:`~panos.panorama.Panorama.refresh_devices`  | Pull all the devices attached to Panorama as Firewall objects |
+------------------------------------------------------+---------------------------------------------------------------+
| :py:meth:`~panos.base.PanDevice.op`                  | Execute an operational command                                |
+------------------------------------------------------+---------------------------------------------------------------+
| :py:meth:`~panos.base.PanDevice.watch_op`            | Same as 'op', then watch for a specific result                |
+------------------------------------------------------+---------------------------------------------------------------+

There are many other convenience methods available. They're all documented in the
:py:class:`~panos.base.PanDevice` class.

.. |y| replace:: ✅
