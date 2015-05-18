__author__ = 'btorres-gil'

import device
import errors as err


# PanObject type
class PanObject(object):

    def __init__(self, name=None):
        self.name = name
        self.parent = None
        self.children = []

    def add(self, child):
        child.parent = self
        self.children.append(child)
        return child

    def remove(self, index):
        child = self.children[index]
        child.parent = None
        self.children.remove(index)
        return child

    def remove_by_name(self, name, cls=None):
        index = PanObject.find(self.children, name, cls)
        if index is None:
            return None
        child = self.children[index]
        child.parent = None
        self.children.remove(index)
        return child  # Just remove the first child that matches the name

    def xpath(self):
        return "/"

    def element(self):
        return "<entry name=\"%s\"></entry>" % self.name

    def apply(self):
        self.pandevice()._xapi.edit(self.xpath(), self.element())

    def create(self):
        # Remove the last part from the xpath
        xpath = self.xpath().rsplit("/", 1)[0]
        self.pandevice()._xapi.set(xpath, self.element())

    def delete(self):
        self.pandevice()._xapi.delete(self.xpath())

    def pandevice(self):
        if issubclass(self.__class__, device.PanDevice):
            return self
        else:
            if self.parent is None:
                raise err.PanDeviceNotSet("No PanDevice set for object tree")
            else:
                return self.parent.pandevice()

    @classmethod
    def find(cls, list_of_panobjects, name, class_type=None):
        if class_type is None:
            class_type = cls
        indexes = [i for i, child in enumerate(list_of_panobjects) if child.name == name and issubclass(class_type, child)]
        for index in indexes:
            return index  # Just return the first index that matches the name
        return None
