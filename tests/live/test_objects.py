from pandevice import objects
from tests.live import testlib


class TestAddressObject(testlib.DevFlow):
    def setup_state_obj(self, dev, state):
        state.obj = objects.AddressObject(
            state.random_name(),
            value=state.random_ip(),
            type='ip-netmask',
            description='This is a test',
        )
        dev.add(state.obj)

    def update_state_obj(self, dev, state):
        state.obj.type = 'ip-range'
        state.obj.value = '10.1.1.1-10.1.1.240'

class TestStaticAddressGroup(testlib.DevFlow):
    def create_dependencies(self, dev, state):
        state.aos = [
            objects.AddressObject(state.random_name(), state.random_ip())
            for x in range(4)
        ]
        for x in state.aos:
            dev.add(x)
            x.create()

    def setup_state_obj(self, dev, state):
        state.obj = objects.AddressGroup(
            state.random_name(), [x.name for x in state.aos[:2]],
        )
        dev.add(state.obj)

    def update_state_obj(self, dev, state):
        state.obj.static_value = [x.name for x in state.aos[2:]]

    def cleanup_dependencies(self, dev, state):
        for x in state.aos:
            try:
                x.delete()
            except Exception:
                pass

class TestDynamicAddressGroup(testlib.DevFlow):
    def create_dependencies(self, dev, state):
        state.tags = [
            objects.Tag(state.random_name(),
                        color='color{0}'.format(x),
                        comments=state.random_name())
            for x in range(1, 5)
        ]
        for x in state.tags:
            dev.add(x)
            x.create()

    def setup_state_obj(self, dev, state):
        state.obj = objects.AddressGroup(
            state.random_name(),
            dynamic_value="'{0}' or '{1}'".format(
                state.tags[0].name, state.tags[1].name),
            description='This is my description',
            tag=state.tags[2].name,
        )
        dev.add(state.obj)

    def update_state_obj(self, dev, state):
        state.obj.dynamic_value = "'{0}' and '{1}'".format(
            state.tags[2].name, state.tags[3].name,
        )
        state.obj.tag = state.tags[1].name

    def cleanup_dependencies(self, dev, state):
        for x in state.tags:
            try:
                x.delete()
            except Exception:
                pass

class TestTag(testlib.DevFlow):
    def setup_state_obj(self, dev, state):
        state.obj = objects.Tag(
            state.random_name(),
            color='color1',
            comments='My new tag',
        )
        dev.add(state.obj)

    def update_state_obj(self, dev, state):
        state.obj.color = 'color5'
        state.obj.comments = state.random_name()

class TestServiceObject(testlib.DevFlow):
    def setup_state_obj(self, dev, state):
        state.obj = objects.ServiceObject(
            state.random_name(),
            protocol='tcp',
            source_port='1025-65535',
            destination_port='80,443,8080',
            description='My service object',
        )
        dev.add(state.obj)

    def update_state_obj(self, dev, state):
        state.obj.protocol = 'udp'
        state.obj.source_port = '12345'

class TestServiceGroup(testlib.DevFlow):
    def create_dependencies(self, dev, state):
        state.tag = None
        state.services = [
            objects.ServiceObject(
                state.random_name(),
                'tcp' if x % 2 == 0 else 'udp',
                destination_port=2000 + x,
                description='Service {0}'.format(x))
            for x in range(4)
        ]
        for x in state.services:
            dev.add(x)
            x.create()
        state.tag = objects.Tag(state.random_name(), 'color5')
        dev.add(state.tag)
        state.tag.create()

    def setup_state_obj(self, dev, state):
        state.obj = objects.ServiceGroup(
            state.random_name(),
            [x.name for x in state.services[:2]],
            tag=state.tag.name,
        )
        dev.add(state.obj)

    def update_state_obj(self, dev, state):
        state.obj.value = [x.name for x in state.services[2:]]

    def cleanup_dependencies(self, dev, state):
        for x in state.services:
            try:
                x.delete()
            except Exception:
                pass

        if state.tag is not None:
            try:
                state.tag.delete()
            except Exception:
                pass

# ApplicationObject
# ApplicationGroup
# ApplicationFilter
# ApplicationContainer
