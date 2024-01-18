import pytest

import inspect

# Packages with classes to omit checks for.
import panos
from panos import base
from panos import errors

# Packages with classes to verify.
from panos import device
from panos import firewall
from panos import ha
from panos import network
from panos import objects
from panos import panorama
from panos import policies
from panos import predefined
from panos import plugins


# Versioning constants.
#
# When checking versioning, this is the highest major version to check for
# param profiles.
MAX_PANOS_VERSION = (11, 1, 0)
MIN_PANOS_VERSION = (6, 1, 0)

# This is the list of all base classes as well as any classes that exist
# only to be inherited from.
OMIT_OBJECTS = [
    device.NTPServer,
    ha.HighAvailabilityInterface,
    network.BgpPolicyFilter,
    network.BgpPolicyRule,
    network.Interface,
    network.PhysicalInterface,
    network.RedistributionProfileBase,
    network.Subinterface,
    plugins.DNSServerBase,
]
# Pull in the classes to omit.
for pkg in (panos, errors, base):
    for name, cls in inspect.getmembers(pkg, inspect.isclass):
        if not cls.__module__.startswith("panos"):
            continue
        if cls not in OMIT_OBJECTS:
            OMIT_OBJECTS.append(cls)

# Pull in everything else.
DEVICE_OBJECTS = []
ALL_OBJECTS = []
NAMED_OBJECTS = []
UNNAMED_OBJECTS = []
VERSIONED_PAN_OBJECTS = []
CLASSIC_PAN_OBJECTS = []
PANORAMA_OBJECTS = ["plugins.CloudServicesPlugin"]
POLICY_RULES = []

for pkg in (
    device,
    firewall,
    ha,
    network,
    objects,
    panorama,
    policies,
    predefined,
    plugins,
):
    for name, cls in inspect.getmembers(pkg, inspect.isclass):
        if not cls.__module__.startswith("panos"):
            continue
        if cls in OMIT_OBJECTS:
            continue
        mro = inspect.getmro(cls)
        if base.PanDevice in mro:
            if cls not in DEVICE_OBJECTS:
                DEVICE_OBJECTS.append(cls)
        elif base.VersionedPanObject in mro or base.PanObject in mro:
            if cls not in ALL_OBJECTS:
                ALL_OBJECTS.append(cls)

            if base.VersionedPanObject in mro:
                if cls not in VERSIONED_PAN_OBJECTS:
                    VERSIONED_PAN_OBJECTS.append(cls)
            elif cls not in CLASSIC_PAN_OBJECTS:
                CLASSIC_PAN_OBJECTS.append(cls)

            if getattr(cls, "NAME", None) is None:
                if cls not in UNNAMED_OBJECTS:
                    UNNAMED_OBJECTS.append(cls)
            elif cls not in NAMED_OBJECTS:
                NAMED_OBJECTS.append(cls)

# Find rule classes in the policies package.
for name, cls in inspect.getmembers(policies, inspect.isclass):
    if cls.__module__ != "panos.policies":
        continue
    if name in ["Rulebase", "PreRulebase", "PostRulebase"]:
        continue
    mro = inspect.getmro(cls)
    if base.VersionedPanObject not in inspect.getmro(cls):
        continue
    POLICY_RULES.append(cls)


# -- Fixtures --


# PanObject / VersionedPanObject that has no NAME.
@pytest.fixture(
    scope="function",
    params=[x for x in UNNAMED_OBJECTS],
    ids=[
        "{0}_{1}".format(x.__module__.replace(".", "_"), x.__name__)
        for x in UNNAMED_OBJECTS
    ],
)
def unnamed_object(request):
    return request.param


# PanObject / VersionedPanObject that has a NAME.
@pytest.fixture(
    scope="function",
    params=[x for x in NAMED_OBJECTS],
    ids=[
        "{0}_{1}".format(x.__module__.replace(".", "_"), x.__name__)
        for x in NAMED_OBJECTS
    ],
)
def named_object(request):
    return request.param


# PanDevice.
@pytest.fixture(
    scope="function",
    params=[x for x in DEVICE_OBJECTS],
    ids=[
        "{0}_{1}".format(x.__module__.replace(".", "_"), x.__name__)
        for x in DEVICE_OBJECTS
    ],
)
def device_object(request):
    return request.param


# VersionedPanObjects only.
@pytest.fixture(
    scope="function",
    params=[x for x in VERSIONED_PAN_OBJECTS],
    ids=[
        "{0}_{1}".format(x.__module__.replace(".", "_"), x.__name__)
        for x in VERSIONED_PAN_OBJECTS
    ],
)
def versioned_object(request):
    return request.param


# Classic PanObjects only.
@pytest.fixture(
    scope="function",
    params=[x for x in CLASSIC_PAN_OBJECTS],
    ids=[
        "{0}_{1}".format(x.__module__.replace(".", "_"), x.__name__)
        for x in CLASSIC_PAN_OBJECTS
    ],
)
def classic_object(request):
    return request.param


# All PanObjects / VersionedPanObjects.  This is UNNAMED_OBJECTS + NAMED_OBJECTS.
@pytest.fixture(
    scope="function",
    params=[x for x in ALL_OBJECTS],
    ids=[
        "{0}_{1}".format(x.__module__.replace(".", "_"), x.__name__)
        for x in ALL_OBJECTS
    ],
)
def panobj(request):
    return request.param


# Rules in the policies package.
@pytest.fixture(
    scope="function",
    params=[x for x in POLICY_RULES],
    ids=[
        "{0}_{1}".format(x.__module__.replace(".", "_"), x.__name__)
        for x in POLICY_RULES
    ],
)
def policy_rule(request):
    return request.param


# -- Helpers --


def inst(cls):
    """Create an instance of the given class."""
    if getattr(cls, "NAME", None) is not None:
        return cls("test")
    return cls()


def versions():
    val = MIN_PANOS_VERSION
    while True:
        yield val
        if val == MAX_PANOS_VERSION:
            break
        if val[1] == 1:
            val = (val[0] + 1, 0, 0)
        else:
            val = (val[0], 1, 0)


def docstring_params(obj):
    docstring = obj.__doc__
    if "\n    Args:\n" in obj.__doc__:
        docstring = docstring.split("\n    Args:")[1]

    return [
        x.split(":")[0].split("(")[0].strip()
        for x in docstring.split("\n")
        if x.startswith(" " * 8) and not x.startswith(" " * 9)
    ]


# -- Tests --


def test_versioned_object_params_are_only_defined_once(versioned_object):
    # Skip objects without params (such as rulebases).
    count = {}
    obj = inst(versioned_object)

    for x in getattr(obj, "_params", []):
        count.setdefault(x.name, 0)
        count[x.name] = count[x.name] + 1

    for key in count:
        assert count[key] == 1, "Param '{0}' is defined {1} times".format(
            key, count[key]
        )


def test_classic_object_params_are_only_defined_once(classic_object):
    count = {}
    obj = inst(classic_object)

    for x in obj.variables():
        count.setdefault(x.variable, 0)
        count[x.variable] = count[x.variable] + 1

    for key in count:
        assert count[key] == 1, "Param '{0}' is defined {1} times".format(
            key, count[key]
        )


def test_versioned_object_has_args_in_docstring(versioned_object):
    obj = inst(versioned_object)

    if hasattr(obj, "_params"):
        assert "    Args:\n" in obj.__doc__
    else:
        assert "    Args:\n" not in obj.__doc__


def test_classic_object_has_args_in_docstring(classic_object):
    obj = inst(classic_object)
    listing = obj.variables()

    if len(obj.variables()) > 0:
        assert (
            "    Args:\n" in obj.__doc__
        ), "`Args:` is missing from the class docstring"
    else:
        assert "    Args:\n" not in obj.__doc__


def test_firewall_object_childtypes(panobj):
    # Skip Panorama objects.
    if panobj.__module__ == "panos.panorama":
        pytest.skip("Skipping panorama specific classes for firewall test")

    cts = panos.childtype_name(panobj)

    if cts in PANORAMA_OBJECTS:
        pytest.skip("Skipping Panoroama-only objects")

    found = cts in firewall.Firewall.CHILDTYPES
    if not found:
        for cls in ALL_OBJECTS:
            if cts in cls.CHILDTYPES:
                found = True
                break

    assert found, "{0} doesn't have a parent defined".format(panobj)


def test_object_with_vsys_root_is_in_vsys_childtypes(panobj):
    # Skip Panorama objects.
    if panobj.__module__ == "panos.panorama":
        pytest.skip("Skipping panorama specific classes for firewall test")

    cts = panos.childtype_name(panobj)

    if panobj.ROOT != base.Root.VSYS:
        pytest.skip("Not a vsys object")
    elif cts not in firewall.Firewall.CHILDTYPES:
        pytest.skip("Object does not sit off of the firewall object")

    msg = "{0} is in panos.firewall.Firewall.CHILDTYPES but not in panos.device.Vsys.CHILDTYPES"
    assert cts in device.Vsys.CHILDTYPES, msg.format(cts)


def test_object_with_vsys_root_is_in_firewall_childtypes(panobj):
    # Skip Panorama objects.
    if panobj.__module__ == "panos.panorama":
        pytest.skip("Skipping panorama specific classes for firewall test")

    cts = panos.childtype_name(panobj)

    if panobj.ROOT != base.Root.VSYS:
        pytest.skip("Not a vsys object")
    elif cts not in device.Vsys.CHILDTYPES:
        pytest.skip("Object does not sit off of the vsys object")

    msg = "{0} is in panos.device.Vsys.CHILDTYPES but not in panos.firewall.Firewall.CHILDTYPES"
    assert cts in firewall.Firewall.CHILDTYPES, msg.format(cts)


def test_object_with_non_vsys_root_is_not_in_vsys_childtypes(panobj):
    # Skip Panorama objects.
    if panobj.__module__ == "panos.panorama":
        pytest.skip("Skipping panorama specific classes for firewall test")

    cts = panos.childtype_name(panobj)

    if hasattr(panobj, "ALWAYS_IMPORT"):
        pytest.skip("Skipping importable object")
    elif panobj.ROOT in (base.Root.VSYS, base.Root.PANORAMA_VSYS):
        pytest.skip("Skipping vsys object")

    msg = "{0} is a non-vsys object but is in panos.device.Vsys.CHILDTYPES"
    assert cts not in device.Vsys.CHILDTYPES, msg.format(cts)


def test_vsys_importable_childtypes(panobj):
    # Skip Panorama objects.
    if panobj.__module__ == "panos.panorama":
        pytest.skip("Skipping panorama specific classes for firewall test")

    cts = panos.childtype_name(panobj)

    if not hasattr(panobj, "ALWAYS_IMPORT"):
        pytest.skip("Skipping standard object")

    omissions = (
        "network.Layer2Subinterface",
        "network.Layer3Subinterface",
    )
    if cts in omissions:
        pytest.skip(
            "Subinterfaces can be children of these objects, but won't show up in the XPATH"
        )

    msg = "{0} is vsys importable and needs to be in {1}.CHILDTYPES"
    assert cts in firewall.Firewall.CHILDTYPES, msg.format(cts, "firewall.Firewall")
    assert cts in device.Vsys.CHILDTYPES, msg.format(cts, "device.Vsys")


def test_param_path_does_not_have_slash_prefix(versioned_object):
    obj = inst(versioned_object)

    if not hasattr(obj, "_params"):
        pytest.skip("Object does not have _params")

    msg = "{0}.{1}.{2} (version {3}) path has a leading slash"
    for param in obj._params:
        for version_tuple in versions():
            pp = param._get_versioned_value(version_tuple)
            if pp.path is not None:
                assert not pp.path.startswith("/"), msg.format(
                    obj.__module__,
                    obj.__class__.__name__,
                    pp.param,
                    "{0}.{1}.{2}".format(*version_tuple),
                )


def test_xpaths_have_slash_prefix(versioned_object):
    obj = inst(versioned_object)

    if not hasattr(obj, "_xpaths"):
        pytest.skip("No xpaths present")

    msg = "{0}.{1} xpath (version {2}) is missing leading slash"
    for combo in obj._xpaths.settings:
        for version_tuple in versions():
            path = obj._xpaths.settings[combo]._get_versioned_value(version_tuple)
            if path:
                assert path.startswith("/"), msg.format(
                    obj.__module__,
                    obj.__class__.__name__,
                    "{0}.{1}.{2}".format(*version_tuple),
                )


def test_classic_object_param_documentation(classic_object):
    obj = inst(classic_object)

    actual_params = [x.variable for x in obj.variables()]
    docstring_listing = docstring_params(obj)

    if getattr(obj, "NAME", None) is not None:
        assert docstring_listing
        assert (
            docstring_listing[0] == obj.NAME
        ), "Unique identifier {0} is not documented".format(obj.NAME)
        docstring_listing = docstring_listing[1:]

    assert (
        actual_params == docstring_listing
    ), "Actual params don't match documented params"


def test_versioned_object_param_documentation(versioned_object):
    obj = inst(versioned_object)

    actual_params = [x.name for x in getattr(obj, "_params", [])]
    docstring_listing = docstring_params(obj)

    if getattr(obj, "NAME", None) is not None:
        assert docstring_listing
        assert (
            docstring_listing[0] == obj.NAME
        ), "Unique identifier {0} is not documented".format(obj.NAME)
        docstring_listing = docstring_listing[1:]

    assert (
        actual_params == docstring_listing
    ), "Actual params don't match documented params"


def test_policy_rule_is_in_all_rulebase_childtypes(policy_rule):
    cts = panos.childtype_name(policy_rule)

    for cls in [policies.Rulebase, policies.PreRulebase, policies.PostRulebase]:
        assert cts in cls.CHILDTYPES


def test_parent_aware_children_show_in_parent_childtypes(versioned_object):
    obj = inst(versioned_object)

    classes = set([])
    for combo in obj._xpaths.settings:
        cls_str = combo[0]
        if cls_str is None:
            continue

        cls = None
        for x in (
            device,
            firewall,
            ha,
            network,
            objects,
            panorama,
            policies,
            predefined,
        ):
            if hasattr(x, cls_str):
                cls = getattr(x, cls_str)
                break
        else:
            assert False, "Could not find class {0}".format(cls_str)

        if cls is not None:
            classes.add(cls)

    msg = "Child {0} has parent {1}, but does not show in parent's CHILDTYPES"
    for cls in classes:
        assert panos.childtype_name(versioned_object) in cls.CHILDTYPES, msg.format(
            versioned_object, cls
        )


def test_opstates_is_a_dict(panobj):
    assert isinstance(getattr(panobj, "OPSTATES", {}), dict)


def test_opstates_inherit_from_opstate(panobj):
    for name, cls in panobj.OPSTATES.items():
        mro = inspect.getmro(cls)
        assert (
            base.OpState in mro
        ), "base.OpState is not in the {0}.opstate.{1} mro".format(
            panobj.__name__, name
        )
