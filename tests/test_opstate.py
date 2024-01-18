from datetime import datetime
import xml.etree.ElementTree as ET

try:
    from unittest import mock
except ImportError:
    import mock

from panos.firewall import Firewall
from panos.policies import HitCount
from panos.policies import Rulebase
from panos.policies import SecurityRule
from panos.policies import AuditCommentLog


HIT_COUNT_PREFIX = """
<response>
    <result>
        <rule-hit-count>
            <vsys>
                <entry>
                    <rule-base>
                        <entry>
                            <rules>
"""

HIT_COUNT_SUFFIX = """
                            </rules>
                        </entry>
                    </rule-base>
                </entry>
            </vsys>
        </rule-hit-count>
    </result>
</response>
"""


def _fw():
    fw = Firewall("127.0.0.1", "admin", "admin", "secret")
    fw._version_info = (9999, 0, 0)
    return fw


def _hit_count_fw_setup(*args):
    fw = _fw()

    inner = "".join(ET.tostring(x, encoding="utf-8").decode("utf-8") for x in args)

    fw.op = mock.Mock(
        return_value=ET.fromstring(
            HIT_COUNT_PREFIX + inner + HIT_COUNT_SUFFIX,
        )
    )

    rb = Rulebase()
    fw.add(rb)

    return fw, rb


def _hit_count_elm(
    name,
    latest="yes",
    hit_count=0,
    last_hit_timestamp=0,
    last_reset_timestamp=0,
    first_hit_timestamp=0,
    rule_creation_timestamp=0,
    rule_modification_timestamp=0,
    obj=None,
):
    tmpl = """
    <entry name="{0}">
        <latest>{1}</latest>
        <hit-count>{2}</hit-count>
        <last-hit-timestamp>{3}</last-hit-timestamp>
        <last-reset-timestamp>{4}</last-reset-timestamp>
        <first-hit-timestamp>{5}</first-hit-timestamp>
        <rule-creation-timestamp>{6}</rule-creation-timestamp>
        <rule-modification-timestamp>{7}</rule-modification-timestamp>
    </entry>"""

    val = None
    if obj is not None:
        val = tmpl.format(
            obj.name,
            obj.latest,
            obj.hit_count,
            obj.last_hit_timestamp,
            obj.last_reset_timestamp,
            obj.first_hit_timestamp,
            obj.rule_creation_timestamp,
            obj.rule_modification_timestamp,
        )
    else:
        val = tmpl.format(
            name,
            latest,
            hit_count,
            last_hit_timestamp,
            last_reset_timestamp,
            first_hit_timestamp,
            rule_creation_timestamp,
            rule_modification_timestamp,
        )

    return ET.fromstring(val)


def _hit_count_eq(a, b):
    for key in vars(a).keys():
        if key == "obj":
            continue
        assert hasattr(b, key)
        assert getattr(a, key) == getattr(b, key)


def test_rulebase_hit_count_refresh_for_single_attached_security_rule():
    name = "intrazone-default"
    elm = _hit_count_elm(
        name=name,
        rule_creation_timestamp=1599752499,
        rule_modification_timestamp=1599752499,
    )
    expected = HitCount(None, name=name, elm=elm)

    fw, rb = _hit_count_fw_setup(elm)
    o = SecurityRule(name)
    rb.add(o)

    assert not o.opstate.hit_count.rule_creation_timestamp

    ans = rb.opstate.hit_count.refresh("security")

    assert len(ans) == 1
    assert o.uid in ans
    _hit_count_eq(expected, ans[o.uid])
    _hit_count_eq(expected, o.opstate.hit_count)


def test_rulebase_hit_count_refresh_for_multiple_attached_security_rules():
    n1 = "foo"
    elm1 = _hit_count_elm(
        name=n1,
        hit_count=42,
        rule_creation_timestamp=1599752499,
        rule_modification_timestamp=1599752499,
    )
    e1 = HitCount(None, name=n1, elm=elm1)

    n2 = "bar"
    elm2 = _hit_count_elm(
        name=n2,
        hit_count=24,
        rule_creation_timestamp=1234,
        rule_modification_timestamp=5678,
    )
    e2 = HitCount(None, name=n2, elm=elm2)

    fw, rb = _hit_count_fw_setup(elm1, elm2)
    o1 = SecurityRule(n1)
    rb.add(o1)

    o2 = SecurityRule(n2)
    rb.add(o2)

    assert not o1.opstate.hit_count.hit_count
    assert not o2.opstate.hit_count.hit_count

    ans = rb.opstate.hit_count.refresh("security")

    assert len(ans) == 2
    assert o1.uid in ans
    _hit_count_eq(e1, ans[o1.uid])
    _hit_count_eq(e1, o1.opstate.hit_count)
    assert o2.uid in ans
    _hit_count_eq(e2, ans[o2.uid])
    _hit_count_eq(e2, o2.opstate.hit_count)


def test_rulebase_hit_count_refresh_for_all_rules_updates_attached_rule():
    n1 = "intrazone-default"
    elm1 = _hit_count_elm(
        name=n1,
        hit_count=1,
        rule_creation_timestamp=1599752499,
        rule_modification_timestamp=1599752499,
    )
    e1 = HitCount(None, name=n1, elm=elm1)

    n2 = "interzone-default"
    elm2 = _hit_count_elm(
        name=n2,
        hit_count=2,
        rule_creation_timestamp=1599752499,
        rule_modification_timestamp=1599752499,
    )
    e2 = HitCount(None, name=n2, elm=elm2)

    name = "bar"
    elm3 = _hit_count_elm(
        name=name,
        hit_count=24,
        rule_creation_timestamp=1234,
        rule_modification_timestamp=5678,
    )
    expected = HitCount(None, name=name, elm=elm3)

    fw, rb = _hit_count_fw_setup(elm1, elm2, elm3)
    o = SecurityRule(name)
    rb.add(o)

    assert not o.opstate.hit_count.hit_count

    ans = rb.opstate.hit_count.refresh("security", all_rules=True)

    assert len(ans) == 3
    assert n1 in ans
    _hit_count_eq(e1, ans[n1])
    assert n2 in ans
    _hit_count_eq(e2, ans[n2])
    assert o.uid in ans
    _hit_count_eq(expected, ans[o.uid])
    _hit_count_eq(expected, o.opstate.hit_count)


def test_security_rule_hit_count_refresh():
    name = "foo"
    elm = _hit_count_elm(
        name=name,
        hit_count=1,
        last_hit_timestamp=21,
        last_reset_timestamp=22,
        first_hit_timestamp=23,
        rule_creation_timestamp=24,
        rule_modification_timestamp=25,
    )
    expected = HitCount(None, name=name, elm=elm)

    fw, rb = _hit_count_fw_setup(elm)
    o = SecurityRule(name)
    rb.add(o)

    assert not o.opstate.hit_count.rule_creation_timestamp

    o.opstate.hit_count.refresh()

    _hit_count_eq(expected, o.opstate.hit_count)


def test_current_audit_comment():
    expected = "Hello, world"

    fw = _fw()
    rb = Rulebase()
    fw.add(rb)
    obj = SecurityRule("foo")
    rb.add(obj)
    fw.op = mock.Mock(
        return_value=ET.fromstring(
            "\n".join(
                [
                    "<response>",
                    "<result>",
                    "<entry>",
                    "<xpath>{0}</xpath>".format(obj.xpath()),
                    "<dirtyId>17</dirtyId>",
                    "<comment>{0}</comment>".format(expected),
                    "<prevdirtyId>0</prevdirtyId>",
                    "</entry>",
                    "</result>",
                    "</response>",
                ]
            ),
        ),
    )

    assert expected == obj.opstate.audit_comment.current()


def test_audit_comment_history():
    fw = _fw()
    rb = Rulebase()
    fw.add(rb)
    obj = SecurityRule("my policy")
    rb.add(obj)
    fw.xapi.log = mock.Mock(
        return_value=ET.fromstring(
            """
<response status="success"><result>
  <job>
    <tenq>10:28:38</tenq>
    <tdeq>10:28:38</tdeq>
    <tlast>10:28:38</tlast>
    <status>FIN</status>
    <id>729</id>
  </job>
  <log>
    <logs count="2" progress="100">
      <entry logid="6947456634637516808">
        <domain>1</domain>
        <receive_time>2021/04/05 15:21:50</receive_time>
        <serial>unknown</serial>
        <seqno>2306</seqno>
        <actionflags>0x0</actionflags>
        <is-logging-service>no</is-logging-service>
        <type>CONFIG</type>
        <subtype>1</subtype>
        <config_ver>16</config_ver>
        <time_generated>2021/04/05 15:21:50</time_generated>
        <dg_hier_level_1>0</dg_hier_level_1>
        <dg_hier_level_2>0</dg_hier_level_2>
        <dg_hier_level_3>0</dg_hier_level_3>
        <dg_hier_level_4>0</dg_hier_level_4>
        <device_name>PA-VM</device_name>
        <vsys_id>0</vsys_id>
        <host>174.87.104.22</host>
        <cmd>audit-commit</cmd>
        <admin>admin1</admin>
        <client>Web</client>
        <result>Succeeded</result>
        <path> vsys  vsys1 rulebase security rules  my policy</path>
        <dg_id>0</dg_id>
        <comment>newest comment</comment>
        <before-change-preview>d0c5e58b-63d1-475b-a9b3-25f169ee296e</before-change-preview>
        <after-change-preview>d0c5e58b-63d1-475b-a9b3-25f169ee296e</after-change-preview>
        <full-path>/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='my policy']</full-path>
      </entry>
      <entry logid="6947456634637516805">
        <domain>1</domain>
        <receive_time>2021/04/05 14:57:40</receive_time>
        <serial>unknown</serial>
        <seqno>2303</seqno>
        <actionflags>0x0</actionflags>
        <is-logging-service>no</is-logging-service>
        <type>CONFIG</type>
        <subtype>1</subtype>
        <config_ver>15</config_ver>
        <time_generated>2021/04/05 14:57:40</time_generated>
        <dg_hier_level_1>0</dg_hier_level_1>
        <dg_hier_level_2>0</dg_hier_level_2>
        <dg_hier_level_3>0</dg_hier_level_3>
        <dg_hier_level_4>0</dg_hier_level_4>
        <device_name>PA-VM</device_name>
        <vsys_id>0</vsys_id>
        <host>174.87.104.22</host>
        <cmd>audit-commit</cmd>
        <admin>admin2</admin>
        <client>Web</client>
        <result>Succeeded</result>
        <path> vsys  vsys1 rulebase security rules  my policy</path>
        <dg_id>0</dg_id>
        <comment>initial comment</comment>
        <before-change-preview>d0c5e58b-63d1-475b-a9b3-25f169ee296e</before-change-preview>
        <after-change-preview>d0c5e58b-63d1-475b-a9b3-25f169ee296e</after-change-preview>
        <full-path>/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='my policy']</full-path>
      </entry>
    </logs>
  </log>
  <meta>
    <devices>
      <entry name="localhost.localdomain">
        <hostname>localhost.localdomain</hostname>
        <vsys>
          <entry name="vsys1">
            <display-name>vsys1</display-name>
          </entry>
        </vsys>
      </entry>
    </devices>
  </meta>
</result></response>
        """
        ),
    )
    t1 = datetime(2021, 4, 5, 15, 21, 50)
    t2 = datetime(2021, 4, 5, 14, 57, 40)

    ans = obj.opstate.audit_comment.history()

    assert len(ans) == 2
    assert ans[0].admin == "admin1"
    assert ans[0].comment == "newest comment"
    assert ans[0].config_version == 16
    assert ans[0].time == t1
    assert ans[1].admin == "admin2"
    assert ans[1].comment == "initial comment"
    assert ans[1].config_version == 15
    assert ans[1].time == t2
