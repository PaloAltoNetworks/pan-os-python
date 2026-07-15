"""Tests for XML safety utilities."""

import pytest
from panos._xml_safety import safe_fromstring, _check_xml_safety


class TestXmlSafety:
    """Test XML safety checks."""

    def test_safe_xml(self):
        """Test that safe XML parses correctly."""
        xml = "<root><child>text</child></root>"
        result = safe_fromstring(xml)
        assert result.tag == "root"
        assert result.find("child").text == "text"

    def test_xxe_entity_blocked(self):
        """Test that XML with ENTITY declarations is blocked."""
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <root>&xxe;</root>"""
        
        with pytest.raises(ValueError, match="ENTITY declarations"):
            safe_fromstring(malicious_xml)

    def test_xxe_doctype_blocked(self):
        """Test that XML with DOCTYPE internal subset is blocked."""
        malicious_xml = """<?xml version="1.0"?>
        <!DOCTYPE foo [
            <!ELEMENT root ANY>
        ]>
        <root>text</root>"""
        
        with pytest.raises(ValueError, match="DOCTYPE with internal subset"):
            safe_fromstring(malicious_xml)

    def test_normal_doctype_allowed(self):
        """Test that DOCTYPE without internal subset is allowed."""
        xml = '<?xml version="1.0"?><!DOCTYPE root><root>text</root>'
        result = safe_fromstring(xml)
        assert result.tag == "root"

    def test_bytes_input(self):
        """Test that bytes input is handled correctly."""
        xml = b"<root><child>text</child></root>"
        result = safe_fromstring(xml)
        assert result.tag == "root"

    def test_uid_message_format(self):
        """Test that pan-os-python's uid-message format works."""
        # This is the actual format used in userid.py
        xml = (
            "<uid-message>"
            "<version>1.0</version>"
            "<type>update</type>"
            "<payload/>"
            "</uid-message>"
        )
        result = safe_fromstring(xml)
        assert result.tag == "uid-message"
        assert result.find("version").text == "1.0"
        assert result.find("type").text == "update"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
