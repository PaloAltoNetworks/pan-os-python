"""
Safe XML parsing utilities for pan-os-python.

This module provides XML parsing functions that are protected against
XML External Entity (XXE) attacks. It addresses security findings
related to unsafe XML parser usage (see issue #617).

Note: Python 3.11+ includes expat 2.6.0+ which has built-in XXE protection.
However, pan-os-python supports Python 2.7 and 3.5+, so this module
provides defense-in-depth for older Python versions.
"""

from __future__ import absolute_import
import re
import sys
import xml.etree.ElementTree as ET


# Regex patterns for detecting dangerous XML constructs
_ENTITY_PATTERN = re.compile(
    r'<!ENTITY[^>]*>',
    re.IGNORECASE | re.DOTALL
)
_DOCTYPE_PATTERN = re.compile(
    r'<!DOCTYPE[^>]*\[',  # DOCTYPE with internal subset
    re.IGNORECASE | re.DOTALL
)


def _check_xml_safety(xml_string):
    """
    Check if an XML string contains potentially dangerous constructs.
    
    Args:
        xml_string: The XML string to check
        
    Raises:
        ValueError: If the XML contains dangerous constructs (entities, DOCTYPE with internal subset)
    """
    if not isinstance(xml_string, str):
        # Handle bytes
        if isinstance(xml_string, bytes):
            xml_string = xml_string.decode('utf-8', errors='ignore')
        else:
            return  # Skip non-string types
    
    if _ENTITY_PATTERN.search(xml_string):
        raise ValueError(
            "XML contains ENTITY declarations which are not allowed. "
            "This may indicate an XXE attack attempt."
        )
    
    if _DOCTYPE_PATTERN.search(xml_string):
        raise ValueError(
            "XML contains DOCTYPE with internal subset which is not allowed. "
            "This may indicate an XXE attack attempt."
        )


def safe_fromstring(xml_string, *args, **kwargs):
    """
    Safely parse an XML string, protecting against XXE attacks.
    
    This is a drop-in replacement for xml.etree.ElementTree.fromstring()
    that includes XXE protection for Python versions < 3.11.
    
    Args:
        xml_string: The XML string to parse
        *args, **kwargs: Additional arguments passed to ET.fromstring()
        
    Returns:
        Element: The parsed XML element
        
    Raises:
        ValueError: If the XML contains dangerous constructs
    """
    _check_xml_safety(xml_string)
    return ET.fromstring(xml_string, *args, **kwargs)


def safe_parse(source, *args, **kwargs):
    """
    Safely parse an XML file or file-like object, protecting against XXE attacks.
    
    This is a drop-in replacement for xml.etree.ElementTree.parse()
    that includes XXE protection for Python versions < 3.11.
    
    Args:
        source: File path or file-like object
        *args, **kwargs: Additional arguments passed to ET.parse()
        
    Returns:
        ElementTree: The parsed XML tree
        
    Raises:
        ValueError: If the XML contains dangerous constructs
    """
    # For file-like objects, we need to read and check content
    if hasattr(source, 'read'):
        content = source.read()
        _check_xml_safety(content)
        # Reset file position if possible
        if hasattr(source, 'seek'):
            source.seek(0)
        # Create a new StringIO/StringBytes object
        if isinstance(content, bytes):
            from io import BytesIO
            source = BytesIO(content)
        else:
            from io import StringIO
            source = StringIO(content)
    else:
        # File path - read and check
        with open(source, 'r') as f:
            content = f.read()
        _check_xml_safety(content)
    
    return ET.parse(source, *args, **kwargs)
