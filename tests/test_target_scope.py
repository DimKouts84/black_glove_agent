"""Host extraction from scan targets."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent.target_scope import split_host_port, strip_host


def test_strip_host_drops_query_when_scheme_was_removed():
    assert strip_host("zebeh.com/?s=test") == "zebeh.com"
    assert strip_host("https://zebeh.com/?s=test") == "zebeh.com"
    assert strip_host("http://zebeh.com/path?s=test#frag") == "zebeh.com"


def test_split_host_port_keeps_port_and_drops_path():
    assert split_host_port("zebeh.com:8443/path") == ("zebeh.com", 8443)
    assert split_host_port("https://zebeh.com:8443/?s=test") == ("zebeh.com", 8443)
    assert split_host_port("[::1]:443") == ("::1", 443)
    assert split_host_port("66.29.132.181") == ("66.29.132.181", None)
