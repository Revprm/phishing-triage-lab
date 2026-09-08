"""Unit tests for phishlab.extract + heuristics + scoring."""

import sys
from pathlib import Path

# Ensure src on path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from phishlab.extract import classify, defang, extract_iocs, refang
from phishlab.heuristics import heuristic
from phishlab.scoring import verdict


def test_refang():
    assert refang("hxxp://example[.]com") == "http://example.com"
    assert refang("example[.]com") == "example.com"
    assert refang("user[@]example[.]com") == "user@example.com"


def test_defang():
    assert "[.]" in defang("http://example.com")


def test_classify():
    assert classify("http://example.com/login") == "url"
    assert classify("8.8.8.8") == "ip"
    assert classify("44d88612fea8a8f36de82e1278abb02f") == "md5"
    assert classify("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") == "sha256"
    assert classify("example.com") == "domain"
    assert classify("user@example.com") == "email"


def test_extract_iocs(tmp_path):
    p = tmp_path / "iocs.txt"
    p.write_text("hxxp://micorsoft-365security[.]com/login\n192[.]0[.]2[.]10\n")
    iocs = extract_iocs(str(p))
    values = [i["value"] for i in iocs]
    assert "http://micorsoft-365security.com/login" in values
    assert "192.0.2.10" in values


def test_heuristic_lookalike():
    assert "lookalike-keyword" in heuristic("micorsoft-365security.com", "domain")
    assert "url-shortener" in heuristic("http://bit.ly/abc", "url")
    assert "eicar-test-file" in heuristic("44d88612fea8a8f36de82e1278abb02f", "md5")


def test_verdict():
    assert verdict(85) == "Confirmed-malicious (block + incident)"
    assert verdict(50) == "Suspicious (escalate Tier-2)"
    assert verdict(0) == "Likely-benign / FP (monitor)"
