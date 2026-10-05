import os
import sys
import tempfile
import unittest
from pathlib import Path
import importlib.machinery
import importlib.util

repo_root = Path(__file__).parent.parent.parent
script_path = repo_root / "deploy" / "scripts" / "moonshield-suricata-rules-filter"

loader = importlib.machinery.SourceFileLoader("filter_script", str(script_path))
spec = importlib.util.spec_from_loader("filter_script", loader)
filter_script = importlib.util.module_from_spec(spec)
loader.exec_module(filter_script)

MOCK_DICT = {
    "app-layer": {
        "protocols": {
            "dnp3": {"enabled": "no"},
            "enip": {"enabled": False},
            "modbus": {"enabled": "no"},
            "pgsql": {"enabled": "no"},
            "http": {"enabled": "yes"},
            "imap": {"enabled": "detection-only"},
            "smb": {"enabled": True},
        }
    }
}

MOCK_RULES = """
# Regras validas
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Rule"; sid:1;)
drop dnp3 $EXTERNAL_NET any -> $HOME_NET any (msg:"DNP3 Rule 1"; sid:2;)
alert enip any any -> any any (msg:"ENIP Rule 1"; sid:3;)
pass modbus any any -> any any (msg:"Modbus Rule 1"; sid:4;)
reject pgsql any any -> any any (msg:"PGSQL Rule 1"; sid:5;)
alert imap any any -> any any (msg:"IMAP Rule"; sid:6;)
alert smb any any -> any any (msg:"SMB Rule"; sid:7;)

# Mais 11 regras desabilitadas para somar 15 no total
alert dnp3 any any -> any any (msg:"DNP3 Rule 2"; sid:8;)
alert dnp3 any any -> any any (msg:"DNP3 Rule 3"; sid:9;)
alert modbus any any -> any any (msg:"Modbus Rule 2"; sid:10;)
alert modbus any any -> any any (msg:"Modbus Rule 3"; sid:11;)
alert enip any any -> any any (msg:"ENIP Rule 2"; sid:12;)
alert enip any any -> any any (msg:"ENIP Rule 3"; sid:13;)
alert pgsql any any -> any any (msg:"PGSQL Rule 2"; sid:14;)
alert pgsql any any -> any any (msg:"PGSQL Rule 3"; sid:15;)
alert pgsql any any -> any any (msg:"PGSQL Rule 4"; sid:16;)
alert pgsql any any -> any any (msg:"PGSQL Rule 5"; sid:17;)
alert pgsql any any -> any any (msg:"PGSQL Rule 6"; sid:18;)

# Regra HTTP extra
alert http any any -> any any (msg:"HTTP Rule 2"; sid:19;)
"""

class TestSuricataFilter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.rules_path = Path(self.temp_dir.name) / "test.rules"
        with open(self.rules_path, "wb") as f:
            f.write(MOCK_RULES.replace('\n', '\r\n').encode('utf-8'))
            
        self.dest_path = Path(self.temp_dir.name) / "suricata.rules"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_disabled_protocols_parsing(self):
        disabled = filter_script.disabled_protocols(MOCK_DICT)
        self.assertEqual(disabled, {"dnp3", "enip", "modbus", "pgsql"})
        self.assertNotIn("http", disabled)

    def test_filter_rules_removes_exact_count(self):
        disabled = filter_script.disabled_protocols(MOCK_DICT)
        removed_counts = filter_script.filter_rules([self.rules_path], self.dest_path, disabled)
        
        total_removed = sum(removed_counts.values())
        self.assertEqual(total_removed, 15)

    def test_filter_rules_keeps_enabled(self):
        disabled = filter_script.disabled_protocols(MOCK_DICT)
        filter_script.filter_rules([self.rules_path], self.dest_path, disabled)
        
        content = self.dest_path.read_text(encoding="utf-8")
        self.assertIn("HTTP Rule", content)
        self.assertNotIn("DNP3 Rule", content)

    def test_newline_bug_fix(self):
        disabled = filter_script.disabled_protocols(MOCK_DICT)
        filter_script.filter_rules([self.rules_path], self.dest_path, disabled)
        
        with open(self.dest_path, "rb") as f:
            raw_content = f.read()
            
        self.assertNotIn(b'\r\n', raw_content)

if __name__ == '__main__':
    unittest.main()
