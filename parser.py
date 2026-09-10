# parser.py
import re

class ConfigParser:
    def __init__(self, config_text, vendor='cisco'):
        self.config_text = config_text
        self.vendor = vendor
        self.parse = None
        self.config_lines = config_text.splitlines()

    def parse_config(self):
        """Parse the configuration into lines for checking"""
        try:
            self.parse = self.config_lines
            return True
        except Exception as e:
            print(f"Parse error: {e}")
            return False

    def detect_vendor(self):
        """Auto-detect vendor from config syntax"""
        config_lower = self.config_text.lower()

        # --- Arista signatures (checked FIRST because Arista looks like Cisco) ---
        arista_signatures = [
            '! device:',
            'service routing protocols model multi-agent',
            'daemon terminattr',
            'management api http-commands',
            'transceiver qsfp default-mode',
            'spanning-tree mode mstp',
            'vrf instance'
        ]
        arista_hits = sum(1 for sig in arista_signatures if sig in config_lower)

        # --- Juniper signatures ---
        juniper_signatures = [
            'set system ',
            'set interfaces ',
            'set protocols ',
            'set security ',
            'set snmp ',
            'set routing-options',
            'junos',
            'juniper'
        ]
        juniper_hits = sum(1 for sig in juniper_signatures if sig in config_lower)

        # --- Cisco signatures ---
        cisco_signatures = [
            'cisco',
            'ios',
            'ios-xe',
            'nx-os',
            'hostname ',
            'interface gigabitethernet',
            'interface fastethernet',
            'interface vlan',
            'boot-start-marker',
            'service password-encryption'
        ]
        cisco_hits = sum(1 for sig in cisco_signatures if sig in config_lower)

        # --- Huawei signatures ---
        huawei_signatures = [
            'sysname ',
            'huawei',
            'vlan batch',
            'interface vlanif',
            'aaa authentication-scheme'
        ]
        huawei_hits = sum(1 for sig in huawei_signatures if sig in config_lower)

        # --- Palo Alto signatures ---
        paloalto_signatures = [
            'set deviceconfig',
            'set network',
            'pan-os',
            'palo alto'
        ]
        paloalto_hits = sum(1 for sig in paloalto_signatures if sig in config_lower)

        # Decide by highest score
        scores = {
            'arista': arista_hits,
            'juniper': juniper_hits,
            'cisco': cisco_hits,
            'huawei': huawei_hits,
            'paloalto': paloalto_hits
        }

        # Special case: Arista has `hostname` too. If arista_hits > 0 and cisco_hits > 0,
        # prefer Arista (since Arista configs often contain Cisco-like syntax)
        if arista_hits >= 2:
            return 'arista'

        # Special case: Juniper uses "set " prefix heavily
        if juniper_hits >= 2:
            return 'juniper'

        # Pick highest
        best = max(scores, key=scores.get)
        if scores[best] == 0:
            return 'cisco'   # default fallback
        return best

    def check_pattern(self, pattern, negative=False):
        """Check if pattern exists in config. If negative=True, check absence."""
        if not pattern:
            return False

        if isinstance(pattern, list):
            hits = any(p.lower() in self.config_text.lower() for p in pattern if p)
            return (not hits) if negative else hits
        else:
            hit = pattern.lower() in self.config_text.lower()
            return (not hit) if negative else hit

    def find_line_number(self, patterns):
        """Find the line number where a pattern appears"""
        if isinstance(patterns, str):
            patterns = [patterns]

        for i, line in enumerate(self.config_lines, 1):
            for pattern in patterns:
                if pattern and pattern.lower() in line.lower():
                    return i
        return None

    def get_config_lines(self):
        """Return all config lines"""
        return self.config_lines