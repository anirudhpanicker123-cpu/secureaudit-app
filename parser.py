# parser.py
import re

class ConfigParser:
    def __init__(self, config_text, vendor='cisco'):
        self.config_text = config_text
        self.vendor = vendor
        self.parse = None
        self.config_lines = config_text.splitlines()

    def parse_config(self):
        try:
            self.parse = self.config_lines
            return True
        except Exception as e:
            print(f"Parse error: {e}")
            return False

    def detect_vendor(self):
        config_lower = self.config_text.lower()

        # --- Fortinet FortiGate signatures ---
        fortinet_signatures = [
            'config system global',
            'config firewall policy',
            'set hostname',
            '# config-version',
            'config system interface'
        ]
        fortinet_hits = sum(1 for sig in fortinet_signatures if sig in config_lower)
        if fortinet_hits >= 2:
            return 'fortinet'

        # --- Palo Alto PAN-OS signatures ---
        paloalto_signatures = [
            'set deviceconfig system',
            'set network interface',
            'set rulebase security',
            'set mgt-config users',
            'pan-os'
        ]
        paloalto_hits = sum(1 for sig in paloalto_signatures if sig in config_lower)
        if paloalto_hits >= 2:
            return 'paloalto'

        # --- Huawei VRP signatures ---
        huawei_signatures = [
            'sysname ',
            'vlan batch',
            'interface vlanif',
            'aaa authentication-scheme',
            'stelnet server enable'
        ]
        huawei_hits = sum(1 for sig in huawei_signatures if sig in config_lower)
        if huawei_hits >= 2:
            return 'huawei'

        # --- Arista EOS signatures ---
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
        if arista_hits >= 2:
            return 'arista'

        # --- Juniper Junos signatures ---
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
        if juniper_hits >= 2:
            return 'juniper'

        # --- Cisco IOS/NX-OS signatures ---
        cisco_signatures = [
            'hostname ',
            'interface gigabitethernet',
            'interface fastethernet',
            'interface vlan',
            'boot-start-marker',
            'service password-encryption',
            'cisco'
        ]
        cisco_hits = sum(1 for sig in cisco_signatures if sig in config_lower)
        if cisco_hits >= 2:
            return 'cisco'

        # Default fallback
        return 'cisco'

    def check_pattern(self, pattern, negative=False):
        if not pattern:
            return False
        if isinstance(pattern, list):
            hits = any(p.lower() in self.config_text.lower() for p in pattern if p)
            return (not hits) if negative else hits
        else:
            hit = pattern.lower() in self.config_text.lower()
            return (not hit) if negative else hit

    def find_line_number(self, patterns):
        if isinstance(patterns, str):
            patterns = [patterns]
        for i, line in enumerate(self.config_lines, 1):
            for pattern in patterns:
                if pattern and pattern.lower() in line.lower():
                    return i
        return None

    def get_config_lines(self):
        return self.config_lines