# compliance_engine.py
from config import Config

class ComplianceEngine:
    def __init__(self, config_text, vendor='cisco'):
        self.config_text = config_text
        self.vendor = vendor
        self.violations = []
        self.passed_checks = []
        self.config_lines = config_text.splitlines()

    def get_check_pattern(self, rule_data):
        """Return the correct check pattern for the detected vendor"""
        vendor_key = f'check_{self.vendor}'
        pattern = rule_data.get(vendor_key)

        # If this vendor has no specific pattern, fall back to Cisco
        if pattern is None:
            pattern = rule_data.get('check_cisco', '')

        return pattern

    def get_check_type(self, rule_data):
        """Return 'positive' or 'negative'"""
        return rule_data.get('check_type', 'positive')

    def find_line_number(self, patterns):
        """Find the line number where a pattern appears"""
        if not patterns:
            return None
        if isinstance(patterns, str):
            patterns = [patterns]
        for i, line in enumerate(self.config_lines, 1):
            for pattern in patterns:
                if pattern and pattern.lower() in line.lower():
                    return i
        return None

    def get_line_content(self, line_number):
        """Get the actual content of a line"""
        if line_number and 1 <= line_number <= len(self.config_lines):
            return self.config_lines[line_number - 1].strip()
        return None

    def check_rule(self, rule_data):
        """Check a rule against the config using vendor-specific patterns"""
        pattern = self.get_check_pattern(rule_data)
        check_type = self.get_check_type(rule_data)

        if not pattern:
            return True   # No pattern = nothing to check (pass)

        patterns_list = pattern if isinstance(pattern, list) else [pattern]

        # Check for the pattern's presence
        found = any(p.lower() in self.config_text.lower() for p in patterns_list if p)

        if check_type == 'negative':
            # For negative rules, PASS means pattern is ABSENT
            return not found
        else:
            # For positive rules, PASS means pattern is PRESENT
            return found

    def find_violation_line(self, rule_data):
        """Find the line number most relevant to the violation"""
        pattern = self.get_check_pattern(rule_data)
        check_type = self.get_check_type(rule_data)

        if not pattern:
            return None

        patterns_list = pattern if isinstance(pattern, list) else [pattern]

        if check_type == 'negative':
            # Bad command IS present — show that line
            return self.find_line_number(patterns_list)
        else:
            # Good command is MISSING — find nearby context
            # Look for a context keyword like "line vty", "hostname", etc.
            context_keywords = {
                'ssh_only': ['line vty', 'line con'],
                'enable_secret': ['hostname'],
                'logging': ['hostname'],
                'password_encryption': ['username', 'hostname'],
                'banner_motd': ['hostname'],
                'ntp_configured': ['hostname'],
                'aaa_configured': ['hostname'],
                'password_min_length': ['username', 'hostname'],
                'exec_timeout': ['line vty', 'line con'],
                'logging_configured': ['logging', 'hostname'],
                'enable_secret_encrypted': ['enable secret', 'enable password'],
                'service_timestamps': ['hostname'],
                'no_ip_source_route': ['hostname', 'ip routing']
            }

            rule_key = rule_data.get('_key', '')
            for keyword in context_keywords.get(rule_key, []):
                line_num = self.find_line_number([keyword])
                if line_num:
                    return line_num

            return None

    def get_remediation(self, rule_data):
        """Get remediation command based on detected vendor"""
        vendor_key = f'remediation_{self.vendor}'
        return rule_data.get(vendor_key,
                rule_data.get('remediation_cisco', 'Manual remediation required'))

    def get_evidence(self, rule_data):
        """Collect evidence lines from the config"""
        pattern = self.get_check_pattern(rule_data)
        if not pattern:
            return ['No direct evidence found']

        patterns_list = pattern if isinstance(pattern, list) else [pattern]
        evidence = []
        for line in self.config_lines:
            for p in patterns_list:
                if p and p.lower() in line.lower():
                    evidence.append(line.strip())
                    break
        return evidence if evidence else ['No direct evidence found']

    def run_checks(self):
        """Run all compliance checks"""
        self.violations = []
        self.passed_checks = []

        for rule_key, rule_data in Config.COMPLIANCE_RULES.items():
            # Inject rule key for context lookups
            rule_data_copy = dict(rule_data)
            rule_data_copy['_key'] = rule_key

            if self.check_rule(rule_data_copy):
                self.passed_checks.append({
                    'rule': rule_key,
                    'description': rule_data['description'],
                    'nist_control': rule_data.get('nist_control', ''),
                    'cis_benchmark': rule_data.get('cis_benchmark', '')
                })
            else:
                line_number = self.find_violation_line(rule_data_copy)
                line_content = self.get_line_content(line_number)

                self.violations.append({
                    'rule': rule_key,
                    'description': rule_data['description'],
                    'severity': rule_data['severity'],
                    'nist_control': rule_data.get('nist_control', ''),
                    'cis_benchmark': rule_data.get('cis_benchmark', ''),
                    'remediation': self.get_remediation(rule_data),
                    'evidence': self.get_evidence(rule_data_copy),
                    'line_number': line_number,
                    'line_content': line_content
                })

        return self.violations, self.passed_checks

    def get_compliance_score(self):
        """Calculate compliance percentage"""
        total_rules = len(Config.COMPLIANCE_RULES)
        passed = len(self.passed_checks)
        return (passed / total_rules) * 100 if total_rules > 0 else 0