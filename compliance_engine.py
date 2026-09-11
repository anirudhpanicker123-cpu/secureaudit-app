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
        vendor_key = f'check_{self.vendor}'
        pattern = rule_data.get(vendor_key)
        if pattern is None:
            pattern = rule_data.get('check_cisco', '')
        return pattern

    def get_check_type(self, rule_data):
        return rule_data.get('check_type', 'positive')

    def find_line_number(self, patterns):
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
        if line_number and 1 <= line_number <= len(self.config_lines):
            return self.config_lines[line_number - 1].strip()
        return None

    def check_rule(self, rule_data):
        pattern = self.get_check_pattern(rule_data)
        check_type = self.get_check_type(rule_data)
        if not pattern:
            return True
        patterns_list = pattern if isinstance(pattern, list) else [pattern]
        found = any(p.lower() in self.config_text.lower() for p in patterns_list if p)
        if check_type == 'negative':
            return not found
        else:
            return found

    def find_violation_line(self, rule_data):
        pattern = self.get_check_pattern(rule_data)
        check_type = self.get_check_type(rule_data)
        if not pattern:
            return None
        patterns_list = pattern if isinstance(pattern, list) else [pattern]
        if check_type == 'negative':
            return self.find_line_number(patterns_list)
        else:
            context_keywords = {
                'ssh_only': ['line vty', 'line con', 'management ssh'],
                'enable_secret': ['hostname', 'config system admin'],
                'logging': ['hostname', 'config log syslogd'],
                'password_encryption': ['username', 'hostname', 'set password-encryption'],
                'banner_motd': ['hostname', 'set pre-login-banner'],
                'ntp_configured': ['hostname', 'set ntp server'],
                'aaa_configured': ['hostname', 'aaa', 'set auth-type'],
                'password_min_length': ['username', 'hostname', 'set password-min-length'],
                'exec_timeout': ['line vty', 'line con', 'set admintimeout'],
                'logging_configured': ['logging', 'hostname', 'set server'],
                'enable_secret_encrypted': ['enable secret', 'enable password', 'set password-encryption'],
                'service_timestamps': ['hostname', 'set log-timestamp']
            }
            rule_key = rule_data.get('_key', '')
            for keyword in context_keywords.get(rule_key, []):
                line_num = self.find_line_number([keyword])
                if line_num:
                    return line_num
            return None

    def get_remediation(self, rule_data):
        vendor_key = f'remediation_{self.vendor}'
        return rule_data.get(vendor_key, rule_data.get('remediation_cisco', 'Manual remediation required'))

    def get_evidence(self, rule_data):
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
        self.violations = []
        self.passed_checks = []
        for rule_key, rule_data in Config.COMPLIANCE_RULES.items():
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
        total_rules = len(Config.COMPLIANCE_RULES)
        passed = len(self.passed_checks)
        return (passed / total_rules) * 100 if total_rules > 0 else 0