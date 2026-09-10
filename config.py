# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-12345'
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'conf', 'cfg', 'config'}
    ALLOWED_ZIP = {'zip'}
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB for ZIP uploads

    GROQ_API_KEY = os.environ.get('GROQ_API_KEY') or 'your-groq-api-key-here'

    COMPLIANCE_RULES = {
        'enable_secret': {
            'description': 'Enable secret password must be set',
            'check_type': 'positive',
            'check_cisco': 'enable secret',
            'check_juniper': 'set system root-authentication',
            'check_arista': 'enable secret',
            'severity': 'HIGH',
            'nist_control': 'NIST SP 800-53 IA-5',
            'cis_benchmark': 'CIS 1.1.1',
            'remediation_cisco': 'enable secret <strong-password>',
            'remediation_juniper': 'set system root-authentication plain-text-password',
            'remediation_arista': 'enable secret <strong-password>'
        },
        'ssh_only': {
            'description': 'SSH must be used instead of Telnet',
            'check_type': 'positive',
            'check_cisco': 'transport input ssh',
            'check_juniper': 'set system services ssh',
            'check_arista': 'management ssh',
            'severity': 'HIGH',
            'nist_control': 'NIST SP 800-53 SC-8',
            'cis_benchmark': 'CIS 2.4',
            'remediation_cisco': 'transport input ssh',
            'remediation_juniper': 'set system services ssh',
            'remediation_arista': 'management ssh'
        },
        'logging': {
            'description': 'Logging must be enabled',
            'check_type': 'positive',
            'check_cisco': 'logging',
            'check_juniper': 'set system syslog',
            'check_arista': 'logging',
            'severity': 'MEDIUM',
            'nist_control': 'NIST SP 800-53 AU-2',
            'cis_benchmark': 'CIS 8.2',
            'remediation_cisco': 'logging <server-ip>',
            'remediation_juniper': 'set system syslog host <server-ip>',
            'remediation_arista': 'logging host <server-ip>'
        },
        'password_encryption': {
            'description': 'Passwords should be encrypted with service password-encryption',
            'check_type': 'positive',
            'check_cisco': 'service password-encryption',
            'check_juniper': 'set system authentication-order password',
            'check_arista': 'service password-encryption',
            'severity': 'MEDIUM',
            'nist_control': 'NIST SP 800-53 IA-5',
            'cis_benchmark': 'CIS 1.1.2',
            'remediation_cisco': 'service password-encryption',
            'remediation_juniper': 'set system authentication-order password',
            'remediation_arista': 'service password-encryption'
        },
        'no_default_snmp': {
            'description': 'Default SNMP community strings (public/private) must be changed',
            'check_type': 'negative',
            'check_cisco': ['snmp-server community public', 'snmp-server community private'],
            'check_juniper': ['set snmp community public', 'set snmp community private'],
            'check_arista': ['snmp-server community public', 'snmp-server community private'],
            'severity': 'HIGH',
            'nist_control': 'NIST SP 800-53 SC-8',
            'cis_benchmark': 'CIS 2.7',
            'remediation_cisco': 'no snmp-server community public',
            'remediation_juniper': 'delete snmp community public',
            'remediation_arista': 'no snmp-server community public'
        },
        'no_telnet': {
            'description': 'Telnet must be disabled (use SSH instead)',
            'check_type': 'negative',
            'check_cisco': ['transport input telnet', 'transport input all'],
            'check_juniper': ['set system services telnet'],
            'check_arista': ['management telnet', 'transport input telnet', 'transport input all'],
            'severity': 'HIGH',
            'nist_control': 'NIST SP 800-53 SC-8',
            'cis_benchmark': 'CIS 2.4',
            'remediation_cisco': 'transport input ssh',
            'remediation_juniper': 'delete system services telnet',
            'remediation_arista': 'management ssh'
        },
        'no_http_server': {
            'description': 'HTTP server should be disabled (use HTTPS)',
            'check_type': 'negative',
            'check_cisco': ['ip http server'],
            'check_juniper': ['set system services web-management http'],
            'check_arista': ['ip http server', 'management api http-commands'],
            'severity': 'HIGH',
            'nist_control': 'NIST SP 800-53 SC-8',
            'cis_benchmark': 'CIS 2.6',
            'remediation_cisco': 'no ip http server',
            'remediation_juniper': 'delete system services web-management http',
            'remediation_arista': 'no management api http-commands'
        },
        'banner_motd': {
            'description': 'Login banner (MOTD) must be configured',
            'check_type': 'positive',
            'check_cisco': 'banner motd',
            'check_juniper': 'set system login message',
            'check_arista': 'banner motd',
            'severity': 'MEDIUM',
            'nist_control': 'NIST SP 800-53 AC-8',
            'cis_benchmark': 'CIS 1.7',
            'remediation_cisco': 'banner motd ^C Authorized Access Only ^C',
            'remediation_juniper': 'set system login message "Authorized Access Only"',
            'remediation_arista': 'banner motd ^C Authorized Access Only ^C'
        },
        'no_cdp': {
            'description': 'CDP/LLDP should be disabled on external interfaces',
            'check_type': 'negative',
            'check_cisco': ['cdp run'],
            'check_juniper': ['set protocols cdp'],
            'check_arista': ['lldp run'],
            'severity': 'MEDIUM',
            'nist_control': 'NIST SP 800-53 SC-7',
            'cis_benchmark': 'CIS 2.5',
            'remediation_cisco': 'no cdp run',
            'remediation_juniper': 'delete protocols cdp',
            'remediation_arista': 'no lldp run'
        },
        'ntp_configured': {
            'description': 'NTP must be configured for accurate logging',
            'check_type': 'positive',
            'check_cisco': 'ntp server',
            'check_juniper': 'set system ntp server',
            'check_arista': 'ntp server',
            'severity': 'MEDIUM',
            'nist_control': 'NIST SP 800-53 AU-8',
            'cis_benchmark': 'CIS 8.4',
            'remediation_cisco': 'ntp server <ntp-server-ip>',
            'remediation_juniper': 'set system ntp server <ntp-server-ip>',
            'remediation_arista': 'ntp server <ntp-server-ip>'
        },
        'aaa_configured': {
            'description': 'AAA authentication must be enabled',
            'check_type': 'positive',
            'check_cisco': 'aaa new-model',
            'check_juniper': 'set system authentication-order',
            'check_arista': 'aaa authentication',
            'severity': 'HIGH',
            'nist_control': 'NIST SP 800-53 IA-2',
            'cis_benchmark': 'CIS 1.2',
            'remediation_cisco': 'aaa new-model',
            'remediation_juniper': 'set system authentication-order radius',
            'remediation_arista': 'aaa authentication login default local'
        },
        'password_min_length': {
            'description': 'Minimum password length must be at least 8',
            'check_type': 'positive',
            'check_cisco': 'security passwords min-length',
            'check_juniper': 'set system login password minimum-length',
            'check_arista': 'security passwords min-length',
            'severity': 'MEDIUM',
            'nist_control': 'NIST SP 800-53 IA-5',
            'cis_benchmark': 'CIS 1.1.3',
            'remediation_cisco': 'security passwords min-length 8',
            'remediation_juniper': 'set system login password minimum-length 8',
            'remediation_arista': 'security passwords min-length 8'
        },
        'exec_timeout': {
            'description': 'EXEC timeout must be configured (max 10 minutes)',
            'check_type': 'positive',
            'check_cisco': 'exec-timeout',
            'check_juniper': 'set system login idle-timeout',
            'check_arista': 'exec-timeout',
            'severity': 'LOW',
            'nist_control': 'NIST SP 800-53 AC-12',
            'cis_benchmark': 'CIS 1.4',
            'remediation_cisco': 'exec-timeout 10 0',
            'remediation_juniper': 'set system login idle-timeout 10',
            'remediation_arista': 'exec-timeout 10 0'
        },
        'no_ip_source_route': {
            'description': 'IP source routing must be disabled',
            'check_type': 'positive',
            'check_cisco': 'no ip source-route',
            'check_juniper': 'set system no-source-route',
            'check_arista': 'no ip source-route',
            'severity': 'HIGH',
            'nist_control': 'NIST SP 800-53 SC-7',
            'cis_benchmark': 'CIS 3.2',
            'remediation_cisco': 'no ip source-route',
            'remediation_juniper': 'set system no-source-route',
            'remediation_arista': 'no ip source-route'
        },
        'logging_configured': {
            'description': 'Logging must be sent to a remote syslog server',
            'check_type': 'positive',
            'check_cisco': 'logging host',
            'check_juniper': 'set system syslog host',
            'check_arista': 'logging host',
            'severity': 'MEDIUM',
            'nist_control': 'NIST SP 800-53 AU-4',
            'cis_benchmark': 'CIS 8.2',
            'remediation_cisco': 'logging host <syslog-server-ip>',
            'remediation_juniper': 'set system syslog host <syslog-server-ip>',
            'remediation_arista': 'logging host <syslog-server-ip>'
        },
        'no_aux_port': {
            'description': 'Auxiliary port must be disabled',
            'check_type': 'negative',
            'check_cisco': ['line aux 0', 'line aux 1'],
            'check_juniper': [],
            'check_arista': ['line aux 0'],
            'severity': 'LOW',
            'nist_control': 'NIST SP 800-53 AC-17',
            'cis_benchmark': 'CIS 1.6',
            'remediation_cisco': 'line aux 0\n no exec\n transport input none',
            'remediation_juniper': 'N/A - no aux port on Junos',
            'remediation_arista': 'line aux 0\n no exec'
        },
        'enable_secret_encrypted': {
            'description': 'Enable secret must be encrypted (type 5 or higher)',
            'check_type': 'positive',
            'check_cisco': 'enable secret 5',
            'check_juniper': 'set system root-authentication encrypted-password',
            'check_arista': 'enable secret 5',
            'severity': 'HIGH',
            'nist_control': 'NIST SP 800-53 IA-5',
            'cis_benchmark': 'CIS 1.1.1',
            'remediation_cisco': 'enable secret <strong-password>',
            'remediation_juniper': 'set system root-authentication encrypted-password <hash>',
            'remediation_arista': 'enable secret <strong-password>'
        },
        'service_timestamps': {
            'description': 'Timestamps must be enabled for logging',
            'check_type': 'positive',
            'check_cisco': 'service timestamps',
            'check_juniper': 'set system syslog time-format',
            'check_arista': 'service timestamps',
            'severity': 'LOW',
            'nist_control': 'NIST SP 800-53 AU-8',
            'cis_benchmark': 'CIS 8.1',
            'remediation_cisco': 'service timestamps log datetime msec',
            'remediation_juniper': 'set system syslog time-format',
            'remediation_arista': 'service timestamps log datetime msec'
        }
    }