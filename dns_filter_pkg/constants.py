# dns_filter_pkg/constants.py
# -*- coding: utf-8 -*-

import os

# --- Application Constants ---
APP_NAME = "DNSFilter"
CONFIG_DIR_NAME = APP_NAME
PROGRAM_DATA_PATH = os.environ.get('ProgramData', 'C:\\ProgramData')
CONFIG_DIR = os.path.join(PROGRAM_DATA_PATH, CONFIG_DIR_NAME)

CONFIG_FILE_NAME = "config.json"
LOG_FILE_NAME = "dns_filter.log"
HOSTS_BACKUP_FILE_NAME = "hosts.backup"

CONFIG_FILE_PATH = os.path.join(CONFIG_DIR, CONFIG_FILE_NAME)
LOG_FILE_PATH = os.path.join(CONFIG_DIR, LOG_FILE_NAME)
HOSTS_FILE_PATH = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'etc', 'hosts')
HOSTS_BACKUP_PATH = os.path.join(CONFIG_DIR, HOSTS_BACKUP_FILE_NAME)


# --- DNS Servers ---
PRIMARY_DNS_SERVERS = ["185.228.168.168", "185.228.169.168"]
FALLBACK_DNS_SERVERS = ["208.67.222.123", "208.67.220.123"]
INSTALL_DNS_SERVERS = PRIMARY_DNS_SERVERS + FALLBACK_DNS_SERVERS

# --- Firewall Rule Names ---
# Base names for rules. Specific IPs will be appended for allow rules.
FW_RULE_PREFIX = f"{APP_NAME}"
# For Allow rules, we'll generate names like: DNSFilter Allow UDP to 1.1.1.1
FW_RULE_ALLOW_UDP_BASE_NAME = f"{FW_RULE_PREFIX} Allow UDP to " # This line is crucial
FW_RULE_ALLOW_TCP_BASE_NAME = f"{FW_RULE_PREFIX} Allow TCP to " # This line is crucial
# Block rules have fixed names
FW_RULE_BLOCK_UDP_NAME = f"{FW_RULE_PREFIX} Block Other DNS UDP"
FW_RULE_BLOCK_TCP_NAME = f"{FW_RULE_PREFIX} Block Other DNS TCP"

# This list is now more for conceptual grouping; actual rule names for 'allow' are dynamic.
# The remove_firewall_rules function will need to generate the names for allow rules.
# For checking status or initial definition, we list the static block rule names.
# The dynamic allow rule names will be constructed in the firewall_manager.
CONCEPTUAL_FW_RULES_TO_MANAGE = {
    "allow_udp_base": FW_RULE_ALLOW_UDP_BASE_NAME,
    "allow_tcp_base": FW_RULE_ALLOW_TCP_BASE_NAME,
    "block_udp": FW_RULE_BLOCK_UDP_NAME,
    "block_tcp": FW_RULE_BLOCK_TCP_NAME,
}


# --- Scheduled Task ---
TASK_NAME = f"{APP_NAME}Monitor"
DEFAULT_MONITOR_INTERVAL_HOURS = 4

# --- Hosts File SafeSearch Block ---
SAFESEARCH_HOSTS_BEGIN_TAG = f"# BEGIN {APP_NAME} SAFESEARCH BLOCK"
SAFESEARCH_HOSTS_END_TAG = f"# END {APP_NAME} SAFESEARCH BLOCK"
SAFESEARCH_DOMAINS_IPV4 = {
    "0.0.0.0": [
        "www.google.com", 
        "www.google.co.il", 
        "forcesafesearch.google.com", 
        # Corrected invalid host entries from original request
        "googleusercontent.com", # Be cautious with this, might block legitimate content
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "www.youtube-nocookie.com",
    ]
}
SAFESEARCH_DOMAINS_IPV6 = {
    "::1": [ 
        "www.google.com",
        "www.google.co.il",
        "forcesafesearch.google.com",
        "googleusercontent.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "www.youtube-nocookie.com",
    ]
}

# --- Language Support ---
DEFAULT_LANGUAGE = "en"
SUPPORTED_LANGUAGES = ["en", "he"]

# --- Exit Codes ---
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_REQUIRES_ADMIN = 2
EXIT_PASSWORD_MISMATCH = 3
EXIT_INCORRECT_PASSWORD = 4
EXIT_ALREADY_INSTALLED = 5
EXIT_NOT_INSTALLED = 6
EXIT_ADAPTER_NOT_FOUND = 7
EXIT_CONFIG_SAVE_FAILED = 8
EXIT_OPERATION_ABORTED = 9
