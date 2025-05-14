# dns_filter_pkg/firewall_manager.py
# -*- coding: utf-8 -*-

from .system_utils import _print, log_message, run_powershell_command
from .constants import (
    INSTALL_DNS_SERVERS,
    FW_RULE_ALLOW_UDP_BASE_NAME,
    FW_RULE_ALLOW_TCP_BASE_NAME,
    FW_RULE_BLOCK_UDP_NAME, # Still needed for get_all_managed and remove cleanup
    FW_RULE_BLOCK_TCP_NAME, # Still needed for get_all_managed and remove cleanup
    APP_NAME
)

def _generate_allow_rule_name(base_name: str, ip_address: str) -> str:
    """Generates a firewall rule name. PowerShell DisplayName can handle spaces."""
    return f"{base_name}{ip_address}"

def firewall_rule_exists_ps(rule_display_name: str) -> bool:
    """Checks if a firewall rule with the given DisplayName exists using PowerShell."""
    ps_command = f"Get-NetFirewallRule -DisplayName '{rule_display_name}' -ErrorAction SilentlyContinue"
    success, stdout, stderr, rc = run_powershell_command(ps_command, check_errors=False, suppress_output=True)
    
    if stdout and success:
        log_message(f"Firewall rule '{rule_display_name}' found via PowerShell.", "DEBUG")
        return True
    log_message(f"Firewall rule '{rule_display_name}' not found via PowerShell (rc={rc}, stdout='{stdout}', stderr='{stderr}').", "DEBUG")
    return False

def add_firewall_rules() -> bool:
    """
    Adds firewall ALLOW rules using PowerShell's New-NetFirewallRule.
    BLOCK rules are NOT created in this version.
    """
    all_rules_succeeded = True
    _print("firewall_creating_allow_rules_only", log_level="INFO") 

    for dns_ip in INSTALL_DNS_SERVERS:
        # Allow UDP rule
        allow_udp_rule_name = _generate_allow_rule_name(FW_RULE_ALLOW_UDP_BASE_NAME, dns_ip)
        allow_udp_params = {
            "DisplayName": allow_udp_rule_name,
            "Description": f"{APP_NAME}: Allow outgoing UDP DNS to {dns_ip}",
            "Direction": "Outbound", "Action": "Allow", "Protocol": "UDP",
            "RemotePort": "53", "RemoteAddress": dns_ip, "Enabled": "True", "Profile": "Any"
        }
        if not _add_single_firewall_rule_ps(allow_udp_params):
            all_rules_succeeded = False

        # Allow TCP rule
        allow_tcp_rule_name = _generate_allow_rule_name(FW_RULE_ALLOW_TCP_BASE_NAME, dns_ip)
        allow_tcp_params = {
            "DisplayName": allow_tcp_rule_name,
            "Description": f"{APP_NAME}: Allow outgoing TCP DNS to {dns_ip}",
            "Direction": "Outbound", "Action": "Allow", "Protocol": "TCP",
            "RemotePort": "53", "RemoteAddress": dns_ip, "Enabled": "True", "Profile": "Any"
        }
        if not _add_single_firewall_rule_ps(allow_tcp_params):
            all_rules_succeeded = False

    _print("firewall_block_rules_skipped_allow_only", log_level="INFO")
            
    return all_rules_succeeded

def _add_single_firewall_rule_ps(rule_params: dict) -> bool:
    """Helper function to add a single firewall rule using PowerShell."""
    rule_display_name = rule_params["DisplayName"]
    _print("firewall_rule_creating", rule_display_name)

    if firewall_rule_exists_ps(rule_display_name):
        log_message(f"Rule '{rule_display_name}' already exists. Removing before re-adding.", "DEBUG")
        if not _remove_single_firewall_rule_ps(rule_display_name): # Ensure removal is also PowerShell based
            log_message(f"Failed to remove existing rule '{rule_display_name}' before re-adding.", "WARNING")
            # Decide if this should be a hard fail or proceed
    
    ps_command_parts = ["New-NetFirewallRule"]
    for key, value in rule_params.items():
        if key == "RemoteAddress" and value == "Any":
            ps_command_parts.append(f"-{key} {value}") 
        elif isinstance(value, str): 
            ps_command_parts.append(f"-{key} '{value}'")
        elif isinstance(value, bool): 
            ps_command_parts.append(f"-{key} ${str(value).lower()}")
        else: 
             ps_command_parts.append(f"-{key} {value}")
    
    ps_command = " ".join(ps_command_parts)
    ps_command += " -ErrorAction Stop"

    log_message(f"Constructed PowerShell firewall command: {ps_command}", "DEBUG")
    success, stdout, stderr, rc = run_powershell_command(ps_command, check_errors=True)
    
    if success:
        _print("firewall_rule_created", rule_display_name)
        return True
    else:
        _print("firewall_rule_error", rule_display_name, stderr if stderr else stdout, log_level="ERROR")
        return False

def remove_firewall_rules() -> bool:
    """Removes firewall ALLOW rules and attempts to clean up any potential BLOCK rules."""
    all_removed_successfully = True
    _print("firewall_removing_allow_rules_only", log_level="INFO") 

    for dns_ip in INSTALL_DNS_SERVERS:
        allow_udp_rule_name = _generate_allow_rule_name(FW_RULE_ALLOW_UDP_BASE_NAME, dns_ip)
        if not _remove_single_firewall_rule_ps(allow_udp_rule_name):
            all_removed_successfully = False
        
        allow_tcp_rule_name = _generate_allow_rule_name(FW_RULE_ALLOW_TCP_BASE_NAME, dns_ip)
        if not _remove_single_firewall_rule_ps(allow_tcp_rule_name):
            all_removed_successfully = False

    # Attempt to remove BLOCK rules as well, in case they exist from a previous full version
    _print("firewall_attempt_remove_block_rules_cleanup", log_level="INFO")
    if firewall_rule_exists_ps(FW_RULE_BLOCK_UDP_NAME):
        if not _remove_single_firewall_rule_ps(FW_RULE_BLOCK_UDP_NAME):
            all_removed_successfully = False 
    if firewall_rule_exists_ps(FW_RULE_BLOCK_TCP_NAME):
        if not _remove_single_firewall_rule_ps(FW_RULE_BLOCK_TCP_NAME):
            all_removed_successfully = False
        
    return all_removed_successfully

def _remove_single_firewall_rule_ps(rule_display_name: str) -> bool:
    """Helper function to remove a single firewall rule using PowerShell."""
    _print("firewall_rule_deleting", rule_display_name)
    if firewall_rule_exists_ps(rule_display_name):
        ps_command = f"Remove-NetFirewallRule -DisplayName '{rule_display_name}' -ErrorAction Stop"
        log_message(f"Constructed PowerShell firewall removal command: {ps_command}", "DEBUG")
        success, stdout, stderr, rc = run_powershell_command(ps_command, check_errors=True)
        if success:
            _print("firewall_rule_deleted", rule_display_name)
            return True
        else:
            _print("firewall_rule_error", rule_display_name, f"(deletion failed) {stderr if stderr else stdout}", log_level="WARNING")
            return False
    else:
        _print("status_firewall_rule_missing", rule_display_name, log_level="DEBUG")
        return True

def get_all_managed_firewall_rule_names() -> list[str]:
    """Generates all firewall rule DisplayNames that this version *would* manage (ALLOW rules only for now)."""
    rule_names = []
    for dns_ip in INSTALL_DNS_SERVERS:
        rule_names.append(_generate_allow_rule_name(FW_RULE_ALLOW_UDP_BASE_NAME, dns_ip))
        rule_names.append(_generate_allow_rule_name(FW_RULE_ALLOW_TCP_BASE_NAME, dns_ip))
    # Not adding block rule names as they are not actively created in this version for status check
    return rule_names
