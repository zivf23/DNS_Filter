# dns_filter_pkg/main.py
# -*- coding: utf-8 -*-

import datetime
import os
import sys

from .system_utils import _print, log_message, get_localized_string
from .constants import (
    APP_NAME, CONFIG_FILE_PATH, HOSTS_BACKUP_PATH,
    EXIT_SUCCESS, EXIT_ERROR, EXIT_ALREADY_INSTALLED, EXIT_NOT_INSTALLED,
    EXIT_PASSWORD_MISMATCH, EXIT_INCORRECT_PASSWORD, EXIT_OPERATION_ABORTED,
    EXIT_ADAPTER_NOT_FOUND, EXIT_CONFIG_SAVE_FAILED
)
from .config_manager import (
    load_configuration, save_configuration,
    initialize_password_and_config, authenticate_user,
    get_user_defined_monitor_interval
)
from .network_adapter_manager import (
    get_active_network_adapters_ps,
    backup_and_set_dns_for_adapters,
    restore_dns_for_managed_adapters,
    get_dns_settings_ps, 
    check_dns_responsiveness,
    set_dns_servers_ps 
)
# *** FIX: Corrected import from firewall_manager to use firewall_rule_exists_ps ***
from .firewall_manager import (
    add_firewall_rules, remove_firewall_rules, firewall_rule_exists_ps, # Changed here
    get_all_managed_firewall_rule_names 
)
from .task_manager import (
    create_scheduled_task, delete_scheduled_task, scheduled_task_exists, get_task_details
)
from .hosts_manager import (
    backup_hosts_file, restore_hosts_file_from_backup,
    apply_safesearch_to_hosts, remove_safesearch_from_hosts,
    is_safesearch_block_present
)

ENTRY_POINT_SCRIPT_PATH = None

def set_entry_point_script_path(path: str):
    global ENTRY_POINT_SCRIPT_PATH
    ENTRY_POINT_SCRIPT_PATH = path
    log_message(f"Entry point script path set to: {ENTRY_POINT_SCRIPT_PATH}", "DEBUG")

def install_filter_logic() -> int:
    _print("installation_starting", APP_NAME)
    config = load_configuration()
    if config:
        _print("already_installed", APP_NAME)
        return EXIT_ALREADY_INSTALLED

    initial_config = initialize_password_and_config()
    if not initial_config:
        return EXIT_PASSWORD_MISMATCH

    if not backup_hosts_file():
        _print("hosts_file_backup_failed", "Installation aborted.", log_level="ERROR")
        return EXIT_ERROR
    initial_config["hosts_file_backed_up"] = True

    active_adapters = get_active_network_adapters_ps()
    if not active_adapters:
        _print("adapter_not_found")
        if initial_config.get("hosts_file_backed_up"): restore_hosts_file_from_backup()
        return EXIT_ADAPTER_NOT_FOUND

    dns_backup_data, managed_indices = backup_and_set_dns_for_adapters(active_adapters)
    
    if not managed_indices:
        _print("set_dns_failed", APP_NAME, "No adapters could be configured. Installation aborted.", log_level="ERROR")
        if initial_config.get("hosts_file_backed_up"): restore_hosts_file_from_backup()
        return EXIT_ERROR

    initial_config["adapters_backup"] = dns_backup_data
    initial_config["managed_adapters_indices"] = managed_indices

    if not add_firewall_rules():
        _print("firewall_rule_error", APP_NAME, "Firewall setup failed. Rolling back changes.", log_level="CRITICAL")
        restore_dns_for_managed_adapters(managed_indices, dns_backup_data)
        if initial_config.get("hosts_file_backed_up"): restore_hosts_file_from_backup()
        return EXIT_ERROR

    if not apply_safesearch_to_hosts():
        _print("hosts_file_safesearch_apply_failed", "Rolling back changes.", log_level="CRITICAL")
        remove_firewall_rules()
        restore_dns_for_managed_adapters(managed_indices, dns_backup_data)
        if initial_config.get("hosts_file_backed_up"): restore_hosts_file_from_backup()
        return EXIT_ERROR

    if ENTRY_POINT_SCRIPT_PATH is None:
        log_message("CRITICAL: Entry point script path not set for creating scheduled task.", "ERROR")
        remove_safesearch_from_hosts()
        if initial_config.get("hosts_file_backed_up"): restore_hosts_file_from_backup()
        remove_firewall_rules()
        restore_dns_for_managed_adapters(managed_indices, dns_backup_data)
        return EXIT_ERROR

    monitor_interval = initial_config.get("monitor_interval_hours", 4)
    if not create_scheduled_task(monitor_interval, ENTRY_POINT_SCRIPT_PATH):
        _print("task_error", APP_NAME, "Scheduled task setup failed. Rolling back changes.", log_level="CRITICAL")
        remove_safesearch_from_hosts()
        if initial_config.get("hosts_file_backed_up"): restore_hosts_file_from_backup()
        remove_firewall_rules()
        restore_dns_for_managed_adapters(managed_indices, dns_backup_data)
        return EXIT_ERROR

    if not save_configuration(initial_config):
        _print("error_saving_config", CONFIG_FILE_PATH, "CRITICAL: Config not saved. Rolling back all changes.", log_level="CRITICAL")
        delete_scheduled_task()
        remove_safesearch_from_hosts()
        if initial_config.get("hosts_file_backed_up"): restore_hosts_file_from_backup()
        remove_firewall_rules()
        restore_dns_for_managed_adapters(managed_indices, dns_backup_data)
        return EXIT_CONFIG_SAVE_FAILED

    _print("installation_complete", APP_NAME)
    return EXIT_SUCCESS

def uninstall_filter_logic() -> int:
    _print("uninstallation_starting", APP_NAME)
    config = load_configuration()
    if not config:
        _print("not_installed_error", APP_NAME)
        return EXIT_NOT_INSTALLED

    if not authenticate_user(config, "action_uninstall"):
        return EXIT_INCORRECT_PASSWORD

    if not delete_scheduled_task():
        _print("task_error", APP_NAME, "Failed to delete scheduled task. Continuing uninstall.", log_level="WARNING")

    if not remove_safesearch_from_hosts():
        _print("hosts_file_safesearch_remove_failed", "Continuing uninstall.", log_level="WARNING")

    if config.get("hosts_file_backed_up", False):
        if not restore_hosts_file_from_backup():
            _print("hosts_file_restore_failed", "Hosts file may need manual restoration.", log_level="WARNING")
    else:
        log_message("No record of hosts file being backed up. Skipping restore from backup.", "INFO")

    if not remove_firewall_rules():
        _print("firewall_rule_error", APP_NAME, "Failed to remove all firewall rules. Continuing uninstall.", log_level="WARNING")

    managed_indices = config.get("managed_adapters_indices", [])
    adapters_backup = config.get("adapters_backup", {})
    
    adapters_backup_int_keys = {}
    for k, v in adapters_backup.items():
        try:
            adapters_backup_int_keys[int(k)] = v
        except ValueError:
            log_message(f"Warning: Invalid non-integer key '{k}' found in adapters_backup.", "WARNING")

    if managed_indices:
        if not restore_dns_for_managed_adapters(managed_indices, adapters_backup_int_keys):
            _print("restore_dns_failed", APP_NAME, "Some adapters may need manual DNS restoration.", log_level="WARNING")
    else:
        _print("no_managed_adapters", log_level="INFO")

    try:
        if os.path.exists(CONFIG_FILE_PATH):
            os.remove(CONFIG_FILE_PATH)
            log_message(f"Configuration file {CONFIG_FILE_PATH} deleted.", "INFO")
        if os.path.exists(HOSTS_BACKUP_PATH):
            os.remove(HOSTS_BACKUP_PATH)
            log_message(f"Hosts backup file {HOSTS_BACKUP_PATH} deleted.", "INFO")
        
        config_dir_path = os.path.dirname(CONFIG_FILE_PATH)
        if os.path.exists(config_dir_path) and not os.listdir(config_dir_path):
            try:
                os.rmdir(config_dir_path)
                log_message(f"Configuration directory {config_dir_path} removed.", "INFO")
            except OSError as e:
                log_message(f"Could not remove configuration directory {config_dir_path}: {e}", "WARNING")
    except OSError as e:
        _print("error_saving_config", f"(could not delete config/backup files): {e}", log_level="WARNING")

    _print("uninstallation_complete", APP_NAME)
    return EXIT_SUCCESS

def show_status_logic() -> int:
    _print("status_checking", APP_NAME)
    config = load_configuration()
    if not config:
        _print("not_installed_error", APP_NAME)
        return EXIT_NOT_INSTALLED

    _print("status_installed_on", APP_NAME, config.get("install_date", "N/A"))
    _print("status_config_file_path", CONFIG_FILE_PATH)

    _print("status_adapters_dns_header")
    managed_indices = config.get("managed_adapters_indices", [])
    adapters_backup_info = config.get("adapters_backup", {})
    adapters_backup_int_keys = {int(k): v for k, v in adapters_backup_info.items() if k.isdigit()}


    if not managed_indices:
        _print("no_managed_adapters")
    else:
        adapter_table_data = []
        headers = [
            get_localized_string("status_table_header_adapter"),
            get_localized_string("status_table_header_index"),
            get_localized_string("status_table_header_dns"),
            get_localized_string("status_table_header_dns_type")
        ]
        
        for index in managed_indices:
            index_key = int(index)
            original_name = adapters_backup_int_keys.get(index_key, {}).get("original_name", "Unknown")
            current_dns_settings = get_dns_settings_ps(index_key)
            
            if current_dns_settings:
                dns_type = "DHCP" if current_dns_settings.get("dhcp") else "Static"
                servers = ", ".join(current_dns_settings.get("servers", [])) or "N/A"
                adapter_table_data.append([original_name, index_key, servers, dns_type])
            else:
                adapter_table_data.append([original_name, index_key, "Error fetching", "N/A"])
        
        if adapter_table_data:
            col_widths = [len(h) for h in headers]
            for row in adapter_table_data:
                for i, cell in enumerate(row):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
            
            header_line = " | ".join(str(h).ljust(col_widths[i]) for i, h in enumerate(headers))
            print(header_line)
            print("-" * len(header_line))
            for row in adapter_table_data:
                row_line = " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
                print(row_line)
        else:
             _print("no_managed_adapters")

    # --- Firewall Status (Corrected) ---
    _print("status_firewall_rules_header")
    all_managed_rules = get_all_managed_firewall_rule_names()
    if not all_managed_rules:
        log_message("No managed firewall rule names generated for status check.", "WARNING")
    for rule_name in all_managed_rules:
        # *** FIX: Use firewall_rule_exists_ps ***
        if firewall_rule_exists_ps(rule_name): 
            _print("status_firewall_rule_present", rule_name)
        else:
            _print("status_firewall_rule_missing", rule_name)

    _print("status_scheduled_task_header")
    task_interval = config.get("monitor_interval_hours", "N/A")
    if scheduled_task_exists():
        _print("status_task_present", TASK_NAME, task_interval)
        task_details = get_task_details()
        if task_details:
            for key, value in task_details.items():
                print(f"    {key}: {value}")
    else:
        _print("status_task_missing", TASK_NAME)

    _print("status_hosts_file_header")
    if is_safesearch_block_present():
        _print("hosts_file_safesearch_block_present")
    else:
        _print("hosts_file_safesearch_block_missing")
    if os.path.exists(HOSTS_BACKUP_PATH):
        print(f"  {get_localized_string('hosts_file_backup_present_status', HOSTS_BACKUP_PATH)}")
    else:
        print(f"  {get_localized_string('hosts_file_backup_missing_status', HOSTS_BACKUP_PATH)}")

    _print("status_last_monitor_run", config.get("last_monitor_run", "N/A"))
    _print("status_last_monitor_status", config.get("last_monitor_status", "N/A"))

    return EXIT_SUCCESS

def monitor_dns_logic() -> int:
    log_message("DNS Monitor task started.", "INFO")
    config = load_configuration()
    if not config:
        _print("monitor_no_config", log_level="ERROR")
        return EXIT_ERROR

    from .constants import PRIMARY_DNS_SERVERS, FALLBACK_DNS_SERVERS

    _print("monitor_checking_dns", ", ".join(PRIMARY_DNS_SERVERS))
    
    primary_dns_is_ok = False
    for dns_ip in PRIMARY_DNS_SERVERS:
        if check_dns_responsiveness(dns_ip, domain_to_check="services.googleapis.com"):
            primary_dns_is_ok = True
            log_message(f"Monitor: Primary DNS server {dns_ip} is responsive.", "INFO")
            break
    
    current_status_msg = ""
    if primary_dns_is_ok:
        _print("monitor_dns_ok")
        current_status_msg = f"OK - Primary DNS ({', '.join(PRIMARY_DNS_SERVERS)}) responsive."
    else:
        _print("monitor_dns_fail", ", ".join(FALLBACK_DNS_SERVERS))
        current_status_msg = f"Primary DNS unresponsive. Attempting to revert to Fallback DNS ({', '.join(FALLBACK_DNS_SERVERS)})."
        
        managed_indices = config.get("managed_adapters_indices", [])
        adapters_backup_info = config.get("adapters_backup", {})
        adapters_backup_int_keys = {int(k): v for k, v in adapters_backup_info.items() if k.isdigit()}


        if not managed_indices:
            _print("monitor_no_adapters_in_config", log_level="WARNING")
            current_status_msg += " Error: No managed adapters in config to revert."
        else:
            all_reverted_successfully = True
            for index in managed_indices:
                index_key = int(index)
                adapter_name = adapters_backup_int_keys.get(index_key, {}).get("original_name", f"Index {index_key}")
                
                _print("set_dns_for_adapter", adapter_name, FALLBACK_DNS_SERVERS)
                if not set_dns_servers_ps(index_key, FALLBACK_DNS_SERVERS): 
                    log_message(f"Monitor: Failed to set fallback DNS for adapter {adapter_name} (Index {index_key})", "ERROR")
                    all_reverted_successfully = False
                else:
                     _print("monitor_reverted_dns", ", ".join(FALLBACK_DNS_SERVERS), adapter_name)

            if all_reverted_successfully:
                 current_status_msg += " Successfully reverted all managed adapters to Fallback DNS."
            else:
                 current_status_msg += " Error: Failed to revert some/all adapters to Fallback DNS."

    config["last_monitor_run"] = datetime.datetime.now().isoformat()
    config["last_monitor_status"] = current_status_msg
    if not save_configuration(config):
        log_message("Monitor: Failed to save updated config after monitor run.", "ERROR")
        return EXIT_ERROR

    log_message(f"DNS Monitor task finished. Status: {current_status_msg}", "INFO")
    return EXIT_SUCCESS
