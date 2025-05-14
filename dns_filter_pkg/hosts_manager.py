# dns_filter_pkg/hosts_manager.py
# -*- coding: utf-8 -*-

import os
import shutil 

from .system_utils import _print, log_message, run_command
from .constants import (
    HOSTS_FILE_PATH,
    HOSTS_BACKUP_PATH,
    # SAFESEARCH_HOSTS_BEGIN_TAG, # Not used in this diagnostic version
    # SAFESEARCH_HOSTS_END_TAG,   # Not used
    # SAFESEARCH_DOMAINS_IPV4,    # Not used
    # SAFESEARCH_DOMAINS_IPV6,    # Not used
    # APP_NAME                    # Not directly used here, but good for consistency
)

def backup_hosts_file() -> bool:
    """
    Creates a backup of the current hosts file.
    (This function remains active for safety).
    """
    _print("hosts_file_backup_creating", HOSTS_BACKUP_PATH)
    try:
        if not os.path.exists(HOSTS_FILE_PATH):
            _print("file_not_found", HOSTS_FILE_PATH, log_level="ERROR")
            return False
        backup_dir = os.path.dirname(HOSTS_BACKUP_PATH)
        if not os.path.exists(backup_dir):
            try:
                os.makedirs(backup_dir, exist_ok=True)
            except OSError as e:
                _print("error_creating_directory", backup_dir, str(e), log_level="ERROR")
                return False
        shutil.copy2(HOSTS_FILE_PATH, HOSTS_BACKUP_PATH)
        _print("hosts_file_backup_success")
        log_message(f"Hosts file backed up from '{HOSTS_FILE_PATH}' to '{HOSTS_BACKUP_PATH}'.", "INFO")
        return True
    except IOError as e:
        _print("hosts_file_backup_failed", str(e), log_level="ERROR")
        return False
    except Exception as e:
        _print("hosts_file_backup_failed", f"Unexpected error: {str(e)}", log_level="ERROR")
        return False

def restore_hosts_file_from_backup() -> bool:
    """
    Restores the hosts file from the backup.
    (This function remains active for safety).
    """
    _print("hosts_file_restore_from_backup", HOSTS_BACKUP_PATH)
    if not os.path.exists(HOSTS_BACKUP_PATH):
        _print("file_not_found", HOSTS_BACKUP_PATH, log_level="WARNING")
        _print("hosts_file_restore_failed", "Backup file does not exist.", log_level="WARNING")
        return False
    try:
        shutil.copy2(HOSTS_BACKUP_PATH, HOSTS_FILE_PATH)
        _print("hosts_file_restore_success")
        log_message(f"Hosts file restored from '{HOSTS_BACKUP_PATH}' to '{HOSTS_FILE_PATH}'.", "INFO")
        flush_dns_cache()
        return True
    except IOError as e:
        _print("hosts_file_restore_failed", str(e), log_level="ERROR")
        return False
    except Exception as e:
        _print("hosts_file_restore_failed", f"Unexpected error: {str(e)}", log_level="ERROR")
        return False

def read_hosts_content() -> list[str] | None:
    """Reads the content of the hosts file. (Kept for potential future use/diagnostics)."""
    try:
        with open(HOSTS_FILE_PATH, 'r', encoding='utf-8') as f:
            return f.readlines()
    except IOError as e:
        _print("error_reading_file", HOSTS_FILE_PATH, str(e), log_level="ERROR")
        return None

def write_hosts_content(lines: list[str]) -> bool:
    """Writes the given lines to the hosts file. (Kept for potential future use/diagnostics)."""
    try:
        with open(HOSTS_FILE_PATH, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        flush_dns_cache()
        return True
    except IOError as e:
        _print("error_writing_file", HOSTS_FILE_PATH, str(e), log_level="ERROR")
        _print("hosts_file_not_writeable", HOSTS_FILE_PATH, log_level="ERROR")
        return False

def is_safesearch_block_present(hosts_lines: list[str] = None) -> bool:
    """DIAGNOSTIC: Always returns False as no block is applied."""
    log_message("Hosts (DIAGNOSTIC - NO-OP): is_safesearch_block_present called - returning False.", "DEBUG")
    return False

def apply_safesearch_to_hosts() -> bool:
    """
    DIAGNOSTIC VERSION: DOES NOTHING.
    Simulates successful application of SafeSearch block for diagnostic purposes.
    """
    _print("hosts_file_diagnostic_mode_noop_apply", log_level="WARNING") # Add this string
    log_message("Hosts (DIAGNOSTIC - NO-OP): apply_safesearch_to_hosts called, doing nothing and returning True.", "INFO")
    return True # Simulate success

def remove_safesearch_from_hosts() -> bool:
    """
    DIAGNOSTIC VERSION: DOES NOTHING.
    Simulates successful removal of SafeSearch block for diagnostic purposes.
    """
    _print("hosts_file_diagnostic_mode_noop_remove", log_level="WARNING") # Add this string
    log_message("Hosts (DIAGNOSTIC - NO-OP): remove_safesearch_from_hosts called, doing nothing and returning True.", "INFO")
    return True # Simulate success

def flush_dns_cache() -> bool:
    """Flushes the system's DNS cache."""
    log_message("Flushing DNS cache...", "INFO")
    cmd = ["ipconfig", "/flushdns"]
    success, stdout, stderr, rc = run_command(cmd, check_errors=True, suppress_output=False)
    if success:
        log_message(f"DNS cache flushed successfully. Output: {stdout}", "INFO")
        return True
    else:
        log_message(f"Failed to flush DNS cache. RC={rc}. Error: {stderr}", "ERROR")
        return False
