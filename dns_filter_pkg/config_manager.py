# dns_filter_pkg/config_manager.py
# -*- coding: utf-8 -*-

import hashlib
import json
import os
import secrets
import getpass
import datetime # Added missing import

from .constants import (
    CONFIG_FILE_PATH, APP_NAME, DEFAULT_MONITOR_INTERVAL_HOURS, EXIT_OPERATION_ABORTED
)
from .system_utils import _print, log_message, get_localized_string # Relative import

def hash_password(password: str, salt: bytes = None) -> tuple[str, bytes]:
    """
    Hashes a password using PBKDF2-HMAC-SHA256.
    Returns (hex_encoded_hash, salt_bytes).
    """
    if salt is None:
        salt = secrets.token_bytes(16) # Generate a new 16-byte salt
    # NIST recommends at least 10,000 iterations. 100,000 is a common default.
    # dklen = 32 for SHA-256 (256 bits = 32 bytes)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    return pwd_hash.hex(), salt

def verify_password(stored_password_hash_hex: str, salt_hex: str, provided_password: str) -> bool:
    """
    Verifies a provided password against a stored hash and salt.
    Uses secrets.compare_digest for timing attack resistance.
    """
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        log_message("Invalid salt_hex format during password verification.", "ERROR")
        return False # Salt hex is malformed

    # Hash the provided password with the stored salt
    provided_hash_bytes, _ = hash_password(provided_password, salt)
    
    # Compare the hex representation of the newly hashed password with the stored one
    # Ensure both are strings before comparison
    return secrets.compare_digest(str(provided_hash_bytes), str(stored_password_hash_hex))

def get_password_from_user_prompt(prompt_key: str, action_key: str = "") -> str | None:
    """
    Gets password from user securely using getpass.
    Returns the password string or None if input is aborted (e.g., Ctrl+C).
    """
    action_str = get_localized_string(action_key) if action_key else ""
    prompt_str_template = get_localized_string(prompt_key)
    
    prompt_display = prompt_str_template.format(action_str) if action_str and "{}" in prompt_str_template else prompt_str_template

    try:
        password = getpass.getpass(prompt_display)
        if not password: # User might have just pressed Enter
            _print("password_mismatch", log_level="WARNING") # Or a more specific "password_empty"
            return None
        return password
    except KeyboardInterrupt:
        _print("operation_aborted", log_level="WARNING")
        # Propagate the interruption or handle as an exit
        # For now, returning None and letting caller decide.
        # Consider sys.exit(EXIT_OPERATION_ABORTED) here or in caller.
        return None
    except EOFError: # Can happen if input stream is closed (e.g. piping)
        _print("operation_aborted", log_level="WARNING")
        return None


def load_configuration() -> dict | None:
    """Loads the configuration from the JSON file."""
    if not os.path.exists(CONFIG_FILE_PATH):
        log_message(f"Configuration file {CONFIG_FILE_PATH} not found.", "DEBUG")
        return None # No config file exists
    try:
        with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
            config = json.load(f)
        _print("config_loaded", CONFIG_FILE_PATH, log_level="DEBUG")
        return config
    except (IOError, json.JSONDecodeError) as e:
        _print("error_loading_config", CONFIG_FILE_PATH, str(e), log_level="ERROR")
        # Consider if a corrupted config file should be handled differently (e.g., backup and recreate)
        return None # Indicates error or corrupted config

def save_configuration(config_data: dict) -> bool:
    """Saves the configuration to the JSON file."""
    try:
        # Ensure CONFIG_DIR exists (should be created by setup_logging_and_localization)
        # os.makedirs(os.path.dirname(CONFIG_FILE_PATH), exist_ok=True) # Redundant if setup ran
        with open(CONFIG_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=4, ensure_ascii=False)
        _print("config_saved", CONFIG_FILE_PATH, log_level="INFO")
        return True
    except IOError as e:
        _print("error_saving_config", CONFIG_FILE_PATH, str(e), log_level="ERROR")
        return False

def get_user_defined_monitor_interval(config: dict = None) -> int:
    """
    Gets the monitor interval.
    1. From existing config if available.
    2. Prompts user if not in config (e.g., during first install).
    3. Falls back to default if input is invalid.
    """
    if config and "monitor_interval_hours" in config:
        try:
            interval = int(config["monitor_interval_hours"])
            if interval > 0:
                return interval
        except ValueError:
            log_message("Invalid monitor_interval_hours in config, using default.", "WARNING")

    # Prompt user if not in config or invalid
    try:
        interval_str = input(get_localized_string("monitor_interval_prompt", DEFAULT_MONITOR_INTERVAL_HOURS))
        if not interval_str: # User pressed Enter
            return DEFAULT_MONITOR_INTERVAL_HOURS
        interval = int(interval_str)
        if interval <= 0:
            raise ValueError("Interval must be positive.")
        return interval
    except ValueError:
        _print("invalid_monitor_interval", DEFAULT_MONITOR_INTERVAL_HOURS, log_level="WARNING")
        return DEFAULT_MONITOR_INTERVAL_HOURS
    except (KeyboardInterrupt, EOFError):
        _print("operation_aborted", log_level="WARNING")
        # Decide on behavior: use default or abort installation?
        # For now, use default to allow installation to proceed if possible.
        return DEFAULT_MONITOR_INTERVAL_HOURS

def initialize_password_and_config() -> dict | None:
    """
    Handles password setup during initial installation.
    Returns the initial configuration dictionary (without adapter backups yet) or None on failure/abort.
    """
    password = get_password_from_user_prompt("install_prompt_password")
    if password is None: return None # User aborted

    confirm_password = get_password_from_user_prompt("install_confirm_password")
    if confirm_password is None: return None # User aborted

    if password != confirm_password:
        _print("password_mismatch")
        return None # Password mismatch

    hashed_password_hex, salt_bytes = hash_password(password)
    salt_hex = salt_bytes.hex()

    monitor_interval = get_user_defined_monitor_interval() # Get interval from user

    initial_config = {
        "app_name": APP_NAME,
        "password_hash": hashed_password_hex,
        "salt_hex": salt_hex,
        "install_date": datetime.datetime.now().isoformat(),
        "monitor_interval_hours": monitor_interval,
        "adapters_backup": {}, # To be populated by network_manager, keyed by index
        # *** FIX: Changed key name from _guids to _indices ***
        "managed_adapters_indices": [], # To be populated by network_manager with InterfaceIndex
        "hosts_file_backed_up": False, # To be set by hosts_manager
        "last_monitor_run": None,
        "last_monitor_status": "Not yet run"
    }
    return initial_config

def authenticate_user(config: dict, action_key: str) -> bool:
    """
    Authenticates the user for a given action using the stored password.
    `action_key` is a key from strings_db.py for messages like "uninstall", "change_settings".
    """
    if not config or "password_hash" not in config or "salt_hex" not in config:
        _print("error_loading_config", CONFIG_FILE_PATH, "Password data missing.", log_level="ERROR")
        return False

    password = get_password_from_user_prompt("enter_password_action", action_key)
    if password is None:
        return False # User aborted

    if not verify_password(config["password_hash"], config["salt_hex"], password):
        _print("incorrect_password")
        return False
    return True

