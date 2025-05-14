# dns_filter_pkg/system_utils.py
# -*- coding: utf-8 -*-

import ctypes
import datetime
import json
import locale
import os
import subprocess
import sys
import time # For potential delays if needed

from .constants import (
    LOG_FILE_PATH, CONFIG_DIR, APP_NAME, DEFAULT_LANGUAGE, SUPPORTED_LANGUAGES
)
# strings_db will be imported dynamically to avoid circular dependency at module load time
# from .strings import STRINGS_DB # Avoid direct import at top level if STRINGS_DB is large or complex

# Global variable for current language, initialized by setup_logging_and_localization
CURRENT_LANG = DEFAULT_LANGUAGE
STRINGS_DB_CACHE = None # Cache for strings

def _load_strings_db_if_needed():
    global STRINGS_DB_CACHE
    if STRINGS_DB_CACHE is None:
        try:
            # Dynamically import strings when first needed
            from .strings import STRINGS_DB
            STRINGS_DB_CACHE = STRINGS_DB
        except ImportError as e:
            # This is a critical failure if strings cannot be loaded.
            # Fallback to a very basic error message.
            print(f"FATAL: Could not load strings database: {e}", file=sys.stderr)
            STRINGS_DB_CACHE = {"en": {"general_error": "Unexpected error (strings DB failed to load): {}"}} # Minimal fallback
            # Consider exiting or raising a custom exception.

def get_localized_string(key: str, *args, lang: str = None) -> str:
    """
    Retrieves a localized string for a given key and language.
    Falls back to DEFAULT_LANGUAGE if the key or language is not found.
    """
    _load_strings_db_if_needed()
    global CURRENT_LANG
    effective_lang = lang if lang else CURRENT_LANG

    lang_strings = STRINGS_DB_CACHE.get(effective_lang)
    if not lang_strings: 
        lang_strings = STRINGS_DB_CACHE.get(DEFAULT_LANGUAGE, {})
        # log_message below might cause recursion if called before logging is fully set up.
        # Only log if this function is called after basic logging setup.
        # For early calls (like in setup_logging_and_localization itself), avoid logging from here.
        # print(f"DEBUG: Language '{effective_lang}' not found for strings, falling back to '{DEFAULT_LANGUAGE}' for key '{key}'.", file=sys.stderr)


    msg_fmt = lang_strings.get(key)
    if not msg_fmt: 
        # print(f"DEBUG: Key '{key}' not found in lang '{effective_lang}', trying '{DEFAULT_LANGUAGE}'.", file=sys.stderr)
        msg_fmt = STRINGS_DB_CACHE.get(DEFAULT_LANGUAGE, {}).get(key, f"<{key}>")

    try:
        return msg_fmt.format(*args) if args else msg_fmt
    except Exception as e:
        # print(f"ERROR: Formatting string for key '{key}' with args {args} in lang '{effective_lang}': {e}", file=sys.stderr)
        return f"<Error formatting key: {key}>"


def _print(message_key: str, *args, log_level: str = "INFO", lang: str = None, **kwargs) -> None:
    """
    Prints a localized message to the console and logs it.
    """
    message = get_localized_string(message_key, *args, lang=lang)
    print(message, **kwargs)
    if log_level: 
        log_message(message, level=log_level.upper()) # Log level in uppercase


def setup_logging_and_localization() -> None:
    """
    Ensures the configuration directory exists for logging.
    Determines the language to use based on system locale or fallback.
    This should be called once at the beginning of the application.
    """
    global CURRENT_LANG
    try:
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR, exist_ok=True)
            # Set restrictive permissions on the directory after creation
            set_directory_permissions(CONFIG_DIR) # This function needs to be robust
    except IOError as e:
        print(f"CRITICAL: Error creating config directory {CONFIG_DIR}: {e}. Exiting.", file=sys.stderr)
        sys.exit(1) # Cannot proceed without config/log directory

    # Basic language detection (can be overridden by --lang argument later by calling set_current_lang)
    try:
        sys_lang_code, _ = locale.getdefaultlocale()
        if sys_lang_code:
            lang_prefix = sys_lang_code.split('_')[0].lower()
            if lang_prefix in SUPPORTED_LANGUAGES:
                CURRENT_LANG = lang_prefix
                log_message(f"System language detected: {sys_lang_code}, using '{CURRENT_LANG}'.", "DEBUG")
            else:
                log_message(f"System language '{sys_lang_code}' not directly supported, using default '{DEFAULT_LANGUAGE}'.", "DEBUG")
    except Exception as e:
        log_message(f"Could not detect system locale, using default '{DEFAULT_LANGUAGE}'. Error: {e}", "DEBUG")
    
    # Ensure strings are loaded now that language might be set
    _load_strings_db_if_needed()
    log_message(f"Effective UI language set to: {CURRENT_LANG}", "INFO")


def log_message(message: str, level: str = "INFO") -> None:
    """
    Writes a message to the log file with a timestamp and severity level.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        # Ensure CONFIG_DIR exists (should have been created by setup_logging_and_localization)
        if not os.path.exists(os.path.dirname(LOG_FILE_PATH)):
             os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)

        with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} [{level.upper()}] {message}\n")
    except IOError:
        print(f"LOGGING_ERROR: {timestamp} [{level.upper()}] {message}", file=sys.stderr)


def run_command(command: list[str], check_errors: bool = True, suppress_output: bool = False,
                expected_return_codes: list[int] = None, encoding: str = 'utf-8') -> tuple[bool, str, str, int]:
    """
    Executes a system command.
    Returns a tuple: (success_boolean, stdout_string, stderr_string, return_code_integer).
    `expected_return_codes`: If provided, codes in this list are also considered success (along with 0 if not overridden).
    """
    if expected_return_codes is None:
        effective_expected_codes = [0]
    elif 0 not in expected_return_codes: # Ensure 0 is success unless explicitly excluded.
        effective_expected_codes = [0] + expected_return_codes
    else:
        effective_expected_codes = expected_return_codes


    try:
        log_message(f"Running command: {' '.join(command)}", "DEBUG")
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding=encoding,
            errors='ignore', 
            check=False 
        )
        
        stdout = process.stdout.strip() if process.stdout else ""
        stderr = process.stderr.strip() if process.stderr else ""
        return_code = process.returncode

        if not suppress_output:
            if stdout: log_message(f"Cmd stdout (rc={return_code}): {stdout}", "DEBUG")
            if stderr: log_message(f"Cmd stderr (rc={return_code}): {stderr}", "DEBUG")
        
        successful = return_code in effective_expected_codes

        if check_errors and not successful:
            log_message(f"Command failed with code {return_code} (expected one of {effective_expected_codes}): {' '.join(command)}. Error: {stderr}", "ERROR")
            return False, stdout, stderr, return_code
        
        return successful, stdout, stderr, return_code

    except FileNotFoundError:
        log_message(f"Command not found: {command[0]}", "ERROR")
        return False, "", f"{get_localized_string('file_not_found', command[0])}", -1 
    except Exception as e:
        log_message(f"Exception running command {' '.join(command)}: {e}", "ERROR")
        return False, "", str(e), -2 


def run_powershell_command(ps_command: str, check_errors: bool = True, suppress_output: bool = False) -> tuple[bool, str, str, int]:
    """Executes a PowerShell command."""
    full_command = [
        "powershell.exe",
        "-NoProfile",         # Skips loading user profile for faster startup
        "-NonInteractive",    # Ensures no interactive prompts hang the script
        "-ExecutionPolicy", "Bypass", # Allows running unsigned scripts for this session
        "-Command", ps_command
    ]
    log_message(f"Running PowerShell command: {ps_command}", "DEBUG")
    
    # PowerShell can output with BOM. `utf-8-sig` can handle this.
    # Standard `utf-8` usually works too.
    success, stdout, stderr, rc = run_command(full_command, check_errors, suppress_output, encoding='utf-8-sig')

    # PowerShell scripts might set $LASTEXITCODE for external commands,
    # or exit with a specific code. A successful PS command execution is usually rc=0.
    if not success and check_errors: # run_command already logs detailed error
        _print("powershell_cmd_failed", ps_command, stderr if stderr else stdout, log_level="ERROR")
    
    return success, stdout, stderr, rc

def parse_powershell_json_output(stdout: str, ps_command_description: str) -> any:
    """Tries to parse JSON output from a PowerShell command."""
    if not stdout:
        log_message(f"No stdout to parse JSON from PowerShell command: {ps_command_description}", "WARNING")
        return None
    try:
        # Remove potential BOM if present before parsing JSON
        if stdout.startswith('\ufeff'):
            stdout = stdout[1:]
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        _print("powershell_json_parse_error", ps_command_description, log_level="ERROR")
        log_message(f"JSONDecodeError: {e}. PowerShell stdout was: {stdout[:500]}...", "ERROR") # Log snippet
        return None

def is_admin() -> bool:
    """Checks if the current script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError: 
        log_message("Could not determine admin status via ctypes.windll.shell32.IsUserAnAdmin. Assuming not admin.", "WARNING")
        return False
    except Exception as e:
        log_message(f"Error checking admin status: {e}. Assuming not admin.", "ERROR")
        return False

def elevate_privileges(executable_path_to_elevate: str, args_list_for_elevated: list[str]) -> None:
    """
    If not already admin, re-runs the script with administrator privileges
    and exits the current non-admin process.
    `executable_path_to_elevate`: Absolute path to the .exe or python.exe.
    `args_list_for_elevated`: Arguments to pass. If python.exe, this should include the script path first.
    """
    if not is_admin():
        _print("admin_required")
        _print("elevating_perms")
        try:
            # Construct parameters string for ShellExecuteW
            # If executable_path_to_elevate is python.exe, args_list_for_elevated should start with the script path.
            # If it's the .exe itself, args_list_for_elevated are just the app's args.
            params_str = ' '.join([f'"{arg}"' for arg in args_list_for_elevated])
            
            log_message(f"Elevating: Exe='{executable_path_to_elevate}', Params='{params_str}'", "DEBUG")

            # SW_SHOWNORMAL = 1
            ret_code = ctypes.windll.shell32.ShellExecuteW(
                None,                 # hwnd
                "runas",              # lpOperation
                executable_path_to_elevate, # lpFile
                params_str,           # lpParameters
                None,                 # lpDirectory
                1                     # nShowCmd (SW_SHOWNORMAL)
            )

            if ret_code <= 32: 
                log_message(f"ShellExecuteW failed with error code: {ret_code}. See ShellExecuteW documentation.", "ERROR")
                _print("general_error", f"Failed to elevate (ShellExecuteW error code: {ret_code})")
                sys.exit(1) 
            else:
                log_message("Privilege elevation process initiated. Exiting current non-admin process.", "INFO")
                sys.exit(0) # Success, new process started.

        except Exception as e:
            log_message(f"Exception during privilege elevation: {e}", "ERROR")
            _print("general_error", str(e))
            sys.exit(1)

def set_directory_permissions(dir_path: str) -> bool:
    """
    Sets restrictive permissions for the configuration directory:
    SYSTEM: Full Control, Administrators: Full Control. Inheritance is removed.
    """
    if not os.path.exists(dir_path):
        log_message(f"Directory {dir_path} does not exist. Cannot set permissions.", "WARNING")
        return False # Or True if we consider it "not failed" because dir doesn't exist
        
    _print("acl_setting_permissions", dir_path, log_level="DEBUG")
    cmd = [
        "icacls", dir_path,
        "/inheritance:r", 
        "/grant", "SYSTEM:(OI)(CI)F", 
        "/grant", "Administrators:(OI)(CI)F" 
    ]
    
    success, stdout, stderr, rc = run_command(cmd, check_errors=True) # icacls returns 0 on success
    if success:
        _print("acl_permissions_set_success", dir_path, log_level="INFO")
        return True
    else:
        # icacls might output to stdout on success as well, stderr for errors.
        err_msg = stderr if stderr else stdout
        _print("acl_permissions_set_failed", dir_path, f"icacls error: {err_msg} (Code: {rc})", log_level="ERROR")
        return False

def set_current_lang(lang_code: str) -> None:
    """Sets the current language for localization if supported."""
    global CURRENT_LANG
    if lang_code and lang_code.lower() in SUPPORTED_LANGUAGES:
        CURRENT_LANG = lang_code.lower()
        log_message(f"User explicitly set language to: {CURRENT_LANG}", "INFO")
    elif lang_code:
        log_message(f"User tried to set unsupported language: {lang_code}. Using current: {CURRENT_LANG}", "WARNING")

