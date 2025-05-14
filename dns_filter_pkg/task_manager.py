# dns_filter_pkg/task_manager.py
# -*- coding: utf-8 -*-

import os
import sys
import re # For parsing schtasks output if needed

from .system_utils import _print, log_message, run_command, get_localized_string, CURRENT_LANG
from .constants import TASK_NAME, DEFAULT_MONITOR_INTERVAL_HOURS, APP_NAME

def get_script_path_for_task() -> str:
    """
    Determines the full command string to be executed by the scheduled task.
    It needs to correctly point to the packaged .exe or the python script.
    """
    # If packaged as EXE (PyInstaller): sys.executable is the path to the EXE.
    # If running as .py script: sys.executable is python.exe, and __file__ (or a known entry point) is the script path.
    
    # The entry point for the application is dns_filter_tool.py (or its compiled version)
    # We need the absolute path to it.

    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # Packaged with PyInstaller: sys.executable is the main executable
        executable_path = sys.executable
        # Arguments for the monitor action, including language
        task_args = [f'"{executable_path}"', "--monitor", f"--lang {CURRENT_LANG}"]
    else:
        # Running as .py script. We need the path to 'dns_filter_tool.py'.
        # Assuming dns_filter_tool.py is in the parent directory of this package (dns_filter_pkg)
        # This might need adjustment based on final project structure or how entry_point_script_path is passed.
        # For robustness, the main script (dns_filter_tool.py) should pass its own path.
        # For now, let's assume it can be found relative to this file or is passed.
        
        # A common pattern is for the main executable script (dns_filter_tool.py)
        # to be in the root of the project, and this package (dns_filter_pkg) to be a sub-directory.
        # So, if this file is dns_filter_project/dns_filter_pkg/task_manager.py
        # then dns_filter_tool.py is dns_filter_project/dns_filter_tool.py
        
        # Get the directory of the current file (task_manager.py inside dns_filter_pkg)
        current_pkg_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up one level to the project root (dns_filter_project)
        project_root = os.path.dirname(current_pkg_dir)
        entry_point_script_path = os.path.join(project_root, "dns_filter_tool.py")

        if not os.path.exists(entry_point_script_path):
            log_message(f"CRITICAL: Entry point script '{entry_point_script_path}' for scheduled task not found.", "ERROR")
            # Fallback or raise error. For now, log and it will likely fail task creation.
            # This path needs to be solid.
            # A better way might be to have the main CLI pass its own path (sys.argv[0] or __file__)
            # to the functions that create the task.
            # For now, this is an assumption.
            # Let's assume the main executable is sys.executable (python.exe)
            # and the script is the one that launched the current process, if not frozen.
            # This is still tricky if the task manager is called from a different context.

            # Safest bet if not frozen: sys.executable (python.exe) and sys.argv[0] (the script that was initially run)
            # However, sys.argv[0] might be different if this module is imported.
            # Let's stick to the assumption that dns_filter_tool.py is the main entry point.
            # A placeholder for now, this part should be more robust.
            # A common way is to have the main application pass its own path (sys.argv[0] or __file__)
            # to the task creation logic.
            # For now, we construct it assuming dns_filter_tool.py is the main script.
            # This path should be determined by the calling context (e.g., dns_filter_tool.py itself).
            # We'll make this function accept the entry point script path.
            # For now, this is a placeholder logic for path determination.
            log_message("Warning: Scheduled task path determination for .py script is simplified. Ensure entry point is correct.", "WARNING")
            # This function will be called from main.py, which is called by dns_filter_tool.py.
            # So, sys.argv[0] in dns_filter_tool.py would be correct.
            # We will need to pass this path down.
            # For now, this is a placeholder:
            entry_point_script_path = "dns_filter_tool.py" # This will be resolved by the caller.
            executable_path = sys.executable # python.exe
            task_args = [f'"{executable_path}"', f'"{entry_point_script_path}"', "--monitor", f"--lang {CURRENT_LANG}"]


    return ' '.join(task_args)


def scheduled_task_exists() -> bool:
    """
    Checks if the scheduled task for DNSFilter monitoring exists.
    Uses `schtasks /Query`.
    """
    # schtasks /Query /TN <taskname>
    # Returns 0 if task exists, 1 if task does not exist (with "ERROR: The specified task name ... was not found.")
    cmd = ["schtasks", "/Query", "/TN", TASK_NAME]
    success, stdout, stderr, rc = run_command(cmd, check_errors=False, suppress_output=True, expected_return_codes=[0, 1])

    if rc == 0 and TASK_NAME.lower() in stdout.lower(): # Success and task name in output
        log_message(f"Scheduled task '{TASK_NAME}' found.", "DEBUG")
        return True
    elif rc == 1 and ("not found" in stderr.lower() or "לא נמצא" in stderr.lower()): # Specific error for not found
        log_message(f"Scheduled task '{TASK_NAME}' not found (rc=1).", "DEBUG")
        return False
    else: # Other errors or unexpected output
        log_message(f"Error querying task '{TASK_NAME}'. RC={rc}. Stdout: '{stdout[:100]}'. Stderr: '{stderr[:100]}'.", "WARNING")
        return False


def create_scheduled_task(monitor_interval_hours: int, entry_point_script_path: str) -> bool:
    """
    Creates the scheduled task for DNS monitoring.
    `monitor_interval_hours`: The interval in hours for the task to run.
    `entry_point_script_path`: Absolute path to the main script (e.g., dns_filter_tool.py or the .exe).
    """
    _print("task_creating", TASK_NAME)

    if monitor_interval_hours <= 0:
        log_message(f"Invalid monitor interval: {monitor_interval_hours}. Using default: {DEFAULT_MONITOR_INTERVAL_HOURS}", "WARNING")
        monitor_interval_hours = DEFAULT_MONITOR_INTERVAL_HOURS

    # Determine the command to run for the task
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'): # Packaged
        script_to_run_in_task = entry_point_script_path # This is the .exe path
        task_action_args_list = [f'"{script_to_run_in_task}"', "--monitor", f"--lang {CURRENT_LANG}"]
    else: # Running as .py script
        python_executable = sys.executable
        task_action_args_list = [f'"{python_executable}"', f'"{entry_point_script_path}"', "--monitor", f"--lang {CURRENT_LANG}"]
    
    task_action_command = ' '.join(task_action_args_list)
    log_message(f"Scheduled task action command: {task_action_command}", "DEBUG")


    # SCHTASKS command:
    # /Create : Create a new task
    # /TN <TaskName> : Task Name
    # /TR <TaskRun> : The command to run
    # /SC HOURLY /MO <Interval> : Schedule type (HOURLY) and modifier (every N hours)
    # /RU SYSTEM : Run as the SYSTEM account (for background operation without user login)
    # /RL HIGHEST : Run with highest privileges (SYSTEM already has highest)
    # /F : Force creation (overwrite if task with same name exists)
    # /ST <StartTime> : Optional, e.g., 00:00
    # /IT : Run task only if user is logged on (NOT desired for SYSTEM task)
    # /NP : No password (for /RU other than SYSTEM, not needed here)
    # Consider /Z to delete task after it completes its last run (not for recurring tasks)
    # Consider /K to delete task if not scheduled to run again (not for recurring)

    cmd = [
        "schtasks", "/Create",
        "/TN", TASK_NAME,
        "/TR", task_action_command,
        "/SC", "HOURLY",
        "/MO", str(monitor_interval_hours),
        "/RU", "SYSTEM",
        "/RL", "HIGHEST", # Redundant with SYSTEM but doesn't hurt
        "/F"
    ]
    success, stdout, stderr, rc = run_command(cmd, check_errors=True)

    if success:
        _print("task_created", TASK_NAME)
        return True
    else:
        _print("task_error", TASK_NAME, f"(creation failed) - {stderr if stderr else stdout}", log_level="ERROR")
        return False

def delete_scheduled_task() -> bool:
    """
    Deletes the scheduled task for DNSFilter monitoring.
    Returns True if successful or task didn't exist, False on error.
    """
    _print("task_deleting", TASK_NAME)
    if scheduled_task_exists():
        cmd = ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"] # /F to force deletion
        success, stdout, stderr, rc = run_command(cmd, check_errors=True)
        if success:
            _print("task_deleted", TASK_NAME)
            return True
        else:
            _print("task_error", TASK_NAME, f"(deletion failed) - {stderr if stderr else stdout}", log_level="WARNING")
            return False # Deletion failed
    else:
        _print("status_task_missing", TASK_NAME, log_level="DEBUG")
        return True # Task didn't exist, so consider deletion "successful" in this context.

def get_task_details() -> dict | None:
    """
    Attempts to query details of the scheduled task.
    Returns a dictionary with details like 'Next Run Time', 'Last Run Time', 'Last Task Result',
    or None if task doesn't exist or details cannot be parsed.
    Parsing schtasks /Query /FO CSV /V is complex due to localization and format.
    A simpler approach might be to just confirm existence and rely on config for interval.
    """
    if not scheduled_task_exists():
        return None

    # Using /Query with /XML format might be more parsable if we use an XML library,
    # but that adds a dependency if not using stdlib's xml.etree.ElementTree.
    # `schtasks /Query /TN <TASK_NAME> /FO LIST /V` gives verbose output.
    cmd = ["schtasks", "/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"]
    success, stdout, stderr, rc = run_command(cmd, check_errors=False, suppress_output=True)

    if not success or not stdout:
        _print("task_query_error", TASK_NAME, stderr if stderr else "No output", log_level="WARNING")
        return None

    details = {}
    try:
        # Attempt to parse key information. This is highly dependent on schtasks output format and language.
        # Example lines (English):
        # Next Run Time:          11/05/2025 10:00:00 AM
        # Last Run Time:          11/05/2025 06:00:00 AM
        # Last Result:            0
        # Task To Run:            "C:\Path\To\App.exe" --monitor --lang en
        # Run As User:            SYSTEM
        # Schedule:               Scheduling data is not available in this format.
        # Scheduled Task State:   Enabled
        # Repeat: Every 4 Hour(s), 0 Minute(s) from ... (This is part of "Triggers")

        # For simplicity, we'll extract a few common fields if possible.
        # This parsing is fragile.
        for line in stdout.splitlines():
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                if key == get_localized_string("schtasks_next_run_time_key", lang="en") or "Next Run Time" in key: # Add localized key
                    details["Next Run Time"] = value
                elif key == get_localized_string("schtasks_last_run_time_key", lang="en") or "Last Run Time" in key:
                    details["Last Run Time"] = value
                elif key == get_localized_string("schtasks_last_result_key", lang="en") or "Last Result" in key:
                    details["Last Task Result"] = value
                elif key == get_localized_string("schtasks_status_key", lang="en") or "Status" in key or "Scheduled Task State" in key:
                    details["Status"] = value
                elif key == get_localized_string("schtasks_task_to_run_key", lang="en") or "Task To Run" in key:
                    details["Task To Run"] = value
                # Extracting interval from "Triggers" or "Repeat" is very complex from LIST format.
                # We rely on the value stored in our config.json for the intended interval.

        if not details:
            log_message(f"Could not parse details for task '{TASK_NAME}' from output: {stdout[:200]}", "WARNING")
        else:
            log_message(f"Parsed task details for '{TASK_NAME}': {details}", "DEBUG")
            
    except Exception as e:
        log_message(f"Error parsing schtasks output for '{TASK_NAME}': {e}", "ERROR")
        return None
        
    return details

