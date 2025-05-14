# dns_filter_tool.py
# -*- coding: utf-8 -*-

import argparse
import os
import sys

# --- Path Setup ---
# This section helps Python find the 'dns_filter_pkg' directory,
# especially when running the script directly during development.
# When packaged by PyInstaller, this might be less critical if the package
# is correctly included, but it's good practice for development.
try:
    # Get the directory containing this script (dns_filter_tool.py)
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    # If 'dns_filter_pkg' is a subdirectory of where this script is,
    # then current_script_dir is effectively the project root for imports.
    # If 'dns_filter_pkg' is a sibling, adjust accordingly.
    # Assuming 'dns_filter_pkg' is at the same level or discoverable via PYTHONPATH.
    # For a structure like:
    # dns_filter_project/
    #  ├── dns_filter_tool.py
    #  └── dns_filter_pkg/
    # Adding current_script_dir to sys.path allows `from dns_filter_pkg import ...`
    if current_script_dir not in sys.path:
        sys.path.insert(0, current_script_dir)

    from dns_filter_pkg import main as dns_filter_main_module
    from dns_filter_pkg.system_utils import (
        _print, setup_logging_and_localization, elevate_privileges, set_current_lang,
        get_localized_string, log_message
    )
    from dns_filter_pkg.constants import (
        APP_NAME, EXIT_SUCCESS, EXIT_ERROR, EXIT_OPERATION_ABORTED
    )

except ImportError as e:
    # This basic print will be in English as localization might not be set up.
    print(f"CRITICAL ERROR: Could not import the 'dns_filter_pkg'.\n"
          f"Ensure the package is in the same directory as this script, or in PYTHONPATH.\n"
          f"Details: {e}", file=sys.stderr)
    sys.exit(1) # Cannot proceed without the core package.


def determine_script_path_for_elevation_and_task() -> str:
    """
    Determines the absolute path of the script/executable being run.
    This is crucial for self-elevation and for the scheduled task to know what to execute.
    """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # Running as a PyInstaller bundled executable
        return os.path.abspath(sys.executable)
    else:
        # Running as a .py script
        return os.path.abspath(__file__)


def main_cli():
    """
    Main command-line interface function.
    Parses arguments and calls the appropriate functions from dns_filter_pkg.main.
    """
    # --- Initial Setup ---
    # This must be called first to set up logging directory and initial language.
    setup_logging_and_localization()

    # Determine the absolute path of this script/executable
    # This path is needed for self-elevation and for the scheduled task.
    executable_script_path = determine_script_path_for_elevation_and_task()
    log_message(f"Main executable/script path determined as: {executable_script_path}", "DEBUG")

    # Pass this path to the main logic module so it can use it (e.g., for scheduled task creation)
    dns_filter_main_module.set_entry_point_script_path(executable_script_path)


    # --- Argument Parser Setup ---
    # Now that localization is set up, we can use get_localized_string for help messages.
    parser = argparse.ArgumentParser(
        description=get_localized_string("app_description", APP_NAME),
        prog=os.path.basename(executable_script_path) # Show correct name (script or .exe)
    )
    parser.add_argument(
        "--install", action="store_true",
        help=get_localized_string("help_install")
    )
    parser.add_argument(
        "--uninstall", action="store_true",
        help=get_localized_string("help_uninstall")
    )
    parser.add_argument(
        "--status", action="store_true",
        help=get_localized_string("help_status")
    )
    parser.add_argument(
        "--monitor", action="store_true",
        help=get_localized_string("help_monitor") # Usually for internal/task use
    )
    parser.add_argument(
        "--lang", choices=["en", "he"],
        help=get_localized_string("help_lang")
    )

    if len(sys.argv) == 1: # No arguments provided
        parser.print_help(sys.stderr)
        sys.exit(EXIT_ERROR)
        
    args = parser.parse_args()

    # --- Language Override ---
    if args.lang:
        set_current_lang(args.lang)
        # Note: argparse help messages are generated when parser is defined.
        # If language changes after that, help messages might remain in the initial language.
        # This is a common limitation unless help is dynamically regenerated.
        # For messages printed by _print, the new language will be used.
        log_message(f"Language explicitly set to '{args.lang}' by user.", "INFO")


    # --- Privilege Elevation ---
    # Actions requiring admin privileges
    needs_admin = args.install or args.uninstall or args.status or args.monitor
    if needs_admin:
        # Pass all original arguments (sys.argv[1:]) to the elevated process.
        # The elevate_privileges function handles how to call ShellExecuteW correctly
        # whether it's a .py script or a bundled .exe.
        elevate_privileges(executable_script_path, sys.argv[1:])
        # If elevate_privileges is called and succeeds in starting a new admin process,
        # the current non-admin process will sys.exit(0).
        # If it's already admin, it does nothing and script continues.


    # --- Dispatching Actions to the Main Logic Module ---
    exit_code = EXIT_ERROR # Default to error
    try:
        if args.install:
            exit_code = dns_filter_main_module.install_filter_logic()
        elif args.uninstall:
            exit_code = dns_filter_main_module.uninstall_filter_logic()
        elif args.status:
            exit_code = dns_filter_main_module.show_status_logic()
        elif args.monitor:
            exit_code = dns_filter_main_module.monitor_dns_logic()
        else:
            # This case should ideally not be reached if argparse is configured correctly,
            # as it would exit if no known action is provided.
            parser.print_help(sys.stderr)
            exit_code = EXIT_ERROR
            
    except SystemExit as e:
        # Catch sys.exit() calls from within the logic if they happen (e.g., from elevate_privileges)
        # Log and re-raise to ensure the process actually exits with the intended code.
        log_message(f"Exiting with code {e.code} due to SystemExit.", "INFO" if e.code == EXIT_SUCCESS else "WARNING")
        sys.exit(e.code)
    except KeyboardInterrupt:
        _print("operation_aborted", log_level="WARNING")
        sys.exit(EXIT_OPERATION_ABORTED)
    except Exception as e:
        # Catch any other unhandled exceptions from the main logic
        _print("general_error", str(e), log_level="CRITICAL")
        log_message(f"Unhandled critical exception in CLI: {e}", "CRITICAL")
        import traceback
        log_message(traceback.format_exc(), "CRITICAL") # Log full traceback
        sys.exit(EXIT_ERROR)
    
    log_message(f"Application finished with exit code {exit_code}.", "INFO")
    sys.exit(exit_code)

if __name__ == "__main__":
    # This is the main entry point when the script is executed.
    main_cli()
