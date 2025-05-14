# dns_filter_pkg/strings.py
# -*- coding: utf-8 -*-

# Centralized string definitions for localization

STRINGS_DB = {

    
    "en": {
        # General
        "app_description": "{} - DNS Filtering and SafeSearch Utility.", # For argparse
        "admin_required": "Administrator privileges are required to run this script.",
        "elevating_perms": "Attempting to elevate privileges...",
        "general_error": "An unexpected error occurred: {}",
        "operation_aborted": "Operation aborted by user.",
        "path_not_found": "Error: Path not found: {}",
        "file_not_found": "Error: File not found: {}",
        "permission_denied_file": "Error: Permission denied for file: {}",
        "error_creating_directory": "Error creating directory {}: {}",
        "error_reading_file": "Error reading file {}: {}",
        "error_writing_file": "Error writing file {}: {}",

        # Argparse Help Messages
        "help_install": "Install and configure the DNS filter and SafeSearch. Requires admin.",
        "help_uninstall": "Uninstall the filter and restore settings. Requires admin.",
        "help_status": "Show the current status of the filter. Requires admin.",
        "help_monitor": "Run the DNS monitoring check (usually via scheduled task). Requires admin.",
        "help_lang": "Set the language for output (en/he). Overrides system locale detection.",

        # Password Management
        "install_prompt_password": "Set a password for managing the filter: ",
        "install_confirm_password": "Confirm password: ",
        "password_mismatch": "Passwords do not match. Action aborted.",
        "enter_password_action": "Enter password to {}: ", # e.g., "Enter password to uninstall"
        "incorrect_password": "Incorrect password. Action aborted.",

        # Installation & Uninstallation
        "installation_starting": "Starting {} installation...",
        "installation_complete": "{} installed successfully.",
        "uninstallation_starting": "Starting {} uninstallation...",
        "uninstallation_complete": "{} uninstalled successfully.",
        "already_installed": "{} seems to be already installed. Uninstall first or check status.",
        "not_installed_error": "{} is not installed. Cannot perform this action.",
        "action_install": "install",
        "action_uninstall": "uninstall",
        "action_status": "check status",
        "action_monitor": "run monitor",

        # Configuration
        "config_saved": "Configuration saved to {}.",
        "config_loaded": "Configuration loaded from {}.",
        "error_saving_config": "Error saving configuration: {}.",
        "error_loading_config": "Error loading configuration: {}. It might be corrupted or inaccessible.",
        "config_file_missing": "Configuration file not found at {}.",
        "monitor_interval_prompt": "Enter monitor interval in hours (default {}): ",
        "invalid_monitor_interval": "Invalid interval. Using default value: {} hours.",


        # Network Adapter Management
        "adapter_not_found": "Could not find any suitable active network adapters.",
        "no_managed_adapters": "No network adapters were configured by the filter.",
        # *** FIX: Updated log message to show Index primarily ***
        "backup_dns_for_adapter": "Backing up DNS settings for adapter '{}' (Index: {})...",
        "backup_dns_success": "Successfully backed up DNS for '{}'. Type: {}. DNS: {}.",
        "backup_dns_failed": "Failed to backup DNS for adapter '{}': {}.",
        "set_dns_for_adapter": "Setting DNS for adapter '{}' to: {}.",
        "set_dns_success": "Successfully set DNS for adapter '{}'.",
        "set_dns_failed": "Failed to set DNS for adapter '{}': {}.",
        "restore_dns_for_adapter": "Restoring DNS for adapter '{}'.",
        "restore_dns_success": "Successfully restored DNS for adapter '{}'.",
        "restore_dns_failed": "Failed to restore DNS for adapter '{}': {}.",
        "getting_adapters_info": "Getting network adapter information...",
        "adapter_guid_missing": "Could not retrieve GUID for adapter '{}'. Skipping.", # Kept for info

        # Firewall Management
        "firewall_rule_creating": "Creating firewall rule '{}'...",
        "firewall_rule_created": "Firewall rule '{}' created/verified.",
        "firewall_rule_deleting": "Deleting firewall rule '{}'...",
        "firewall_rule_deleted": "Firewall rule '{}' deleted.",
        "firewall_rule_error": "Error processing firewall rule '{}': {}.",
        "status_firewall_rule_present": "  Rule '{}': Present",
        "status_firewall_rule_missing": "  Rule '{}': Missing",


        
        # ... (all previous strings remain the same) ...

        # Firewall Management (Updated messages)
        "firewall_creating_all_rules_ps": "Firewall: Creating all rules (ALLOW and BLOCK) using PowerShell...",
        "firewall_removing_all_rules_ps": "Firewall: Removing all managed rules (ALLOW and BLOCK) using PowerShell...",
        # Remove or comment out old diagnostic messages if they are no longer needed:
        # "firewall_diagnostic_mode_active": "Firewall: Running in DIAGNOSTIC mode (Block rules are NOT being created).",
        # "firewall_block_rules_skipped_diag": "Firewall: Skipping creation of BLOCK rules (Diagnostic Mode).",
        # "firewall_diagnostic_mode_active_removal": "Firewall: Running removal in DIAGNOSTIC mode (Block rules might not exist).",
        # "firewall_attempt_remove_block_diag": "Firewall: Attempting to remove BLOCK rules (Diagnostic Mode - may not exist).",
        # "firewall_diagnostic_mode_noop_active": "Firewall: Running in DIAGNOSTIC (NO-OP) mode. No firewall rules will be created or modified.",
        # "firewall_diagnostic_mode_noop_removal": "Firewall: Running removal in DIAGNOSTIC (NO-OP) mode. No firewall rules will be removed.",
        "firewall_creating_allow_rules_only": "Firewall: Creating ALLOW rules only (PowerShell). BLOCK rules are currently disabled.", # Might be reused if we need such a mode later
        "firewall_block_rules_skipped_allow_only": "Firewall: BLOCK rule creation skipped (ALLOW rules only mode).", # Might be reused
        "firewall_removing_allow_rules_only": "Firewall: Removing ALLOW rules only (PowerShell). Attempting cleanup of any old BLOCK rules.", # Might be reused
        "firewall_attempt_remove_block_rules_cleanup": "Firewall: Attempting to remove any existing BLOCK rules as a cleanup step.", # Might be reused


        # Scheduled Task Management
        "task_creating": "Creating scheduled task '{}'...",
        "task_created": "Scheduled task '{}' created.",
        "task_deleting": "Deleting scheduled task '{}'...",
        "task_deleted": "Scheduled task '{}' deleted.",
        "task_error": "Error with scheduled task '{}': {}.",
        "status_task_present": "  Task '{}': Present and configured (Interval: {} hours)",
        "status_task_missing": "  Task '{}': Missing or not configured correctly",
        "task_query_error": "Could not query scheduled task '{}': {}",
        "schtasks_next_run_time_key": "Next Run Time", # For parsing schtasks output
        "schtasks_last_run_time_key": "Last Run Time",
        "schtasks_last_result_key": "Last Result",
        "schtasks_status_key": "Status", # Or "Scheduled Task State"
        "schtasks_task_to_run_key": "Task To Run",


        # DNS Monitoring
        "monitor_checking_dns": "Monitoring: Checking primary DNS servers ({}) against google.com...",
        "monitor_dns_ok": "Monitoring: Primary DNS servers are responsive.",
        "monitor_dns_fail": "Monitoring: Primary DNS servers unresponsive. Reverting to fallback DNS ({}) for all managed adapters.",
        "monitor_reverted_dns": "Monitoring: Reverted system DNS to {} for adapter '{}'.",
        "monitor_no_config": "Monitoring: Configuration file not found. Cannot perform checks.",
        "monitor_no_adapters_in_config": "Monitoring: No adapters found in configuration to manage.",
        "dns_query_failed": "DNS query to {} for {} failed. Output: {}",
        "dns_query_success": "DNS query to {} for {} successful.",

        # Hosts File Management
        "hosts_file_backup_creating": "Backing up original hosts file to {}...",
        "hosts_file_backup_success": "Hosts file backed up successfully.",
        "hosts_file_backup_failed": "Failed to back up hosts file: {}.",
        "hosts_file_safesearch_applying": "Applying SafeSearch block to hosts file...",
        "hosts_file_safesearch_applied": "SafeSearch block applied to hosts file.",
        "hosts_file_safesearch_apply_failed": "Failed to apply SafeSearch block: {}.",
        "hosts_file_safesearch_removing": "Removing SafeSearch block from hosts file...",
        "hosts_file_safesearch_removed": "SafeSearch block removed from hosts file.",
        "hosts_file_safesearch_remove_failed": "Failed to remove SafeSearch block: {}.",
        "hosts_file_restore_from_backup": "Restoring hosts file from backup {}...",
        "hosts_file_restore_success": "Hosts file restored successfully from backup.",
        "hosts_file_restore_failed": "Failed to restore hosts file from backup: {}. Manual check may be needed.",
        "hosts_file_not_writeable": "Hosts file at {} is not writeable. Check permissions.",
        "hosts_file_safesearch_block_present": "  SafeSearch Block: Present in hosts file.",
        "hosts_file_safesearch_block_missing": "  SafeSearch Block: Missing from hosts file.",
        "hosts_file_backup_present_status": "Hosts file backup: Present at {}", # For status output
        "hosts_file_backup_missing_status": "Hosts file backup: Missing (expected at {})", # For status output


        # Status Output
        "status_checking": "Checking {} status...",
        "status_not_installed": "{} is not installed.",
        "status_installed_on": "{} installed on: {}.",
        "status_config_file_path": "Configuration file: {}",
        "status_adapters_dns_header": "Adapter DNS Configuration:",
        # *** FIX: Changed status message to show Index ***
        "status_adapter_name": "  Adapter: {} (Index: {})",
        "status_adapter_dns_servers": "    DNS Servers: {} ({})", # servers, type (Static/DHCP)
        "status_firewall_rules_header": "Firewall Rules Status:",
        "status_scheduled_task_header": "Scheduled Task Status:",
        "status_hosts_file_header": "Hosts File Status:",
        "status_last_monitor_run": "Last monitor run: {}",
        "status_last_monitor_status": "Last monitor status: {}",
        "status_table_header_adapter": "Adapter Name",
        # *** FIX: Changed header from GUID to Index ***
        "status_table_header_index": "Index",
        "status_table_header_dns": "Current DNS",
        "status_table_header_dns_type": "Type",
        "firewall_creating_allow_rules_only": "Firewall: Creating ALLOW rules only (PowerShell). BLOCK rules are currently disabled.",
        "firewall_block_rules_skipped_allow_only": "Firewall: BLOCK rule creation skipped (ALLOW rules only mode).",
        "firewall_removing_allow_rules_only": "Firewall: Removing ALLOW rules only (PowerShell). Attempting cleanup of any old BLOCK rules.",
        "firewall_attempt_remove_block_rules_cleanup": "Firewall: Attempting to remove any existing BLOCK rules as a cleanup step.",


        "firewall_creating_all_rules_ps_explicit_any": "Firewall: Creating all rules (ALLOW and BLOCK with explicit RemoteAddress Any) using PowerShell...",


        # ACL Management
        "acl_setting_permissions": "Setting permissions for configuration directory: {}",
        "acl_permissions_set_success": "Permissions set successfully for {}.",
        "acl_permissions_set_failed": "Failed to set permissions for {}: {}",

        # PowerShell interaction
        "powershell_cmd_failed": "PowerShell command failed: {}. Error: {}",
        "powershell_json_parse_error": "Failed to parse JSON output from PowerShell: {}",
    },
    "he": {
        # General
        "app_description": "{} - כלי סינון DNS וחיפוש בטוח.", # For argparse
        "admin_required": "נדרשות הרשאות מנהל להפעלת הסקריפט.",
        "elevating_perms": "מנסה להעלות הרשאות...",
        "general_error": "אירעה שגיאה בלתי צפויה: {}",
        "operation_aborted": "הפעולה בוטלה על ידי המשתמש.",
        "path_not_found": "שגיאה: נתיב לא נמצא: {}",
        "file_not_found": "שגיאה: קובץ לא נמצא: {}",
        "permission_denied_file": "שגיאה: הרשאת גישה נדחתה לקובץ: {}",
        "error_creating_directory": "שגיאה ביצירת תיקייה {}: {}",
        "error_reading_file": "שגיאה בקריאת קובץ {}: {}",
        "error_writing_file": "שגיאה בכתיבת קובץ {}: {}",

        # Argparse Help Messages
        "help_install": "התקן והגדר את מסנן ה-DNS והחיפוש הבטוח. דורש הרשאות מנהל.",
        "help_uninstall": "הסר את המסנן ושחזר הגדרות. דורש הרשאות מנהל.",
        "help_status": "הצג את הסטטוס הנוכחי של המסנן. דורש הרשאות מנהל.",
        "help_monitor": "הרץ בדיקת ניטור DNS (בדרך כלל דרך משימה מתוזמנת). דורש הרשאות מנהל.",
        "help_lang": "הגדר שפת פלט (en/he). דורס זיהוי שפה אוטומטי.",


        # Password Management
        "install_prompt_password": "הגדר סיסמה לניהול המסנן: ",
        "install_confirm_password": "אשר סיסמה: ",
        "password_mismatch": "הסיסמאות אינן תואמות. הפעולה בוטלה.",
        "enter_password_action": "הזן סיסמה עבור {}: ", # לדוגמה: "הזן סיסמה עבור הסרה"
        "incorrect_password": "סיסמה שגויה. הפעולה בוטלה.",

        # Installation & Uninstallation
        "installation_starting": "מתחיל התקנת {}...",
        "installation_complete": "{} הותקן בהצלחה.",
        "uninstallation_starting": "מתחיל הסרת {}...",
        "uninstallation_complete": "{} הוסר בהצלחה.",
        "already_installed": "נראה ש-{} כבר מותקן. הסר אותו תחילה או בדוק סטטוס.",
        "not_installed_error": "{} אינו מותקן. לא ניתן לבצע פעולה זו.",
        "action_install": "התקנה",
        "action_uninstall": "הסרה",
        "action_status": "בדיקת סטטוס",
        "action_monitor": "הרצת ניטור",

        # Configuration
        "config_saved": "התצורה נשמרה בנתיב {}.",
        "config_loaded": "התצורה נטענה מהנתיב {}.",
        "error_saving_config": "שגיאה בשמירת התצורה: {}.",
        "error_loading_config": "שגיאה בטעינת התצורה: {}. ייתכן שהקובץ פגום או לא נגיש.",
        "config_file_missing": "קובץ התצורה לא נמצא בנתיב {}.",
        "monitor_interval_prompt": "הזן מרווח ניטור בשעות (ברירת מחדל {}): ",
        "invalid_monitor_interval": "מרווח לא תקין. משתמש בערך ברירת המחדל: {} שעות.",

        # Network Adapter Management
        "adapter_not_found": "לא נמצאו מתאמי רשת פעילים מתאימים.",
        "no_managed_adapters": "המסנן לא הגדיר תצורה עבור אף מתאם רשת.",
        # *** FIX: Updated log message to show Index primarily ***
        "backup_dns_for_adapter": "מגבה הגדרות DNS עבור מתאם '{}' (אינדקס: {})...",
        "backup_dns_success": "הגדרות DNS גובו בהצלחה עבור '{}'. סוג: {}. שרתים: {}.",
        "backup_dns_failed": "גיבוי DNS עבור מתאם '{}' נכשל: {}.",
        "set_dns_for_adapter": "מגדיר DNS עבור מתאם '{}' לשרתים: {}.",
        "set_dns_success": "DNS הוגדר בהצלחה עבור מתאם '{}'.",
        "set_dns_failed": "הגדרת DNS עבור מתאם '{}' נכשלה: {}.",
        "restore_dns_for_adapter": "משחזר DNS עבור מתאם '{}'.",
        "restore_dns_success": "DNS שוחזר בהצלחה עבור מתאם '{}'.",
        "restore_dns_failed": "שחזור DNS עבור מתאם '{}' נכשל: {}.",
        "getting_adapters_info": "מאחזר מידע על מתאמי רשת...",
        "adapter_guid_missing": "לא ניתן היה לאחזר GUID עבור מתאם '{}'. מדלג.", # Kept for info

        # Firewall Management
        "firewall_rule_creating": "יוצר חוק חומת אש '{}'...",
        "firewall_rule_created": "חוק חומת אש '{}' נוצר/אומת.",
        "firewall_rule_deleting": "מוחק חוק חומת אש '{}'...",
        "firewall_rule_deleted": "חוק חומת אש '{}' נמחק.",
        "firewall_rule_error": "שגיאה בעיבוד חוק חומת אש '{}': {}.",
        "status_firewall_rule_present": "  חוק '{}': קיים",
        "status_firewall_rule_missing": "  חוק '{}': חסר",

        # Scheduled Task Management
        "task_creating": "יוצר משימה מתוזמנת '{}'...",
        "task_created": "משימה מתוזמנת '{}' נוצרה.",
        "task_deleting": "מוחק משימה מתוזמנת '{}'...",
        "task_deleted": "משימה מתוזמנת '{}' נמחקה.",
        "task_error": "שגיאה במשימה מתוזמנת '{}': {}.",
        "status_task_present": "  משימה '{}': קיימת ומוגדרת (מרווח: {} שעות)",
        "status_task_missing": "  משימה '{}': חסרה או לא מוגדרת כראוי",
        "task_query_error": "לא ניתן היה לשאול את המשימה המתוזמנת '{}': {}",
        "schtasks_next_run_time_key": "זמן ריצה הבא", # For parsing schtasks output
        "schtasks_last_run_time_key": "זמן ריצה אחרון",
        "schtasks_last_result_key": "תוצאה אחרונה",
        "schtasks_status_key": "מצב", # Or "מצב משימה מתוזמנת"
        "schtasks_task_to_run_key": "משימה להרצה",


        # DNS Monitoring
        "monitor_checking_dns": "ניטור: בודק שרתי DNS ראשיים ({}) מול google.com...",
        "monitor_dns_ok": "ניטור: שרתי DNS ראשיים מגיבים.",
        "monitor_dns_fail": "ניטור: שרתי DNS ראשיים אינם מגיבים. חוזר לשרתי גיבוי ({}) עבור כל המתאמים המנוהלים.",
        "monitor_reverted_dns": "ניטור: DNS המערכת שונה ל-{} עבור מתאם '{}'.",
        "monitor_no_config": "ניטור: קובץ התצורה לא נמצא. לא ניתן לבצע בדיקות.",
        "monitor_no_adapters_in_config": "ניטור: לא נמצאו מתאמים בתצורה לניהול.",
        "dns_query_failed": "שאילתת DNS ל-{} עבור {} נכשלה. פלט: {}",
        "dns_query_success": "שאילתת DNS ל-{} עבור {} הצליחה.",

        # Hosts File Management
        "hosts_file_backup_creating": "מגבה את קובץ ה-hosts המקורי אל {}...",
        "hosts_file_backup_success": "קובץ ה-hosts גובה בהצלחה.",
        "hosts_file_backup_failed": "גיבוי קובץ ה-hosts נכשל: {}.",
        "hosts_file_safesearch_applying": "מחיל חסימת SafeSearch על קובץ ה-hosts...",
        "hosts_file_safesearch_applied": "חסימת SafeSearch הוחלה על קובץ ה-hosts.",
        "hosts_file_safesearch_apply_failed": "החלת חסימת SafeSearch נכשלה: {}.",
        "hosts_file_safesearch_removing": "מסיר חסימת SafeSearch מקובץ ה-hosts...",
        "hosts_file_safesearch_removed": "חסימת SafeSearch הוסרה מקובץ ה-hosts.",
        "hosts_file_safesearch_remove_failed": "הסרת חסימת SafeSearch נכשלה: {}.",
        "hosts_file_restore_from_backup": "משחזר את קובץ ה-hosts מהגיבוי {}...",
        "hosts_file_restore_success": "קובץ ה-hosts שוחזר בהצלחה מהגיבוי.",
        "hosts_file_restore_failed": "שחזור קובץ ה-hosts מהגיבוי נכשל: {}. ייתכן שיידרש טיפול ידני.",
        "hosts_file_not_writeable": "קובץ ה-hosts בנתיב {} אינו ניתן לכתיבה. בדוק הרשאות.",
        "hosts_file_safesearch_block_present": "  חסימת SafeSearch: קיימת בקובץ ה-hosts.",
        "hosts_file_safesearch_block_missing": "  חסימת SafeSearch: חסרה מקובץ ה-hosts.",
        "hosts_file_backup_present_status": "גיבוי קובץ Hosts: קיים ב-{}", # For status output
        "hosts_file_backup_missing_status": "גיבוי קובץ Hosts: חסר (צפוי להיות ב-{})", # For status output


        # Status Output
        "status_checking": "בודק סטטוס {}...",
        "status_not_installed": "{} אינו מותקן.",
        "status_installed_on": "{} הותקן בתאריך: {}.",
        "status_config_file_path": "קובץ תצורה: {}",
        "status_adapters_dns_header": "תצורת DNS של מתאמים:",
        # *** FIX: Changed status message to show Index ***
        "status_adapter_name": "  מתאם: {} (אינדקס: {})",
        "status_adapter_dns_servers": "    שרתי DNS: {} ({})", # servers, type (Static/DHCP)
        "status_firewall_rules_header": "סטטוס חוקי חומת אש:",
        "status_scheduled_task_header": "סטטוס משימה מתוזמנת:",
        "status_hosts_file_header": "סטטוס קובץ Hosts:",
        "status_last_monitor_run": "ריצת ניטור אחרונה: {}",
        "status_last_monitor_status": "סטטוס ניטור אחרון: {}",
        "status_table_header_adapter": "שם מתאם",
        # *** FIX: Changed header from GUID to Index ***
        "status_table_header_index": "אינדקס",
        "status_table_header_dns": "DNS נוכחי",
        "status_table_header_dns_type": "סוג",

        "firewall_diagnostic_mode_noop_active": "Firewall: Running in DIAGNOSTIC (NO-OP) mode. No firewall rules will be created or modified.",
        "firewall_diagnostic_mode_noop_removal": "Firewall: Running removal in DIAGNOSTIC (NO-OP) mode. No firewall rules will be removed.",
        "hosts_file_diagnostic_mode_noop_apply": "Hosts File: Running in DIAGNOSTIC (NO-OP) mode. SafeSearch block will NOT be applied.",
        "hosts_file_diagnostic_mode_noop_remove": "Hosts File: Running removal in DIAGNOSTIC (NO-OP) mode. SafeSearch block will NOT be removed.",
        # ACL Management
        "acl_setting_permissions": "מגדיר הרשאות עבור תיקיית התצורה: {}",
        "acl_permissions_set_success": "ההרשאות הוגדרו בהצלחה עבור {}.",
        "acl_permissions_set_failed": "הגדרת ההרשאות נכשלה עבור {}: {}",

        # PowerShell interaction
        "powershell_cmd_failed": "פקודת PowerShell נכשלה: {}. שגיאה: {}",
        "powershell_json_parse_error": "ניתוח פלט JSON מ-PowerShell נכשל: {}",

        # English

# Hebrew
        "firewall_creating_allow_rules_only": "חומת אש: יוצר חוקי ALLOW בלבד (PowerShell). יצירת חוקי BLOCK מנוטרלת כרגע.",
        "firewall_block_rules_skipped_allow_only": "חומת אש: דילוג על יצירת חוקי BLOCK (מצב חוקי ALLOW בלבד).",
        "firewall_removing_allow_rules_only": "חומת אש: מסיר חוקי ALLOW בלבד (PowerShell). מנסה לנקות חוקי BLOCK ישנים אם קיימים.",
        "firewall_attempt_remove_block_rules_cleanup": "חומת אש: מנסה להסיר חוקי BLOCK קיימים כשלב ניקוי.",

         
        # ... (all other strings remain the same) ...
    
        # ... (all previous strings remain the same) ...

        # Firewall Management (Updated messages)
        "firewall_creating_all_rules_ps": "חומת אש: יוצר את כל החוקים (ALLOW ו-BLOCK) באמצעות PowerShell...",
        "firewall_removing_all_rules_ps": "חומת אש: מסיר את כל החוקים המנוהלים (ALLOW ו-BLOCK) באמצעות PowerShell...",
        # Remove or comment out old diagnostic messages:
        # "firewall_diagnostic_mode_active": "חומת אש: רצה במצב אבחון (חוקי BLOCK אינם נוצרים).",
        # "firewall_block_rules_skipped_diag": "חומת אש: מדלג על יצירת חוקי BLOCK (מצב אבחון).",
        # "firewall_diagnostic_mode_active_removal": "חומת אש: מבצע הסרה במצב אבחון (ייתכן שחוקי BLOCK אינם קיימים).",
        # "firewall_attempt_remove_block_diag": "חומת אש: מנסה להסיר חוקי BLOCK (מצב אבחון - ייתכן שאינם קיימים).",
        # "firewall_diagnostic_mode_noop_active": "חומת אש: רצה במצב אבחון (ללא פעולה). לא ייווצרו או ישונו חוקי חומת אש.",
        # "firewall_diagnostic_mode_noop_removal": "חומת אש: מבצעת הסרה במצב אבחון (ללא פעולה). לא יוסרו חוקי חומת אש.",
        "firewall_creating_allow_rules_only": "חומת אש: יוצר חוקי ALLOW בלבד (PowerShell). יצירת חוקי BLOCK מנוטרלת כרגע.",
        "firewall_block_rules_skipped_allow_only": "חומת אש: דילוג על יצירת חוקי BLOCK (מצב חוקי ALLOW בלבד).",
        "firewall_removing_allow_rules_only": "חומת אש: מסיר חוקי ALLOW בלבד (PowerShell). מנסה לנקות חוקי BLOCK ישנים אם קיימים.",
        "firewall_attempt_remove_block_rules_cleanup": "חומת אש: מנסה להסיר חוקי BLOCK קיימים כשלב ניקוי.",

        # ... (all other strings remain the same) ...
    }
}
