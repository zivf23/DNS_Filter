# dns_filter_pkg/network_adapter_manager.py
# -*- coding: utf-8 -*-

from .system_utils import (
    _print, log_message, run_powershell_command, parse_powershell_json_output
)
from .constants import INSTALL_DNS_SERVERS

# --- Network Adapter Identification and DNS Management using PowerShell ---
# --- Using InterfaceIndex as the primary identifier ---

def get_active_network_adapters_ps() -> list[dict] | None:
    """
    Retrieves a list of active, non-virtual, physical network adapters using PowerShell.
    Returns a list of dictionaries, each containing 'Name', 'InterfaceDescription',
    'InterfaceGuid', and 'InterfaceIndex', or None on failure.
    Filters out common virtual/loopback adapters.
    """
    _print("getting_adapters_info", log_level="DEBUG")
    ps_command = (
        "Get-NetAdapter | "
        "Where-Object {$_.Status -eq 'Up' -and $_.Virtual -eq $false -and $_.MediaType -ne 'Loopback' "
        "-and $_.InterfaceDescription -notmatch 'Loopback|Pseudo|Teredo|ISATAP|Virtual|Bluetooth|TAP-Windows Adapter V9'} | "
        "Select-Object Name, InterfaceDescription, InterfaceGuid, InterfaceIndex | "
        "ConvertTo-Json -Compress"
    )

    success, stdout, stderr, rc = run_powershell_command(ps_command, suppress_output=True)

    if not success or not stdout:
        log_message(f"Failed to get network adapters via PowerShell. RC: {rc}. Stderr: {stderr}", "ERROR")
        _print("adapter_not_found")
        return None

    adapters_data = parse_powershell_json_output(stdout, ps_command)

    if adapters_data is None:
        _print("adapter_not_found")
        return None

    if isinstance(adapters_data, dict): # If only one adapter, it's not a list
        adapters_data = [adapters_data]
    
    if not adapters_data:
        _print("adapter_not_found")
        return None

    for adapter in adapters_data:
        log_message(f"Found adapter: Name='{adapter.get('Name')}', GUID='{adapter.get('InterfaceGuid')}', Idx='{adapter.get('InterfaceIndex')}'", "DEBUG")
    
    return adapters_data


def get_dns_settings_ps(adapter_index: int | str) -> dict | None:
    """
    Gets current DNS settings for a given adapter InterfaceIndex using PowerShell.
    """
    if adapter_index is None:
        log_message("Adapter InterfaceIndex is required to get DNS settings.", "ERROR")
        return None
    
    adapter_index_str = str(adapter_index) 

    ps_script_template = """
        $ErrorActionPreference = "Stop";
        # Select adapter by InterfaceIndex
        $adapter = Get-NetAdapter -InterfaceIndex {index_placeholder};

        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex;
        $dnsClientServers = @();
        try {
            $dnsClientServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses;
        } catch {
             Write-Verbose "Get-DnsClientServerAddress failed for $($adapter.InterfaceIndex), likely no static DNS set."
        }

        if ($null -eq $dnsClientServers) { $dnsClientServers = @(); }

        $isInterfaceDhcpEnabled = $false;
        if ($ipConfig.NetIPv4Interface.Dhcp -eq 'Enabled') {
            $isInterfaceDhcpEnabled = $true;
        }

        $isDnsViaDhcp = $isInterfaceDhcpEnabled -and ($dnsClientServers.Count -eq 0);

        $effectiveDnsServers = $dnsClientServers;
        if ($isDnsViaDhcp -and $ipConfig.DNSServer) {
            $effectiveDnsServers = $ipConfig.DNSServer.ServerAddresses | Where-Object { $_ -ne $null -and $_ -ne '0.0.0.0' -and $_ -ne '::' -and $_ -ne '::1' }
            if ($null -eq $effectiveDnsServers) { $effectiveDnsServers = @(); }
        }

        if ($effectiveDnsServers -isnot [array]) { $effectiveDnsServers = @($effectiveDnsServers); }
        if ($dnsClientServers -isnot [array]) { $dnsClientServers = @($dnsClientServers); }

        @{
            OriginalAdapterName = $adapter.Name;
            DhcpForDns = $isDnsViaDhcp;
            ConfiguredDnsServers = $dnsClientServers;
            EffectiveDnsServers = $effectiveDnsServers;
        } | ConvertTo-Json -Compress -Depth 3
    """
    ps_command = ps_script_template.replace("{index_placeholder}", adapter_index_str)

    success, stdout, stderr, rc = run_powershell_command(ps_command, suppress_output=True)

    if not success or not stdout:
        log_message(f"Failed to get DNS settings for Index {adapter_index_str}. RC: {rc}. Stderr: {stderr}", "ERROR")
        return None

    dns_data = parse_powershell_json_output(stdout, f"Get DNS for Index {adapter_index_str}")
    if dns_data is None:
        return None

    effective_servers = dns_data.get("EffectiveDnsServers", [])
    if effective_servers is None: effective_servers = []
    
    return {
        "name": dns_data.get("OriginalAdapterName", "Unknown Adapter"),
        "dhcp": dns_data.get("DhcpForDns", False),
        "servers": list(effective_servers)
    }


def set_dns_servers_ps(adapter_index: int | str, dns_servers: list[str]) -> bool:
    """
    Sets static DNS servers for a given adapter InterfaceIndex using PowerShell.
    """
    if adapter_index is None:
        log_message("Adapter InterfaceIndex is required to set DNS servers.", "ERROR")
        return False
    if not dns_servers:
        log_message("No DNS servers provided to set_dns_servers_ps.", "WARNING")
        return False

    adapter_index_str = str(adapter_index)
    servers_ps_array = ",".join([f'"{s}"' for s in dns_servers])
    ps_command = f'Set-DnsClientServerAddress -InterfaceIndex {adapter_index_str} -ServerAddresses ({servers_ps_array}) -ErrorAction Stop'
    
    success, stdout, stderr, rc = run_powershell_command(ps_command, suppress_output=False)

    if not success:
        error_message = stderr if stderr else stdout
        _print("set_dns_failed", f"Index {adapter_index_str}", error_message, log_level="ERROR")
        return False
    
    log_message(f"DNS successfully set for Index {adapter_index_str}.", "INFO")
    return True

def clear_dns_servers_ps(adapter_index: int | str) -> bool:
    """
    Clears statically configured DNS servers for an adapter InterfaceIndex.
    """
    if adapter_index is None:
        log_message("Adapter InterfaceIndex is required to clear DNS servers.", "ERROR")
        return False

    adapter_index_str = str(adapter_index)
    ps_command = f'Set-DnsClientServerAddress -InterfaceIndex {adapter_index_str} -ResetServerAddresses -ErrorAction Stop'
    
    success, stdout, stderr, rc = run_powershell_command(ps_command, suppress_output=False)

    if not success:
        error_message = stderr if stderr else stdout
        _print("restore_dns_failed", f"Index {adapter_index_str} (to DHCP/Reset)", error_message, log_level="ERROR")
        return False
        
    log_message(f"DNS settings cleared/reset for Index {adapter_index_str}.", "INFO")
    return True


def backup_and_set_dns_for_adapters(adapters_to_manage: list[dict]) -> tuple[dict, list[int | str]]:
    """
    Backs up current DNS settings and applies new DNS settings for the given adapters.
    Uses InterfaceIndex as the key.
    Returns a tuple: (backup_data_dict_keyed_by_index, list_of_successfully_managed_indices).
    """
    adapters_backup_data = {}
    managed_adapters_indices = [] 

    if not adapters_to_manage:
        _print("adapter_not_found")
        return adapters_backup_data, managed_adapters_indices

    for adapter_info in adapters_to_manage:
        index = adapter_info.get("InterfaceIndex")
        name = adapter_info.get("Name", "Unknown")
        guid = adapter_info.get("InterfaceGuid", "N/A") 

        if index is None:
            log_message(f"Adapter '{name}' found without an InterfaceIndex. Skipping.", "WARNING")
            continue

        index_key = int(index)

        # Corrected _print call to pass index_key directly for the second placeholder
        _print("backup_dns_for_adapter", name, index_key) 
        current_dns_settings = get_dns_settings_ps(index_key)

        if current_dns_settings:
            current_dns_settings["original_name"] = name
            current_dns_settings["guid"] = guid 
            adapters_backup_data[index_key] = current_dns_settings
            
            dns_type_str = "DHCP" if current_dns_settings.get("dhcp") else "Static"
            dns_servers_str = ", ".join(current_dns_settings.get("servers", [])) or "N/A"
            _print("backup_dns_success", name, dns_type_str, dns_servers_str)
            
            _print("set_dns_for_adapter", name, INSTALL_DNS_SERVERS)
            if set_dns_servers_ps(index_key, INSTALL_DNS_SERVERS):
                _print("set_dns_success", name)
                managed_adapters_indices.append(index_key)
            else:
                _print("set_dns_failed", name, "This adapter will not be actively managed with new DNS.", log_level="WARNING")
        else:
            _print("backup_dns_failed", name, "Cannot manage this adapter.", log_level="WARNING")
            
    if not managed_adapters_indices:
        _print("adapter_not_found")
        
    return adapters_backup_data, managed_adapters_indices


def restore_dns_for_managed_adapters(
    managed_indices: list[int | str], 
    backup_config: dict 
    ) -> bool:
    """
    Restores DNS settings for all managed adapters from the backup configuration.
    Uses InterfaceIndex.
    """
    all_restored_ok = True
    if not managed_indices:
        _print("no_managed_adapters", log_level="INFO")
        return True

    for index in managed_indices:
        index_key = int(index) 
        adapter_backup = backup_config.get(index_key)
        
        adapter_display_name = adapter_backup.get("original_name", f"Adapter Index {index_key}") if adapter_backup else f"Adapter Index {index_key}"
        _print("restore_dns_for_adapter", adapter_display_name)

        if not adapter_backup:
            _print("restore_dns_failed", adapter_display_name, "No backup data found.", log_level="WARNING")
            if clear_dns_servers_ps(index_key):
                log_message(f"Cleared DNS for {adapter_display_name} (Index {index_key}) as a fallback.", "INFO")
            else:
                log_message(f"Failed to clear DNS for {adapter_display_name} (Index {index_key}) as a fallback.", "ERROR")
                all_restored_ok = False
            continue

        restored_successfully = False
        if adapter_backup.get("dhcp", False):
            log_message(f"Restoring adapter {adapter_display_name} (Index {index_key}) to DHCP for DNS.", "DEBUG")
            if clear_dns_servers_ps(index_key):
                restored_successfully = True
        else: 
            static_servers_to_restore = adapter_backup.get("servers", [])
            if static_servers_to_restore:
                log_message(f"Restoring adapter {adapter_display_name} (Index {index_key}) to static DNS: {static_servers_to_restore}", "DEBUG")
                if set_dns_servers_ps(index_key, static_servers_to_restore):
                    restored_successfully = True
            else:
                log_message(f"Adapter {adapter_display_name} (Index {index_key}) was static with no servers. Clearing DNS.", "DEBUG")
                if clear_dns_servers_ps(index_key):
                    restored_successfully = True
        
        if restored_successfully:
            _print("restore_dns_success", adapter_display_name)
        else:
            all_restored_ok = False
            
    return all_restored_ok

def check_dns_responsiveness(dns_server_ip: str, domain_to_check:str = "google.com", timeout_s:int = 2) -> bool:
    """
    Checks if a DNS server can resolve a domain using nslookup.
    """
    from .system_utils import run_command 
    try:
        cmd = ["nslookup", f"-timeout={timeout_s}", "-nosearch", domain_to_check, dns_server_ip]
        success, stdout, stderr, rc = run_command(cmd, check_errors=False, suppress_output=True, expected_return_codes=[0, 1])
        
        if stdout: 
            output_lower = stdout.lower()
            if ("address:" in output_lower or "addresses:" in output_lower) and \
               not ("timed out" in output_lower) and \
               not ("server failed" in output_lower) and \
               not ("can't find" in output_lower):
                _print("dns_query_success", dns_server_ip, domain_to_check, log_level="DEBUG")
                return True
        
        err_details = f"rc={rc}, stdout: '{stdout[:100]}...', stderr: '{stderr[:100]}...'" if stdout or stderr else f"rc={rc}, No output."
        _print("dns_query_failed", dns_server_ip, domain_to_check, err_details, log_level="DEBUG")
        return False
    except Exception as e:
        log_message(f"Exception during nslookup for {dns_server_ip} with {domain_to_check}: {e}", "ERROR")
        return False

