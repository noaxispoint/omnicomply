using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.NetworkSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Advanced Network Security")]
    [ExportMetadata("Category", "Advanced Network Security")]
    [ExportMetadata("Order", 15)]
    public class AdvancedNetworkSecurityModule : ComplianceModuleBase
    {
        public override string Name => "Advanced Network Security";
        public override string Description => "Validates LLMNR, NetBIOS, RDP Network Level Authentication, and firewall logging configuration";
        public override string Category => "Advanced Network Security";
        public override int Order => 15;

        private const string Nist = "SC-7, AC-17";
        private const string Cis = "4.8, 12.6";
        private const string Iso = "A.13.1.1";

        protected override void RunChecks()
        {
            CheckLlmnrDisabled();
            CheckNetBiosDisabled();
            CheckRdpNla();
            CheckFirewallLoggingDroppedPackets();
            CheckFirewallLoggingSuccessfulConnections();
        }

        private void CheckLlmnrDisabled()
        {
            try
            {
                int enableMulticast = RegistryHelper.GetDword(
                    @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                    "EnableMulticast");

                // EnableMulticast == 0 means LLMNR is disabled
                bool passed = enableMulticast == 0;
                string currentValue;
                switch (enableMulticast)
                {
                    case 0: currentValue = "Disabled (0)"; break;
                    case 1: currentValue = "Enabled (1)"; break;
                    default: currentValue = "Not Configured via policy (" + enableMulticast + ") - LLMNR may be active by default"; break;
                }

                AddCheck(
                    "LLMNR (Link-Local Multicast Name Resolution) Disabled",
                    "LLMNR must be disabled to prevent name resolution poisoning and credential relay attacks",
                    passed,
                    currentValue,
                    "Disabled (0)",
                    "Disable LLMNR via Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > "
                    + "Turn off multicast name resolution = Enabled. "
                    + "Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0 (DWORD).",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "LLMNR (Link-Local Multicast Name Resolution) Disabled",
                    "LLMNR must be disabled to prevent name resolution poisoning and credential relay attacks",
                    false,
                    "Error: " + ex.Message,
                    "Disabled (0)",
                    "Disable LLMNR via Group Policy: Turn off multicast name resolution = Enabled",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
        }

        private void CheckNetBiosDisabled()
        {
            try
            {
                // Query all IP-enabled network adapters via WMI
                var adapters = WmiHelper.QueryAll("Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE");

                if (adapters == null || adapters.Count == 0)
                {
                    AddCheck(
                        "NetBIOS over TCP/IP Disabled",
                        "NetBIOS over TCP/IP must be disabled on all network adapters to prevent name poisoning attacks",
                        false,
                        "No IP-enabled network adapters found",
                        "Disabled (TcpipNetbios=2) on all adapters",
                        "Check network adapter configuration - no IP-enabled adapters were detected",
                        nist: Nist, cis: Cis, iso27001: Iso
                    );
                    return;
                }

                bool allDisabled = true;
                var adapterDetails = new List<string>();

                foreach (var adapter in adapters)
                {
                    string description = WmiHelper.GetPropertyString(adapter, "Description") ?? "Unknown Adapter";
                    int tcpipNetbios = WmiHelper.GetProperty(adapter, "TcpipNetbios", -1);

                    // TcpipNetbios: 0=Default (use DHCP), 1=Enable, 2=Disable
                    bool isDisabled = tcpipNetbios == 2;
                    if (!isDisabled)
                    {
                        allDisabled = false;
                    }

                    string statusText;
                    switch (tcpipNetbios)
                    {
                        case 0: statusText = "Default/DHCP (0)"; break;
                        case 1: statusText = "Enabled (1)"; break;
                        case 2: statusText = "Disabled (2)"; break;
                        default: statusText = "Unknown (" + tcpipNetbios + ")"; break;
                    }

                    adapterDetails.Add(string.Format("{0}: {1}", description, statusText));
                }

                string currentValue = string.Join("; ", adapterDetails);
                if (currentValue.Length > 500)
                {
                    currentValue = currentValue.Substring(0, 497) + "...";
                }

                AddCheck(
                    "NetBIOS over TCP/IP Disabled",
                    "NetBIOS over TCP/IP must be disabled on all network adapters to prevent name poisoning attacks",
                    allDisabled,
                    currentValue,
                    "Disabled (TcpipNetbios=2) on all adapters",
                    "Disable NetBIOS on each adapter: Network Connections > Adapter Properties > Internet Protocol Version 4 > "
                    + "Advanced > WINS tab > Disable NetBIOS over TCP/IP. "
                    + "Or via DHCP option 001 (set to 0x2). "
                    + "PowerShell: Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | "
                    + "Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbios=2}.",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "NetBIOS over TCP/IP Disabled",
                    "NetBIOS over TCP/IP must be disabled on all network adapters to prevent name poisoning attacks",
                    false,
                    "Error: " + ex.Message,
                    "Disabled (TcpipNetbios=2) on all adapters",
                    "Disable NetBIOS on each adapter via adapter properties > WINS tab > Disable NetBIOS over TCP/IP",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
        }

        private void CheckRdpNla()
        {
            try
            {
                int userAuthentication = RegistryHelper.GetDword(
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                    "UserAuthentication");

                // UserAuthentication == 1 means NLA is required
                bool passed = userAuthentication == 1;
                string currentValue;
                switch (userAuthentication)
                {
                    case 0: currentValue = "NLA Not Required (0) - any RDP client can connect"; break;
                    case 1: currentValue = "NLA Required (1)"; break;
                    default: currentValue = "Not Configured (" + userAuthentication + ")"; break;
                }

                AddCheck(
                    "RDP Network Level Authentication (NLA)",
                    "Network Level Authentication must be required for RDP connections to prevent unauthorized session initiation",
                    passed,
                    currentValue,
                    "Required (UserAuthentication=1)",
                    "Enable NLA via System Properties > Remote tab > check 'Allow connections only from computers running Remote Desktop with NLA'. "
                    + "Or via Group Policy: Computer Configuration > Administrative Templates > Windows Components > "
                    + "Remote Desktop Services > Remote Desktop Session Host > Security > Require user authentication for remote connections by using NLA = Enabled. "
                    + "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication = 1 (DWORD).",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "RDP Network Level Authentication (NLA)",
                    "Network Level Authentication must be required for RDP connections to prevent unauthorized session initiation",
                    false,
                    "Error: " + ex.Message,
                    "Required (UserAuthentication=1)",
                    "Enable NLA via System Properties > Remote tab or Group Policy",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
        }

        private void CheckFirewallLoggingDroppedPackets()
        {
            try
            {
                int logDroppedPackets = RegistryHelper.GetDword(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging",
                    "LogDroppedPackets");

                bool passed = logDroppedPackets == 1;
                string currentValue;
                switch (logDroppedPackets)
                {
                    case 0: currentValue = "Disabled (0)"; break;
                    case 1: currentValue = "Enabled (1)"; break;
                    default: currentValue = "Not Configured (" + logDroppedPackets + ")"; break;
                }

                AddCheck(
                    "Firewall Logging - Dropped Packets (Domain Profile)",
                    "Windows Firewall must log dropped packets on the Domain profile for security monitoring and incident response",
                    passed,
                    currentValue,
                    "Enabled (1)",
                    "Enable dropped packet logging via Group Policy: Computer Configuration > Windows Settings > Security Settings > "
                    + "Windows Defender Firewall with Advanced Security > Properties > Domain Profile > Logging > Log dropped packets = Yes. "
                    + "Or via netsh: netsh advfirewall set domainprofile logging droppedconnections enable. "
                    + "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\Logging\\LogDroppedPackets = 1 (DWORD).",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Firewall Logging - Dropped Packets (Domain Profile)",
                    "Windows Firewall must log dropped packets on the Domain profile for security monitoring and incident response",
                    false,
                    "Error: " + ex.Message,
                    "Enabled (1)",
                    "Enable dropped packet logging via: netsh advfirewall set domainprofile logging droppedconnections enable",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
        }

        private void CheckFirewallLoggingSuccessfulConnections()
        {
            try
            {
                int logSuccessful = RegistryHelper.GetDword(
                    @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging",
                    "LogSuccessfulConnections");

                bool passed = logSuccessful == 1;
                string currentValue;
                switch (logSuccessful)
                {
                    case 0: currentValue = "Disabled (0)"; break;
                    case 1: currentValue = "Enabled (1)"; break;
                    default: currentValue = "Not Configured (" + logSuccessful + ")"; break;
                }

                AddCheck(
                    "Firewall Logging - Successful Connections (Domain Profile)",
                    "Windows Firewall must log successful connections on the Domain profile for audit trail and forensic analysis",
                    passed,
                    currentValue,
                    "Enabled (1)",
                    "Enable successful connection logging via Group Policy: Computer Configuration > Windows Settings > Security Settings > "
                    + "Windows Defender Firewall with Advanced Security > Properties > Domain Profile > Logging > Log successful connections = Yes. "
                    + "Or via netsh: netsh advfirewall set domainprofile logging allowedconnections enable. "
                    + "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\Logging\\LogSuccessfulConnections = 1 (DWORD).",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Firewall Logging - Successful Connections (Domain Profile)",
                    "Windows Firewall must log successful connections on the Domain profile for audit trail and forensic analysis",
                    false,
                    "Error: " + ex.Message,
                    "Enabled (1)",
                    "Enable successful connection logging via: netsh advfirewall set domainprofile logging allowedconnections enable",
                    nist: Nist, cis: Cis, iso27001: Iso
                );
            }
        }
    }
}
