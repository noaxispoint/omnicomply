using System;
using System.ComponentModel.Composition;
using System.Management;
using System.Text;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Models;

namespace OmniComply.Remediation
{
    [Export(typeof(IRemediationAction))]
    public class NetworkSecurityRemediation : IRemediationAction
    {
        public string Name => "Network Security Remediation";
        public string Description => "Disables insecure protocols and enables secure network configurations";
        public string Category => "Network Security";
        public bool RequiresReboot => true;

        public RemediationResult Execute()
        {
            var sb = new StringBuilder();
            bool needsReboot = false;

            // 1. Disable SMBv1 via registry
            if (RegistryHelper.SetDword(@"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0) &&
                RegistryHelper.SetDword(@"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 4))
            {
                sb.AppendLine("SMBv1 disabled (restart required)");
                needsReboot = true;
            }
            else
            {
                sb.AppendLine("Failed to disable SMBv1 via registry");
            }

            // 2. Enable SMB Client Signing
            if (RegistryHelper.SetDword(@"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 1))
                sb.AppendLine("SMB client signing enabled");
            else
                sb.AppendLine("Failed to enable SMB client signing");

            // 3. Enable SMB Server Signing
            if (RegistryHelper.SetDword(@"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 1))
                sb.AppendLine("SMB server signing enabled");
            else
                sb.AppendLine("Failed to enable SMB server signing");

            // 4. Disable LLMNR
            if (RegistryHelper.SetDword(@"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0))
                sb.AppendLine("LLMNR disabled");
            else
                sb.AppendLine("Failed to disable LLMNR");

            // 5. Enable RDP NLA
            if (RegistryHelper.SetDword(@"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1))
                sb.AppendLine("RDP Network Level Authentication enabled");
            else
                sb.AppendLine("Failed to enable RDP NLA");

            // 6. Enable firewall logging via netsh
            var fwResult = ProcessHelper.RunNetSh("advfirewall set allprofiles logging droppedconnections enable");
            if (fwResult.Success)
                sb.AppendLine("Firewall dropped connection logging enabled");

            // 7. Disable NetBIOS over TCP/IP
            try
            {
                var adapters = WmiHelper.QueryAll("Win32_NetworkAdapterConfiguration");
                int disabled = 0;
                foreach (var adapter in adapters)
                {
                    bool ipEnabled = WmiHelper.GetProperty(adapter, "IPEnabled", false);
                    if (ipEnabled)
                    {
                        try
                        {
                            adapter.InvokeMethod("SetTcpipNetbios", new object[] { (uint)2 });
                            disabled++;
                        }
                        catch { }
                    }
                }
                sb.AppendFormat("NetBIOS disabled on {0} adapter(s)\n", disabled);
            }
            catch (Exception ex)
            {
                sb.AppendLine("Failed to disable NetBIOS: " + ex.Message);
            }

            return RemediationResult.Succeeded(sb.ToString(), needsReboot);
        }

        public RemediationResult DryRun()
        {
            return RemediationResult.Succeeded(
                "Would apply:\n" +
                "  1. Disable SMBv1 protocol (requires restart)\n" +
                "  2. Enable SMB client signing\n" +
                "  3. Enable SMB server signing\n" +
                "  4. Disable LLMNR\n" +
                "  5. Enable RDP Network Level Authentication\n" +
                "  6. Enable Windows Firewall logging\n" +
                "  7. Disable NetBIOS over TCP/IP on all adapters");
        }
    }
}
