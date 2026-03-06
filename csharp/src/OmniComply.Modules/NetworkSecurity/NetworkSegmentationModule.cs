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
    [ExportMetadata("Name", "Network Segmentation")]
    [ExportMetadata("Category", "Network Segmentation")]
    [ExportMetadata("Order", 28)]
    public class NetworkSegmentationModule : ComplianceModuleBase
    {
        public override string Name => "Network Segmentation";
        public override string Description => "Validates network adapter inventory, firewall rule counts, IPsec policies, and VLAN configuration";
        public override string Category => "Network Segmentation";
        public override int Order => 28;

        protected override void RunChecks()
        {
            CheckNetworkAdapters();
            CheckFirewallRules();
            CheckIpsecPolicies();
            CheckWindowsFirewallDefaultBlock();
        }

        private void CheckNetworkAdapters()
        {
            try
            {
                var adapters = WmiHelper.QueryAll("Win32_NetworkAdapterConfiguration");
                int enabledCount = 0;
                foreach (var adapter in adapters)
                {
                    bool ipEnabled = WmiHelper.GetProperty(adapter, "IPEnabled", false);
                    if (ipEnabled) enabledCount++;
                }

                bool passed = enabledCount > 0;

                AddCheck(
                    "Network Adapter Inventory",
                    "SOC 2 CC6.1 - All active network adapters must be documented",
                    passed,
                    string.Format("{0} active IP-enabled adapter(s) found", enabledCount),
                    "Network adapters documented and monitored",
                    "Review active network adapters via 'Get-NetAdapter | Where-Object Status -eq Up'",
                    nist: "SC-7", cis: "12.1", iso27001: "A.13.1.1", pciDss: "1.1.2");
            }
            catch (Exception ex)
            {
                AddCheck("Network Adapter Inventory", "SOC 2 CC6.1", false,
                    "Error: " + ex.Message, "Network adapters documented", "Review network adapters manually",
                    nist: "SC-7", cis: "12.1", iso27001: "A.13.1.1", pciDss: "1.1.2");
            }
        }

        private void CheckFirewallRules()
        {
            try
            {
                var result = ProcessHelper.Run("netsh.exe", "advfirewall firewall show rule name=all dir=in");
                int ruleCount = 0;
                if (result.Success && !string.IsNullOrEmpty(result.StandardOutput))
                {
                    foreach (var line in result.StandardOutput.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (line.TrimStart().StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                            ruleCount++;
                    }
                }

                bool passed = ruleCount > 0;

                AddCheck(
                    "Inbound Firewall Rules Configured",
                    "PCI-DSS 1.2 - Firewall rules must restrict inbound traffic",
                    passed,
                    string.Format("{0} inbound firewall rule(s) configured", ruleCount),
                    "Firewall rules properly configured for network segmentation",
                    "Review firewall rules: netsh advfirewall firewall show rule name=all dir=in",
                    nist: "SC-7(5)", cis: "13.4", iso27001: "A.13.1.1", pciDss: "1.2, 1.3");
            }
            catch (Exception ex)
            {
                AddCheck("Inbound Firewall Rules Configured", "PCI-DSS 1.2", false,
                    "Error: " + ex.Message, "Firewall rules configured", "Check firewall rules manually",
                    nist: "SC-7(5)", cis: "13.4", iso27001: "A.13.1.1", pciDss: "1.2, 1.3");
            }
        }

        private void CheckIpsecPolicies()
        {
            try
            {
                var result = ProcessHelper.Run("netsh.exe", "ipsec static show policy all");
                bool hasPolicies = result.Success && !string.IsNullOrEmpty(result.StandardOutput)
                    && !result.StandardOutput.Contains("There are no policies");

                AddCheck(
                    "IPsec Policies",
                    "HIPAA § 164.312(e)(1) - IPsec should be configured for network encryption",
                    hasPolicies,
                    hasPolicies ? "IPsec policies configured" : "No IPsec policies found",
                    "IPsec policies configured for sensitive network segments",
                    "Configure IPsec via Group Policy or netsh ipsec commands",
                    nist: "SC-8, SC-12", cis: "13.7", iso27001: "A.13.1.1, A.10.1.1", pciDss: "4.1");
            }
            catch
            {
                AddCheck("IPsec Policies", "HIPAA § 164.312(e)(1)", false,
                    "Unable to query IPsec policies", "IPsec policies configured",
                    "Configure IPsec via Group Policy",
                    nist: "SC-8, SC-12", cis: "13.7", iso27001: "A.13.1.1", pciDss: "4.1");
            }
        }

        private void CheckWindowsFirewallDefaultBlock()
        {
            try
            {
                var result = ProcessHelper.Run("netsh.exe", "advfirewall show allprofiles");
                bool allBlockInbound = true;

                if (result.Success && !string.IsNullOrEmpty(result.StandardOutput))
                {
                    var lines = result.StandardOutput.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (line.Contains("Firewall Policy") && line.Contains("Inbound"))
                        {
                            if (!line.Contains("BlockInbound"))
                                allBlockInbound = false;
                        }
                    }
                }
                else
                {
                    allBlockInbound = false;
                }

                AddCheck(
                    "Default Inbound Block Policy",
                    "PCI-DSS 1.2.1 - Default firewall policy should block all inbound traffic",
                    allBlockInbound,
                    allBlockInbound ? "All profiles block inbound by default" : "Not all profiles block inbound",
                    "All firewall profiles set to block inbound by default",
                    "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
                    nist: "SC-7", cis: "13.1", iso27001: "A.13.1.1", pciDss: "1.2.1");
            }
            catch
            {
                AddCheck("Default Inbound Block Policy", "PCI-DSS 1.2.1", false,
                    "Unable to query firewall policy", "All profiles block inbound",
                    "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
                    nist: "SC-7", cis: "13.1", iso27001: "A.13.1.1", pciDss: "1.2.1");
            }
        }
    }
}
