using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.EndpointSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Endpoint Security")]
    [ExportMetadata("Category", "Endpoint Security")]
    [ExportMetadata("Order", 8)]
    public class EndpointSecurityModule : ComplianceModuleBase
    {
        public override string Name => "Endpoint Security";
        public override string Description => "Validates Windows Defender real-time protection, signature freshness, and Windows Firewall profiles";
        public override string Category => "Endpoint Security";
        public override int Order => 8;

        private const string Nist = "SI-3(1), SC-7";
        private const string Cis = "10.1, 13.3";
        private const string Iso = "A.12.2.1, A.13.1.1";
        private const string PciDss = "5.1.2, 1.1";

        protected override void RunChecks()
        {
            CheckDefenderRealTimeProtection();
            CheckDefenderSignatures();
            CheckFirewallDomainProfile();
            CheckFirewallPrivateProfile();
            CheckFirewallPublicProfile();
        }

        private void CheckDefenderRealTimeProtection()
        {
            const string wmiNamespace = @"root\Microsoft\Windows\Defender";
            var status = WmiHelper.QueryFirst("MSFT_MpComputerStatus", wmiNamespace);

            bool rtpEnabled = false;
            string currentValue = "Windows Defender Not Available";

            if (status != null)
            {
                rtpEnabled = WmiHelper.GetProperty(status, "RealTimeProtectionEnabled", false);
                currentValue = rtpEnabled ? "Enabled" : "Disabled";
            }

            AddCheck(
                "Windows Defender Real-Time Protection",
                "Real-time antivirus protection must be enabled",
                rtpEnabled,
                currentValue,
                "Enabled",
                "Enable real-time protection via Windows Security > Virus & threat protection > Manage settings, or Group Policy: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection > Turn on real-time protection.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Endpoint Security > Antivirus > Create Microsoft Defender Antivirus policy. Set 'Real-time protection' to 'Allowed'. Configure 'Cloud-delivered protection level' to 'High' for enhanced threat detection."
            );
        }

        private void CheckDefenderSignatures()
        {
            const string wmiNamespace = @"root\Microsoft\Windows\Defender";
            var status = WmiHelper.QueryFirst("MSFT_MpComputerStatus", wmiNamespace);

            bool signaturesUpToDate = false;
            string currentValue = "Windows Defender Not Available";

            if (status != null)
            {
                string lastUpdatedStr = WmiHelper.GetPropertyString(status, "AntivirusSignatureLastUpdated");
                if (lastUpdatedStr != null)
                {
                    DateTime lastUpdated;
                    // WMI datetime format: yyyyMMddHHmmss.ffffff+zzz
                    if (DateTime.TryParse(lastUpdatedStr, out lastUpdated) ||
                        TryParseWmiDateTime(lastUpdatedStr, out lastUpdated))
                    {
                        var daysSinceUpdate = (DateTime.Now - lastUpdated).TotalDays;
                        signaturesUpToDate = daysSinceUpdate <= 7;
                        currentValue = string.Format("Last updated: {0} ({1:F1} days ago)",
                            lastUpdated.ToString("yyyy-MM-dd HH:mm"), daysSinceUpdate);
                    }
                    else
                    {
                        currentValue = "Unable to parse update date: " + lastUpdatedStr;
                    }
                }
                else
                {
                    currentValue = "Signature date not available";
                }
            }

            AddCheck(
                "Antivirus Signature Freshness",
                "Antivirus signatures must be updated within the last 7 days",
                signaturesUpToDate,
                currentValue,
                "Updated within 7 days",
                "Update antivirus signatures via Windows Security > Virus & threat protection > Check for updates, or run: Update-MpSignature in PowerShell. Ensure Windows Update is configured for automatic definition updates.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Endpoint Security > Antivirus > Microsoft Defender Antivirus policy. Set 'Signature update interval' to '4' hours. Configure Windows Update rings to ensure regular definition delivery."
            );
        }

        private bool TryParseWmiDateTime(string wmiDate, out DateTime result)
        {
            result = DateTime.MinValue;
            try
            {
                if (wmiDate != null && wmiDate.Length >= 14)
                {
                    string dateStr = wmiDate.Substring(0, 4) + "-" +
                                     wmiDate.Substring(4, 2) + "-" +
                                     wmiDate.Substring(6, 2) + " " +
                                     wmiDate.Substring(8, 2) + ":" +
                                     wmiDate.Substring(10, 2) + ":" +
                                     wmiDate.Substring(12, 2);
                    return DateTime.TryParse(dateStr, out result);
                }
            }
            catch
            {
            }
            return false;
        }

        private void CheckFirewallDomainProfile()
        {
            CheckFirewallProfile("DomainProfile", "Domain");
        }

        private void CheckFirewallPrivateProfile()
        {
            CheckFirewallProfile("StandardProfile", "Private");
        }

        private void CheckFirewallPublicProfile()
        {
            CheckFirewallProfile("PublicProfile", "Public");
        }

        private void CheckFirewallProfile(string registryProfile, string displayName)
        {
            string regPath = string.Format(
                @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{0}",
                registryProfile);

            int firewallEnabled = RegistryHelper.GetDword(regPath, "EnableFirewall");

            bool passed = firewallEnabled == 1;
            string currentValue = firewallEnabled == 1 ? "Enabled" : firewallEnabled == 0 ? "Disabled" : "Not Configured (" + firewallEnabled + ")";

            AddCheck(
                "Windows Firewall - " + displayName + " Profile",
                "Windows Firewall must be enabled for the " + displayName + " profile",
                passed,
                currentValue,
                "Enabled",
                string.Format("Enable the {0} firewall profile via: netsh advfirewall set {1}profile state on. Or via Group Policy: Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security.",
                    displayName, displayName.ToLower()),
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: string.Format("Endpoint Security > Firewall > Create Microsoft Defender Firewall policy. Set '{0} network firewall' to 'Enable'. Configure inbound connections to 'Block' by default.", displayName)
            );
        }
    }
}
