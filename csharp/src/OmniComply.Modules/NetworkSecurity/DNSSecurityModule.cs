using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.NetworkSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "DNS Security")]
    [ExportMetadata("Category", "DNS Security")]
    [ExportMetadata("Order", 24)]
    public class DNSSecurityModule : ComplianceModuleBase
    {
        public override string Name => "DNS Security";
        public override string Description => "Validates DNS over HTTPS configuration, DNSSEC support, and DNS client security settings";
        public override string Category => "DNS Security";
        public override int Order => 24;

        protected override void RunChecks()
        {
            CheckDnsOverHttps();
            CheckDnsSecureProtocol();
            CheckMulticastDnsDisabled();
        }

        private void CheckDnsOverHttps()
        {
            // Windows 11+ supports DoH natively
            int dohEnabled = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
                "EnableAutoDoh", -1);

            bool passed = dohEnabled == 2; // 2 = Require DoH

            string currentValue;
            switch (dohEnabled)
            {
                case 0: currentValue = "DoH disabled (0)"; break;
                case 1: currentValue = "DoH allowed but not required (1)"; break;
                case 2: currentValue = "DoH required (2)"; break;
                default: currentValue = "Not configured (" + dohEnabled + ")"; break;
            }

            AddCheck(
                "DNS over HTTPS (DoH)",
                "SOC 2 CC6.1 - DNS queries should be encrypted to prevent interception",
                passed,
                currentValue,
                "Required (EnableAutoDoh=2)",
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\EnableAutoDoh = 2",
                nist: "SC-8", cis: "9.2", iso27001: "A.13.1.1", pciDss: "4.1");
        }

        private void CheckDnsSecureProtocol()
        {
            // Check if DNSSEC validation is enabled
            int dnssecValidation = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "EnableDnssec", -1);

            // Also check DNS client LLMNR disable (covered more in advanced network, but relates to DNS security)
            int enableMultihomed = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "EnableMulticast", -1);

            bool passed = dnssecValidation == 1;

            AddCheck(
                "DNSSEC Validation",
                "NIST SC-20 - DNS responses should be validated for authenticity",
                passed,
                dnssecValidation == 1 ? "Enabled" : dnssecValidation == -1 ? "Not configured" : "Disabled",
                "Enabled via policy",
                "Configure via Group Policy: Computer Configuration > Administrative Templates > Network > DNS Client > Configure DNSSEC validation",
                nist: "SC-20, SC-21", cis: "9.2", iso27001: "A.13.1.1");
        }

        private void CheckMulticastDnsDisabled()
        {
            int enableMulticast = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "EnableMulticast", -1);

            bool passed = enableMulticast == 0;

            AddCheck(
                "Multicast DNS (mDNS) Disabled",
                "SOC 2 CC6.1 - Multicast DNS should be disabled to prevent name resolution attacks",
                passed,
                enableMulticast == 0 ? "Disabled" : enableMulticast == -1 ? "Not configured (enabled by default)" : "Enabled",
                "Disabled (EnableMulticast=0)",
                "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0",
                nist: "SC-7", cis: "9.2", iso27001: "A.13.1.1");
        }
    }
}
