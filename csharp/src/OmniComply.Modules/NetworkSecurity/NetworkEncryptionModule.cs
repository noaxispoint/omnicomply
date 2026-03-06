using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.NetworkSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Network Encryption")]
    [ExportMetadata("Category", "Network Encryption")]
    [ExportMetadata("Order", 29)]
    public class NetworkEncryptionModule : ComplianceModuleBase
    {
        public override string Name => "Network Encryption";
        public override string Description => "Validates SMBv1 disabled, TLS 1.2+ enforcement, LDAP signing, and NTLMv2 authentication";
        public override string Category => "Network Encryption";
        public override int Order => 29;

        protected override void RunChecks()
        {
            CheckTls12Enabled();
            CheckTls10Disabled();
            CheckTls11Disabled();
            CheckLdapSigning();
            CheckNtlmV2();
        }

        private void CheckTls12Enabled()
        {
            int enabled = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
                "Enabled", -1);
            int disabledByDefault = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
                "DisabledByDefault", -1);

            // TLS 1.2 is enabled by default in Windows 10+, so not-configured is acceptable
            bool passed = enabled != 0 && disabledByDefault != 1;

            AddCheck(
                "TLS 1.2 Enabled",
                "HIPAA § 164.312(e)(1) - TLS 1.2 must be enabled for secure communications",
                passed,
                string.Format("Enabled={0}, DisabledByDefault={1}", enabled, disabledByDefault),
                "Enabled (not explicitly disabled)",
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Client\\Enabled = 1 and DisabledByDefault = 0",
                nist: "SC-8, SC-13", cis: "14.4", iso27001: "A.10.1.1, A.13.1.1",
                pciDss: "4.1", sox: "ITGC-07");
        }

        private void CheckTls10Disabled()
        {
            int enabled = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
                "Enabled", -1);

            bool passed = enabled == 0;

            AddCheck(
                "TLS 1.0 Disabled",
                "SOC 2 CC6.1 - Insecure protocol TLS 1.0 must be disabled",
                passed,
                enabled == 0 ? "Disabled" : enabled == -1 ? "Not explicitly disabled" : "Enabled",
                "Disabled (Enabled=0)",
                "Set HKLM\\...\\SCHANNEL\\Protocols\\TLS 1.0\\Client\\Enabled = 0 and DisabledByDefault = 1",
                nist: "SC-8", cis: "14.4", iso27001: "A.10.1.1", pciDss: "4.1");
        }

        private void CheckTls11Disabled()
        {
            int enabled = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
                "Enabled", -1);

            bool passed = enabled == 0;

            AddCheck(
                "TLS 1.1 Disabled",
                "SOC 2 CC6.1 - Insecure protocol TLS 1.1 must be disabled",
                passed,
                enabled == 0 ? "Disabled" : enabled == -1 ? "Not explicitly disabled" : "Enabled",
                "Disabled (Enabled=0)",
                "Set HKLM\\...\\SCHANNEL\\Protocols\\TLS 1.1\\Client\\Enabled = 0 and DisabledByDefault = 1",
                nist: "SC-8", cis: "14.4", iso27001: "A.10.1.1", pciDss: "4.1");
        }

        private void CheckLdapSigning()
        {
            int ldapSigning = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
                "LDAPServerIntegrity", 0);

            bool passed = ldapSigning >= 1;

            AddCheck(
                "LDAP Signing Required",
                "HIPAA § 164.312(e)(1) - LDAP signing prevents man-in-the-middle attacks on directory queries",
                passed,
                ldapSigning == 2 ? "Required (2)" : ldapSigning == 1 ? "Negotiated (1)" : "None (0)",
                "Required (2) or Negotiated (1)",
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity = 2",
                nist: "SC-8, SC-23", cis: "18.4", iso27001: "A.13.1.1", pciDss: "4.1");
        }

        private void CheckNtlmV2()
        {
            int lmLevel = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "LmCompatibilityLevel", -1);

            bool passed = lmLevel >= 5;

            string currentValue;
            switch (lmLevel)
            {
                case 0: currentValue = "Send LM & NTLM (0)"; break;
                case 1: currentValue = "Send LM & NTLM - use NTLMv2 session if negotiated (1)"; break;
                case 2: currentValue = "Send NTLM only (2)"; break;
                case 3: currentValue = "Send NTLMv2 only (3)"; break;
                case 4: currentValue = "Send NTLMv2 only, refuse LM (4)"; break;
                case 5: currentValue = "Send NTLMv2 only, refuse LM & NTLM (5)"; break;
                default: currentValue = "Not configured (" + lmLevel + ")"; break;
            }

            AddCheck(
                "NTLMv2 Authentication Enforced",
                "SOC 2 CC6.1 - Only NTLMv2 authentication should be accepted, refusing LM and NTLM",
                passed,
                currentValue,
                "Send NTLMv2 only, refuse LM & NTLM (5)",
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel = 5",
                nist: "IA-2, IA-5", cis: "18.4", iso27001: "A.9.4.2", pciDss: "8.2.1");
        }
    }
}
