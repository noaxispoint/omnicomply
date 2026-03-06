using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.Encryption
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Credential Guard")]
    [ExportMetadata("Category", "Credential Guard")]
    [ExportMetadata("Order", 19)]
    public class CredentialGuardModule : ComplianceModuleBase
    {
        public override string Name => "Credential Guard";
        public override string Description => "Validates Credential Guard, LSA protection, cached logon limits, and WDigest configuration";
        public override string Category => "Credential Guard";
        public override int Order => 19;

        private const string Nist = "SC-28, IA-5";
        private const string Cis = "18.3.6";
        private const string Iso = "A.10.1.2";
        private const string Sox = "ITGC-07";

        protected override void RunChecks()
        {
            CheckCredentialGuard();
            CheckLsaProtection();
            CheckCachedLogons();
            CheckWDigest();
        }

        private void CheckCredentialGuard()
        {
            int lsaCfgFlags = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\LSA",
                "LsaCfgFlags");

            bool passed = lsaCfgFlags == 1 || lsaCfgFlags == 2;
            string currentValue;
            switch (lsaCfgFlags)
            {
                case 0: currentValue = "Disabled (0)"; break;
                case 1: currentValue = "Enabled with UEFI lock (1)"; break;
                case 2: currentValue = "Enabled without lock (2)"; break;
                default: currentValue = "Not Configured (" + lsaCfgFlags + ")"; break;
            }

            AddCheck(
                "Credential Guard",
                "Windows Credential Guard must be enabled to protect credentials in memory",
                passed,
                currentValue,
                "Enabled with UEFI lock (1) or Enabled without lock (2)",
                "Enable Credential Guard via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security. Set Credential Guard to 'Enabled with UEFI lock'. Alternatively, set registry HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\LsaCfgFlags to 1.",
                nist: Nist, cis: Cis, iso27001: Iso, sox: Sox
            );
        }

        private void CheckLsaProtection()
        {
            int runAsPPL = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "RunAsPPL");

            bool passed = runAsPPL == 1;
            string currentValue = runAsPPL == 1 ? "Enabled (1)" : runAsPPL == 0 ? "Disabled (0)" : "Not Configured (" + runAsPPL + ")";

            AddCheck(
                "LSA Protection (RunAsPPL)",
                "LSA must run as a Protected Process Light to prevent credential theft",
                passed,
                currentValue,
                "Enabled (1)",
                "Enable LSA Protection by setting registry value HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1 (DWORD). A reboot is required for the change to take effect.",
                nist: Nist, cis: Cis, iso27001: Iso, sox: Sox
            );
        }

        private void CheckCachedLogons()
        {
            string cachedLogonsStr = RegistryHelper.GetString(
                @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "CachedLogonsCount",
                null);

            int cachedLogons = -1;
            bool parsed = cachedLogonsStr != null && int.TryParse(cachedLogonsStr, out cachedLogons);

            bool passed = parsed && cachedLogons >= 0 && cachedLogons <= 4;
            string currentValue = parsed ? cachedLogons.ToString() : (cachedLogonsStr ?? "Not Configured");

            AddCheck(
                "Cached Logon Credentials",
                "Number of cached logon credentials must be limited to 4 or fewer",
                passed,
                currentValue + " cached logon(s)",
                "4 or fewer",
                "Set the cached logons count via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Interactive logon: Number of previous logons to cache'. Set to 4 or lower. Registry: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount.",
                nist: Nist, cis: Cis, iso27001: Iso, sox: Sox
            );
        }

        private void CheckWDigest()
        {
            int useLogonCredential = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                "UseLogonCredential");

            bool passed = useLogonCredential == 0;
            string currentValue;
            switch (useLogonCredential)
            {
                case 0: currentValue = "Disabled (0) - Credentials not stored in memory"; break;
                case 1: currentValue = "Enabled (1) - Credentials stored in plaintext"; break;
                default: currentValue = "Not Configured (" + useLogonCredential + ") - May default to enabled on older systems"; break;
            }

            AddCheck(
                "WDigest Authentication",
                "WDigest plaintext credential storage must be disabled",
                passed,
                currentValue,
                "Disabled (0)",
                "Disable WDigest by setting registry value HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0 (DWORD). This prevents plaintext passwords from being stored in LSASS memory.",
                nist: Nist, cis: Cis, iso27001: Iso, sox: Sox
            );
        }
    }
}
