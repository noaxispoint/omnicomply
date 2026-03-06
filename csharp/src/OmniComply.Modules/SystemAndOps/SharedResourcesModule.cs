using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.SystemAndOps
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Shared Resources")]
    [ExportMetadata("Category", "Shared Resources")]
    [ExportMetadata("Order", 24)]
    public class SharedResourcesModule : ComplianceModuleBase
    {
        public override string Name => "Shared Resources";
        public override string Description => "Validates administrative share configuration, null session restrictions, and SMB encryption settings";
        public override string Category => "Shared Resources";
        public override int Order => 24;

        private const string Nist = "AC-3, SC-8";
        private const string Cis = "5.6";
        private const string Iso = "A.13.1.1";
        private const string PciDss = "7.1";

        protected override void RunChecks()
        {
            CheckAdministrativeShares();
            CheckNullSessionAccess();
            CheckSmbEncryption();
        }

        /// <summary>
        /// Checks for the presence of administrative shares (C$, ADMIN$) by running "net share".
        /// Administrative shares are expected on domain-joined systems but should be noted.
        /// </summary>
        private void CheckAdministrativeShares()
        {
            var result = ProcessHelper.RunCmd("net share");

            bool hasCDollar = false;
            bool hasAdminDollar = false;
            string currentValue;

            if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                string output = result.StandardOutput;
                string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (string line in lines)
                {
                    string trimmedLine = line.TrimStart();
                    if (trimmedLine.StartsWith("C$", StringComparison.OrdinalIgnoreCase))
                        hasCDollar = true;
                    if (trimmedLine.StartsWith("ADMIN$", StringComparison.OrdinalIgnoreCase))
                        hasAdminDollar = true;
                }

                if (hasCDollar && hasAdminDollar)
                    currentValue = "Administrative shares present: C$, ADMIN$ (default on domain systems)";
                else if (hasCDollar)
                    currentValue = "Administrative share present: C$";
                else if (hasAdminDollar)
                    currentValue = "Administrative share present: ADMIN$";
                else
                    currentValue = "No administrative shares detected";
            }
            else
            {
                currentValue = "Unable to enumerate shares: " + (result.StandardError ?? "Unknown error");
            }

            // Administrative shares on domain systems are expected; this is informational.
            // We pass if they are NOT present (hardened), but note they are expected in domain environments.
            bool passed = !hasCDollar && !hasAdminDollar;

            AddCheck(
                check: "Administrative Shares",
                requirement: "Administrative shares (C$, ADMIN$) should be reviewed; they are expected on domain systems but may expose risk on standalone systems",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "No unnecessary administrative shares (or documented exception for domain systems)",
                remediation: "To disable administrative shares on non-domain systems, set registry: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v AutoShareWks /t REG_DWORD /d 0 /f. Note: Disabling on domain-joined systems may break management tools such as SCCM, Group Policy, and remote administration.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'Lanman Server' and configure 'AutoShareWks' to 0 for workstations. For domain-joined devices, document the risk acceptance for administrative shares in your compliance baseline."
            );
        }

        /// <summary>
        /// Checks whether null session (anonymous) access is restricted.
        /// RestrictAnonymous should be >= 1 to prevent anonymous enumeration.
        /// </summary>
        private void CheckNullSessionAccess()
        {
            const string regPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
            int restrictAnonymous = RegistryHelper.GetDword(regPath, "RestrictAnonymous", -1);

            bool passed = restrictAnonymous >= 1;
            string currentValue;

            if (restrictAnonymous == -1)
                currentValue = "Not Configured (defaults may allow anonymous access)";
            else if (restrictAnonymous == 0)
                currentValue = "Disabled (RestrictAnonymous = 0 - anonymous access allowed)";
            else if (restrictAnonymous == 1)
                currentValue = "Restricted (RestrictAnonymous = 1 - cannot enumerate SAM accounts/shares)";
            else if (restrictAnonymous == 2)
                currentValue = "Fully Restricted (RestrictAnonymous = 2 - no access without explicit permissions)";
            else
                currentValue = "RestrictAnonymous = " + restrictAnonymous;

            AddCheck(
                check: "Null Session Access Restriction",
                requirement: "Anonymous (null session) access must be restricted to prevent unauthorized enumeration of system resources",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "RestrictAnonymous >= 1",
                remediation: "Restrict anonymous access via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' = Enabled. Or set registry: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'Network access' and set 'Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled'. Alternatively, use Endpoint Security > Attack surface reduction to restrict anonymous network access."
            );
        }

        /// <summary>
        /// Checks whether SMB encryption is enabled on the LanmanServer.
        /// EncryptData should be 1 to require encryption for SMB traffic.
        /// </summary>
        private void CheckSmbEncryption()
        {
            const string regPath = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
            int encryptData = RegistryHelper.GetDword(regPath, "EncryptData", -1);

            bool passed = encryptData == 1;
            string currentValue;

            if (encryptData == -1)
                currentValue = "Not Configured (SMB encryption not enforced)";
            else if (encryptData == 0)
                currentValue = "Disabled (EncryptData = 0)";
            else if (encryptData == 1)
                currentValue = "Enabled (EncryptData = 1)";
            else
                currentValue = "EncryptData = " + encryptData;

            AddCheck(
                check: "SMB Encryption",
                requirement: "SMB server encryption must be enabled to protect data in transit on file shares",
                passed: passed,
                currentValue: currentValue,
                expectedValue: "Enabled (EncryptData = 1)",
                remediation: "Enable SMB encryption via PowerShell: Set-SmbServerConfiguration -EncryptData $true -Force. Or set registry: reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v EncryptData /t REG_DWORD /d 1 /f. Note: Requires SMB 3.0+ clients.",
                nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss,
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog. Search for 'Lanman Server' and set 'EncryptData' to '1'. Ensure client devices also support SMB 3.0+ encryption by configuring the LanmanWorkstation settings."
            );
        }
    }
}
