using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.EndpointSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Advanced Defender")]
    [ExportMetadata("Category", "Advanced Defender")]
    [ExportMetadata("Order", 17)]
    public class AdvancedDefenderModule : ComplianceModuleBase
    {
        public override string Name => "Advanced Defender";
        public override string Description => "Validates advanced Microsoft Defender features including Controlled Folder Access, Network Protection, ASR rules, and Exploit Protection";
        public override string Category => "Advanced Defender";
        public override int Order => 17;

        private const string Nist = "SI-3, SC-7";
        private const string Cis = "10.5";
        private const string Iso = "A.12.2.1";

        protected override void RunChecks()
        {
            CheckControlledFolderAccess();
            CheckNetworkProtection();
            CheckAsrRules();
            CheckExploitProtection();
        }

        private void CheckControlledFolderAccess()
        {
            int cfaEnabled = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access",
                "EnableControlledFolderAccess");

            bool passed = cfaEnabled == 1;
            string currentValue;
            switch (cfaEnabled)
            {
                case 0: currentValue = "Disabled (0)"; break;
                case 1: currentValue = "Enabled (1)"; break;
                case 2: currentValue = "Audit Mode (2)"; break;
                default: currentValue = "Not Configured (" + cfaEnabled + ")"; break;
            }

            AddCheck(
                "Controlled Folder Access",
                "Controlled Folder Access must be enabled to protect important folders from ransomware and unauthorized changes",
                passed,
                currentValue,
                "Enabled (1)",
                "Enable Controlled Folder Access via Windows Security > Virus & threat protection > Ransomware protection, or Group Policy: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Controlled Folder Access > Configure Controlled folder access. Set to 'Enabled'. Registry: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\EnableControlledFolderAccess = 1.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckNetworkProtection()
        {
            int npEnabled = RegistryHelper.GetDword(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection",
                "EnableNetworkProtection");

            bool passed = npEnabled == 1;
            string currentValue;
            switch (npEnabled)
            {
                case 0: currentValue = "Disabled (0)"; break;
                case 1: currentValue = "Enabled (1)"; break;
                case 2: currentValue = "Audit Mode (2)"; break;
                default: currentValue = "Not Configured (" + npEnabled + ")"; break;
            }

            AddCheck(
                "Network Protection",
                "Network Protection must be enabled to block connections to malicious domains and IP addresses",
                passed,
                currentValue,
                "Enabled (1)",
                "Enable Network Protection via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Network Protection > Prevent users and apps from accessing dangerous websites. Set to 'Enabled (Block)'. PowerShell: Set-MpPreference -EnableNetworkProtection Enabled.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckAsrRules()
        {
            bool rulesConfigured = RegistryHelper.KeyExists(
                @"HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules");

            // Check if there are actual rule values configured
            string currentValue = "No ASR rules configured";
            bool passed = false;

            if (rulesConfigured)
            {
                // Attempt to read a well-known ASR rule GUID to verify rules are actually present
                // Common rule: Block Office applications from creating executable content
                var ruleValue = RegistryHelper.GetValue(
                    @"HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                    "3B576869-A4EC-4529-8536-B80A7769E899");

                if (ruleValue != null)
                {
                    passed = true;
                    currentValue = "ASR rules configured";
                }
                else
                {
                    // Check another well-known rule: Block credential stealing from LSASS
                    ruleValue = RegistryHelper.GetValue(
                        @"HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2");

                    if (ruleValue != null)
                    {
                        passed = true;
                        currentValue = "ASR rules configured";
                    }
                    else
                    {
                        currentValue = "ASR rules key exists but no common rules found";
                    }
                }
            }

            AddCheck(
                "Attack Surface Reduction (ASR) Rules",
                "Attack Surface Reduction rules must be configured to mitigate common attack vectors",
                passed,
                currentValue,
                "ASR rules configured and enabled",
                "Configure ASR rules via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules. Add recommended rule GUIDs with action '1' (Block). PowerShell: Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckExploitProtection()
        {
            // Check for system-level exploit mitigation via Image File Execution Options
            // and the ProcessMitigationOptions system-wide settings
            bool ifeoExists = RegistryHelper.KeyExists(
                @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");

            // Check for system-wide exploit protection settings (DEP, ASLR, SEHOP, CFG)
            int depPolicy = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
                "MitigationAuditOptions");

            int mitigationOptions = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
                "MitigationOptions");

            // Also check for the exploit protection XML configuration
            string exploitProtectionConfig = RegistryHelper.GetString(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection",
                "ExploitProtectionSettings");

            bool hasExploitConfig = !string.IsNullOrEmpty(exploitProtectionConfig);
            bool hasMitigationPolicy = mitigationOptions > 0 || depPolicy > 0;
            bool passed = hasExploitConfig || hasMitigationPolicy;

            string currentValue;
            if (hasExploitConfig)
                currentValue = "Exploit Protection policy configured";
            else if (hasMitigationPolicy)
                currentValue = "System-level mitigation options present";
            else
                currentValue = "No exploit protection configuration detected";

            AddCheck(
                "Exploit Protection",
                "System-level exploit protection settings must be configured (DEP, ASLR, SEHOP, CFG)",
                passed,
                currentValue,
                "Exploit protection configured with system-level mitigations",
                "Configure Exploit Protection via Windows Security > App & browser control > Exploit protection settings. Export the configuration as XML and deploy via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Exploit Guard > Exploit Protection > Use a common set of exploit protection settings. PowerShell: Set-ProcessMitigation -System -Enable DEP,SEHOP.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }
    }
}
