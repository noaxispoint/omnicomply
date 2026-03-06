using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Helpers;
using OmniComply.Core.Interfaces;

namespace OmniComply.Modules.AuditAndLogging
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Security Settings")]
    [ExportMetadata("Category", "Security Settings")]
    [ExportMetadata("Order", 5)]
    public class SecuritySettingsModule : ComplianceModuleBase
    {
        public override string Name => "Security Settings";
        public override string Description => "Validates security settings related to audit logging including command line auditing, advanced audit policy, and PowerShell logging";
        public override string Category => "Security Settings";
        public override int Order => 5;

        private const string CmdLineAuditPath = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
        private const string LsaPath = @"HKLM\System\CurrentControlSet\Control\Lsa";
        private const string PsModuleLoggingPath = @"HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging";
        private const string PsScriptBlockLoggingPath = @"HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";

        protected override void RunChecks()
        {
            CheckCommandLineProcessAuditing();
            CheckAdvancedAuditPolicyOverride();
            CheckPowerShellModuleLogging();
            CheckPowerShellScriptBlockLogging();
        }

        /// <summary>
        /// Checks if command line process creation auditing is enabled.
        /// When enabled, the full command line is recorded in process creation audit events.
        /// </summary>
        private void CheckCommandLineProcessAuditing()
        {
            int value = RegistryHelper.GetDword(CmdLineAuditPath, "ProcessCreationIncludeCmdLine_Enabled", 0);
            bool cmdLineEnabled = value == 1;

            AddCheck(
                check: "Command Line Process Auditing",
                requirement: "HIPAA \u00a7 164.312(b) - Detailed Process Tracking",
                passed: cmdLineEnabled,
                currentValue: cmdLineEnabled ? "Enabled" : "Disabled",
                expectedValue: "Enabled",
                remediation: "Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord",
                nist: "AU-2, AU-12",
                cis: "8.2",
                iso27001: "A.12.4.1, A.12.4.3",
                sox: "ITGC-05",
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > System > Audit Process Creation > Include command line in process creation events = Enabled");
        }

        /// <summary>
        /// Checks if advanced audit policy subcategories override legacy category-level audit policies.
        /// This ensures the more granular advanced audit policy settings take precedence.
        /// </summary>
        private void CheckAdvancedAuditPolicyOverride()
        {
            int value = RegistryHelper.GetDword(LsaPath, "SCENoApplyLegacyAuditPolicy", 0);
            bool overrideEnabled = value == 1;

            AddCheck(
                check: "Advanced Audit Policy Override",
                requirement: "SOC 2 CC6.1 - Proper Audit Configuration",
                passed: overrideEnabled,
                currentValue: overrideEnabled ? "Enabled" : "Disabled",
                expectedValue: "Enabled",
                remediation: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord",
                nist: "AU-3",
                cis: "8.2",
                iso27001: "A.12.4.1",
                sox: "ITGC-05",
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog > Local Policies Security Options > Audit: Force audit policy subcategory settings to override audit policy category settings = Enabled");
        }

        /// <summary>
        /// Checks if PowerShell module logging is enabled via Group Policy.
        /// Module logging records pipeline execution events for specified modules.
        /// </summary>
        private void CheckPowerShellModuleLogging()
        {
            int value = RegistryHelper.GetDword(PsModuleLoggingPath, "EnableModuleLogging", 0);
            bool moduleLoggingEnabled = value == 1;

            AddCheck(
                check: "PowerShell Module Logging",
                requirement: "SOC 2 CC7.2 - Command Execution Monitoring",
                passed: moduleLoggingEnabled,
                currentValue: moduleLoggingEnabled ? "Enabled" : "Disabled",
                expectedValue: "Enabled",
                remediation: "Enable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging",
                nist: "AU-2, AU-12",
                cis: "8.2",
                iso27001: "A.12.4.1, A.12.4.3",
                sox: "ITGC-05",
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging = Enabled");
        }

        /// <summary>
        /// Checks if PowerShell script block logging is enabled via Group Policy.
        /// Script block logging records the content of all script blocks that are processed.
        /// </summary>
        private void CheckPowerShellScriptBlockLogging()
        {
            int value = RegistryHelper.GetDword(PsScriptBlockLoggingPath, "EnableScriptBlockLogging", 0);
            bool scriptBlockLoggingEnabled = value == 1;

            AddCheck(
                check: "PowerShell Script Block Logging",
                requirement: "SOC 2 CC7.2 - Command Execution Monitoring",
                passed: scriptBlockLoggingEnabled,
                currentValue: scriptBlockLoggingEnabled ? "Enabled" : "Disabled",
                expectedValue: "Enabled",
                remediation: "Enable via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging",
                nist: "AU-2, AU-12",
                cis: "8.2",
                iso27001: "A.12.4.1, A.12.4.3",
                sox: "ITGC-05",
                intuneRecommendation: "Devices > Configuration profiles > Create profile > Settings catalog > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging = Enabled");
        }
    }
}
