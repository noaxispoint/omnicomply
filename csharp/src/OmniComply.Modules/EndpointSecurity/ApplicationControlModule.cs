using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.EndpointSecurity
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Application Control")]
    [ExportMetadata("Category", "Application Control")]
    [ExportMetadata("Order", 20)]
    public class ApplicationControlModule : ComplianceModuleBase
    {
        public override string Name => "Application Control";
        public override string Description => "Validates application whitelisting controls including AppLocker, WDAC, and SmartScreen";
        public override string Category => "Application Control";
        public override int Order => 20;

        private const string Nist = "CM-7(5)";
        private const string Cis = "2.5";
        private const string Iso = "A.12.6.2";

        protected override void RunChecks()
        {
            CheckAppLockerService();
            CheckAppLockerPolicies();
            CheckWdacPolicy();
            CheckSmartScreen();
        }

        private void CheckAppLockerService()
        {
            // Check if the Application Identity service (AppIDSvc) is running
            var result = ProcessHelper.Run("sc.exe", "query AppIDSvc");

            bool serviceRunning = false;
            string currentValue = "Service not found";

            if (result.Success && result.StandardOutput != null)
            {
                string output = result.StandardOutput;
                if (output.Contains("RUNNING"))
                {
                    serviceRunning = true;
                    currentValue = "Running";
                }
                else if (output.Contains("STOPPED"))
                {
                    currentValue = "Stopped";
                }
                else if (output.Contains("START_PENDING") || output.Contains("STOP_PENDING"))
                {
                    currentValue = "Transitioning";
                }
            }

            AddCheck(
                "AppLocker Service (AppIDSvc)",
                "Application Identity service must be running for AppLocker policy enforcement",
                serviceRunning,
                currentValue,
                "Running",
                "Start the Application Identity service: sc config AppIDSvc start= auto && net start AppIDSvc. The service must be running for AppLocker rules to be enforced.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckAppLockerPolicies()
        {
            // Check for AppLocker policy configuration in the SrpV2 registry key
            bool exeRulesExist = RegistryHelper.KeyExists(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe");
            bool msiRulesExist = RegistryHelper.KeyExists(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi");
            bool scriptRulesExist = RegistryHelper.KeyExists(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script");
            bool dllRulesExist = RegistryHelper.KeyExists(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Dll");
            bool appxRulesExist = RegistryHelper.KeyExists(
                @"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Appx");

            int configuredCount = 0;
            if (exeRulesExist) configuredCount++;
            if (msiRulesExist) configuredCount++;
            if (scriptRulesExist) configuredCount++;
            if (dllRulesExist) configuredCount++;
            if (appxRulesExist) configuredCount++;

            bool passed = configuredCount >= 1;
            string currentValue = configuredCount > 0
                ? string.Format("{0} rule collection(s) configured (Exe:{1}, Msi:{2}, Script:{3}, Dll:{4}, Appx:{5})",
                    configuredCount,
                    exeRulesExist ? "Yes" : "No",
                    msiRulesExist ? "Yes" : "No",
                    scriptRulesExist ? "Yes" : "No",
                    dllRulesExist ? "Yes" : "No",
                    appxRulesExist ? "Yes" : "No")
                : "No AppLocker policies configured";

            AddCheck(
                "AppLocker Policies",
                "AppLocker policies must be configured to control application execution",
                passed,
                currentValue,
                "At least one rule collection configured",
                "Configure AppLocker via Group Policy: Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker. Create rules for Executable, Windows Installer, Script, and Packaged app rules. Start with audit mode before enforcing.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckWdacPolicy()
        {
            // Check WDAC (Windows Defender Application Control) / Code Integrity policy
            int umciAuditMode = RegistryHelper.GetDword(
                @"HKLM\SYSTEM\CurrentControlSet\Control\CI",
                "UMCIAuditMode");

            string activePolicies = RegistryHelper.GetString(
                @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
                "ActivePolicies");

            bool hasPolicies = !string.IsNullOrEmpty(activePolicies);
            bool hasUmci = umciAuditMode >= 0;
            bool passed = hasPolicies || hasUmci;

            string currentValue;
            if (hasPolicies)
                currentValue = "WDAC active policies detected";
            else if (hasUmci)
                currentValue = umciAuditMode == 1
                    ? "UMCI in Audit Mode"
                    : "UMCI configured (mode: " + umciAuditMode + ")";
            else
                currentValue = "No WDAC/Code Integrity policies detected";

            AddCheck(
                "Windows Defender Application Control (WDAC)",
                "WDAC Code Integrity policies should be configured to restrict application execution",
                passed,
                currentValue,
                "WDAC policies active",
                "Deploy WDAC policies using the WDAC Wizard or PowerShell. Create a base policy with New-CIPolicy, then deploy with ConvertFrom-CIPolicy and copy to C:\\Windows\\System32\\CodeIntegrity. For managed environments, deploy via Intune or Group Policy.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }

        private void CheckSmartScreen()
        {
            string smartScreenValue = RegistryHelper.GetString(
                @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                "SmartScreenEnabled");

            bool passed = string.Equals(smartScreenValue, "RequireAdmin", StringComparison.OrdinalIgnoreCase) ||
                          string.Equals(smartScreenValue, "Warn", StringComparison.OrdinalIgnoreCase);

            string currentValue;
            if (string.IsNullOrEmpty(smartScreenValue))
                currentValue = "Not Configured";
            else if (string.Equals(smartScreenValue, "RequireAdmin", StringComparison.OrdinalIgnoreCase))
                currentValue = "RequireAdmin (requires admin override to run unrecognized apps)";
            else if (string.Equals(smartScreenValue, "Warn", StringComparison.OrdinalIgnoreCase))
                currentValue = "Warn (warns before running unrecognized apps)";
            else if (string.Equals(smartScreenValue, "Off", StringComparison.OrdinalIgnoreCase))
                currentValue = "Off (SmartScreen disabled)";
            else
                currentValue = smartScreenValue;

            AddCheck(
                "Windows SmartScreen",
                "Windows SmartScreen must be configured to warn or require admin approval for unrecognized applications",
                passed,
                currentValue,
                "RequireAdmin or Warn",
                "Enable SmartScreen via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows Defender SmartScreen > Explorer > Configure Windows Defender SmartScreen. Set to 'Warn' or 'Warn and prevent bypass'. Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SmartScreenEnabled = RequireAdmin.",
                nist: Nist, cis: Cis, iso27001: Iso
            );
        }
    }
}
