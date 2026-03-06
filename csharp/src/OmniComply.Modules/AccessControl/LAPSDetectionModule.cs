using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.AccessControl
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "LAPS Detection")]
    [ExportMetadata("Category", "LAPS Detection")]
    [ExportMetadata("Order", 14)]
    public class LAPSDetectionModule : ComplianceModuleBase
    {
        private const string LegacyLapsRegistryPath = @"HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd";
        private const string WindowsLapsRegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS";
        private const string WindowsLapsPolicyPath = @"HKLM\SOFTWARE\Microsoft\Policies\LAPS";

        public override string Name => "LAPS Detection";
        public override string Description => "Detects whether Local Administrator Password Solution (LAPS) is installed and configured";
        public override string Category => "LAPS Detection";
        public override int Order => 14;

        protected override void RunChecks()
        {
            CheckLapsInstalled();
            CheckLegacyLapsGpoConfigured();
            CheckWindowsLaps();
        }

        private void CheckLapsInstalled()
        {
            try
            {
                bool legacyLapsInstalled = RegistryHelper.KeyExists(LegacyLapsRegistryPath);
                bool windowsLapsInstalled = RegistryHelper.KeyExists(WindowsLapsRegistryPath);
                bool anyLapsInstalled = legacyLapsInstalled || windowsLapsInstalled;

                string currentValue;
                if (legacyLapsInstalled && windowsLapsInstalled)
                    currentValue = "Both Legacy LAPS and Windows LAPS detected";
                else if (legacyLapsInstalled)
                    currentValue = "Legacy LAPS (Microsoft LAPS / AdmPwd) installed";
                else if (windowsLapsInstalled)
                    currentValue = "Windows LAPS (built-in) detected";
                else
                    currentValue = "No LAPS installation detected";

                AddCheck(
                    check: "LAPS Installation Status",
                    requirement: "Local Administrator Password Solution (LAPS) must be installed for local admin password management",
                    passed: anyLapsInstalled,
                    currentValue: currentValue,
                    expectedValue: "LAPS installed (Legacy or Windows LAPS)",
                    remediation: "Install LAPS: For legacy LAPS, download and install from Microsoft (https://www.microsoft.com/en-us/download/details.aspx?id=46899). For Windows LAPS (Windows 11 21H2+/Server 2019+), it is built into the OS. Verify registry keys exist at HKLM\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd or HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS.",
                    nist: "AC-2, IA-5",
                    cis: "5.3",
                    iso27001: "A.9.2.3",
                    sox: "ITGC-02"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "LAPS Installation Status",
                    requirement: "Local Administrator Password Solution (LAPS) must be installed for local admin password management",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "LAPS installed (Legacy or Windows LAPS)",
                    remediation: "Verify registry access to LAPS registry keys",
                    nist: "AC-2, IA-5",
                    cis: "5.3",
                    iso27001: "A.9.2.3",
                    sox: "ITGC-02"
                );
            }
        }

        private void CheckLegacyLapsGpoConfigured()
        {
            try
            {
                bool keyExists = RegistryHelper.KeyExists(LegacyLapsRegistryPath);
                bool gpoConfigured = false;
                string currentValue;

                if (!keyExists)
                {
                    currentValue = "Legacy LAPS policy registry key not found";
                }
                else
                {
                    // Check for key GPO configuration values
                    int admpwdEnabled = RegistryHelper.GetDword(LegacyLapsRegistryPath, "AdmPwdEnabled", -1);
                    int passwordLength = RegistryHelper.GetDword(LegacyLapsRegistryPath, "PasswordLength", -1);
                    int passwordAgeDays = RegistryHelper.GetDword(LegacyLapsRegistryPath, "PasswordAgeDays", -1);
                    int passwordComplexity = RegistryHelper.GetDword(LegacyLapsRegistryPath, "PasswordComplexity", -1);

                    gpoConfigured = admpwdEnabled == 1;

                    if (gpoConfigured)
                    {
                        currentValue = "Legacy LAPS GPO configured (Enabled=" + admpwdEnabled;
                        if (passwordLength > 0)
                            currentValue += ", Length=" + passwordLength;
                        if (passwordAgeDays > 0)
                            currentValue += ", MaxAge=" + passwordAgeDays + " days";
                        if (passwordComplexity >= 0)
                            currentValue += ", Complexity=" + passwordComplexity;
                        currentValue += ")";
                    }
                    else
                    {
                        currentValue = "Legacy LAPS registry key exists but policy is not enabled (AdmPwdEnabled=" + (admpwdEnabled == -1 ? "not set" : admpwdEnabled.ToString()) + ")";
                    }
                }

                AddCheck(
                    check: "Legacy LAPS GPO Configuration",
                    requirement: "Legacy LAPS Group Policy must be configured and enabled if Legacy LAPS is in use",
                    passed: gpoConfigured,
                    currentValue: currentValue,
                    expectedValue: "Legacy LAPS GPO enabled with password policy configured",
                    remediation: "Configure Legacy LAPS via Group Policy: Computer Configuration > Administrative Templates > LAPS > Enable local admin password management = Enabled. Set password complexity, length (>= 14), and age (<= 30 days).",
                    nist: "AC-2, IA-5",
                    cis: "5.3",
                    iso27001: "A.9.2.3",
                    sox: "ITGC-02"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Legacy LAPS GPO Configuration",
                    requirement: "Legacy LAPS Group Policy must be configured and enabled if Legacy LAPS is in use",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "Legacy LAPS GPO enabled with password policy configured",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
                    nist: "AC-2, IA-5",
                    cis: "5.3",
                    iso27001: "A.9.2.3",
                    sox: "ITGC-02"
                );
            }
        }

        private void CheckWindowsLaps()
        {
            try
            {
                bool windowsLapsExists = RegistryHelper.KeyExists(WindowsLapsRegistryPath);
                bool windowsLapsPolicyExists = RegistryHelper.KeyExists(WindowsLapsPolicyPath);
                bool configured = false;
                string currentValue;

                if (!windowsLapsExists && !windowsLapsPolicyExists)
                {
                    currentValue = "Windows LAPS not detected on this system";
                }
                else
                {
                    // Check Windows LAPS policy configuration
                    // Policy path takes precedence; fall back to the LAPS registry path
                    string policySource = windowsLapsPolicyExists ? WindowsLapsPolicyPath : WindowsLapsRegistryPath;

                    int backupDirectory = RegistryHelper.GetDword(policySource, "BackupDirectory", -1);
                    int passwordAgeDays = RegistryHelper.GetDword(policySource, "PasswordAgeDays", -1);
                    int passwordLength = RegistryHelper.GetDword(policySource, "PasswordLength", -1);
                    int passwordComplexity = RegistryHelper.GetDword(policySource, "PasswordComplexity", -1);
                    int postAuthActions = RegistryHelper.GetDword(policySource, "PostAuthenticationActions", -1);

                    // BackupDirectory: 0=disabled, 1=AAD, 2=AD
                    configured = backupDirectory == 1 || backupDirectory == 2;

                    if (configured)
                    {
                        string backupTarget = backupDirectory == 1 ? "Azure AD" : "Active Directory";
                        currentValue = "Windows LAPS configured (Backup=" + backupTarget;
                        if (passwordLength > 0)
                            currentValue += ", Length=" + passwordLength;
                        if (passwordAgeDays > 0)
                            currentValue += ", MaxAge=" + passwordAgeDays + " days";
                        if (passwordComplexity >= 0)
                            currentValue += ", Complexity=" + passwordComplexity;
                        if (postAuthActions >= 0)
                            currentValue += ", PostAuth=" + postAuthActions;
                        currentValue += ")";
                    }
                    else
                    {
                        currentValue = "Windows LAPS registry key exists but backup directory is not configured (BackupDirectory=" + (backupDirectory == -1 ? "not set" : backupDirectory.ToString()) + ")";
                    }
                }

                AddCheck(
                    check: "Windows LAPS Configuration",
                    requirement: "Windows LAPS (built-in to Windows 11/Server 2019+) must be configured with a backup directory",
                    passed: configured,
                    currentValue: currentValue,
                    expectedValue: "Windows LAPS configured with backup to Azure AD or Active Directory",
                    remediation: "Configure Windows LAPS via Group Policy: Computer Configuration > Administrative Templates > System > LAPS > Configure password backup directory = Enabled (select Azure Active Directory or Active Directory). Set password complexity, length (>= 14), and age (<= 30 days). Or configure via Intune: Endpoint security > Account protection > Local admin password solution (Windows LAPS).",
                    nist: "AC-2, IA-5",
                    cis: "5.3",
                    iso27001: "A.9.2.3",
                    sox: "ITGC-02"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Windows LAPS Configuration",
                    requirement: "Windows LAPS (built-in to Windows 11/Server 2019+) must be configured with a backup directory",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "Windows LAPS configured with backup to Azure AD or Active Directory",
                    remediation: "Verify registry access to Windows LAPS registry keys at HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS and HKLM\\SOFTWARE\\Microsoft\\Policies\\LAPS",
                    nist: "AC-2, IA-5",
                    cis: "5.3",
                    iso27001: "A.9.2.3",
                    sox: "ITGC-02"
                );
            }
        }
    }
}
