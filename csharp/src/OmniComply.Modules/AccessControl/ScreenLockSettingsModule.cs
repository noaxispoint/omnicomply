using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.AccessControl
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Screen Lock Settings")]
    [ExportMetadata("Category", "Screen Lock Settings")]
    [ExportMetadata("Order", 9)]
    public class ScreenLockSettingsModule : ComplianceModuleBase
    {
        private const string DesktopRegistryPath = @"HKCU\Control Panel\Desktop";

        public override string Name => "Screen Lock Settings";
        public override string Description => "Validates screen saver and screen lock configuration for workstation security";
        public override string Category => "Screen Lock Settings";
        public override int Order => 9;

        protected override void RunChecks()
        {
            CheckScreenSaveTimeout();
            CheckScreenSaveActive();
            CheckScreenSaverIsSecure();
        }

        private void CheckScreenSaveTimeout()
        {
            try
            {
                string timeoutStr = RegistryHelper.GetString(DesktopRegistryPath, "ScreenSaveTimeOut", null);
                int timeout = 0;
                bool parsed = !string.IsNullOrEmpty(timeoutStr) && int.TryParse(timeoutStr, out timeout);
                bool passed;
                string currentValue;

                if (!parsed)
                {
                    timeout = 0;
                    passed = false;
                    currentValue = string.IsNullOrEmpty(timeoutStr)
                        ? "Not configured"
                        : "Invalid value: " + timeoutStr;
                }
                else
                {
                    passed = timeout > 0 && timeout <= 900;
                    currentValue = timeout + " seconds (" + (timeout / 60) + " minutes)";
                }

                AddCheck(
                    check: "Screen Saver Timeout",
                    requirement: "Screen saver timeout must be set to 900 seconds (15 minutes) or less",
                    passed: passed,
                    currentValue: currentValue,
                    expectedValue: "<= 900 seconds (15 minutes)",
                    remediation: "Configure the screen saver timeout: Control Panel > Personalization > Lock screen > Screen saver settings > Wait = 15 minutes or less. Or set registry HKCU\\Control Panel\\Desktop\\ScreenSaveTimeOut = 900 or less. For domain environments, use Group Policy: User Configuration > Administrative Templates > Control Panel > Personalization > Screen saver timeout.",
                    nist: "AC-11",
                    cis: "2.3.7",
                    iso27001: "A.11.2.8, A.11.2.9",
                    pciDss: "8.1.8",
                    intuneRecommendation: "Devices > Configuration profiles > Device restrictions > Lock Screen > Maximum minutes of inactivity until screen locks = 15"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Screen Saver Timeout",
                    requirement: "Screen saver timeout must be set to 900 seconds (15 minutes) or less",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "<= 900 seconds (15 minutes)",
                    remediation: "Verify registry access to HKCU\\Control Panel\\Desktop\\ScreenSaveTimeOut",
                    nist: "AC-11",
                    cis: "2.3.7",
                    iso27001: "A.11.2.8, A.11.2.9",
                    pciDss: "8.1.8"
                );
            }
        }

        private void CheckScreenSaveActive()
        {
            try
            {
                string screenSaveActive = RegistryHelper.GetString(DesktopRegistryPath, "ScreenSaveActive", null);
                bool passed = screenSaveActive == "1";

                string currentValue;
                if (string.IsNullOrEmpty(screenSaveActive))
                    currentValue = "Not configured";
                else if (screenSaveActive == "1")
                    currentValue = "1 (Enabled)";
                else
                    currentValue = screenSaveActive + " (Disabled)";

                AddCheck(
                    check: "Screen Saver Enabled",
                    requirement: "Screen saver must be enabled",
                    passed: passed,
                    currentValue: currentValue,
                    expectedValue: "1 (Enabled)",
                    remediation: "Enable the screen saver: Control Panel > Personalization > Lock screen > Screen saver settings > select a screen saver. Or set registry HKCU\\Control Panel\\Desktop\\ScreenSaveActive = 1. For domain environments, use Group Policy: User Configuration > Administrative Templates > Control Panel > Personalization > Enable screen saver.",
                    nist: "AC-11",
                    cis: "2.3.7",
                    iso27001: "A.11.2.8, A.11.2.9",
                    pciDss: "8.1.8",
                    intuneRecommendation: "Devices > Configuration profiles > Device restrictions > Lock Screen > Screen saver = Enabled"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Screen Saver Enabled",
                    requirement: "Screen saver must be enabled",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "1 (Enabled)",
                    remediation: "Verify registry access to HKCU\\Control Panel\\Desktop\\ScreenSaveActive",
                    nist: "AC-11",
                    cis: "2.3.7",
                    iso27001: "A.11.2.8, A.11.2.9",
                    pciDss: "8.1.8"
                );
            }
        }

        private void CheckScreenSaverIsSecure()
        {
            try
            {
                string screenSaverSecure = RegistryHelper.GetString(DesktopRegistryPath, "ScreenSaverIsSecure", null);
                bool passed = screenSaverSecure == "1";

                string currentValue;
                if (string.IsNullOrEmpty(screenSaverSecure))
                    currentValue = "Not configured";
                else if (screenSaverSecure == "1")
                    currentValue = "1 (Password protected)";
                else
                    currentValue = screenSaverSecure + " (Not password protected)";

                AddCheck(
                    check: "Screen Saver Password Protection",
                    requirement: "Screen saver must require a password on resume",
                    passed: passed,
                    currentValue: currentValue,
                    expectedValue: "1 (Password protected)",
                    remediation: "Enable screen saver password protection: Control Panel > Personalization > Lock screen > Screen saver settings > check 'On resume, display logon screen'. Or set registry HKCU\\Control Panel\\Desktop\\ScreenSaverIsSecure = 1. For domain environments, use Group Policy: User Configuration > Administrative Templates > Control Panel > Personalization > Password protect the screen saver.",
                    nist: "AC-11",
                    cis: "2.3.7",
                    iso27001: "A.11.2.8, A.11.2.9",
                    pciDss: "8.1.8",
                    intuneRecommendation: "Devices > Configuration profiles > Device restrictions > Lock Screen > Password required to unlock = Yes"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Screen Saver Password Protection",
                    requirement: "Screen saver must require a password on resume",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "1 (Password protected)",
                    remediation: "Verify registry access to HKCU\\Control Panel\\Desktop\\ScreenSaverIsSecure",
                    nist: "AC-11",
                    cis: "2.3.7",
                    iso27001: "A.11.2.8, A.11.2.9",
                    pciDss: "8.1.8"
                );
            }
        }
    }
}
