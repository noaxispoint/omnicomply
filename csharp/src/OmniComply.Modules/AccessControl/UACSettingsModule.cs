using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.AccessControl
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "UAC Settings")]
    [ExportMetadata("Category", "UAC Settings")]
    [ExportMetadata("Order", 12)]
    public class UACSettingsModule : ComplianceModuleBase
    {
        private const string UacRegistryPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

        public override string Name => "UAC Settings";
        public override string Description => "Validates User Account Control (UAC) configuration for privilege elevation security";
        public override string Category => "UAC Settings";
        public override int Order => 12;

        protected override void RunChecks()
        {
            CheckEnableLUA();
            CheckConsentPromptBehaviorAdmin();
            CheckPromptOnSecureDesktop();
            CheckFilterAdministratorToken();
        }

        private void CheckEnableLUA()
        {
            try
            {
                int enableLUA = RegistryHelper.GetDword(UacRegistryPath, "EnableLUA", -1);
                bool passed = enableLUA == 1;

                AddCheck(
                    check: "UAC Enabled (EnableLUA)",
                    requirement: "User Account Control must be enabled",
                    passed: passed,
                    currentValue: enableLUA == -1 ? "Not configured" : enableLUA.ToString(),
                    expectedValue: "1 (Enabled)",
                    remediation: "Enable UAC via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Run all administrators in Admin Approval Mode = Enabled. Or set registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA = 1",
                    nist: "AC-6(7)",
                    cis: "5.3",
                    iso27001: "A.9.4.4",
                    pciDss: "7.2.2",
                    intuneRecommendation: "Devices > Configuration profiles > Endpoint protection > Local device security options > User Account Control: Run all administrators in Admin Approval Mode = Enabled"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "UAC Enabled (EnableLUA)",
                    requirement: "User Account Control must be enabled",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "1 (Enabled)",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    nist: "AC-6(7)",
                    cis: "5.3",
                    iso27001: "A.9.4.4",
                    pciDss: "7.2.2"
                );
            }
        }

        private void CheckConsentPromptBehaviorAdmin()
        {
            try
            {
                int consentBehavior = RegistryHelper.GetDword(UacRegistryPath, "ConsentPromptBehaviorAdmin", -1);
                bool passed = consentBehavior == 2;

                string currentDescription;
                switch (consentBehavior)
                {
                    case 0: currentDescription = "0 (Elevate without prompting)"; break;
                    case 1: currentDescription = "1 (Prompt for credentials on secure desktop)"; break;
                    case 2: currentDescription = "2 (Prompt for consent on secure desktop)"; break;
                    case 3: currentDescription = "3 (Prompt for credentials)"; break;
                    case 4: currentDescription = "4 (Prompt for consent)"; break;
                    case 5: currentDescription = "5 (Prompt for consent for non-Windows binaries)"; break;
                    default: currentDescription = consentBehavior == -1 ? "Not configured" : consentBehavior.ToString(); break;
                }

                AddCheck(
                    check: "UAC Admin Consent Prompt Behavior",
                    requirement: "UAC must prompt for consent on the secure desktop for admin operations",
                    passed: passed,
                    currentValue: currentDescription,
                    expectedValue: "2 (Prompt for consent on secure desktop)",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Behavior of the elevation prompt for administrators = Prompt for consent on the secure desktop. Or set registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin = 2",
                    nist: "AC-6(7)",
                    cis: "5.3",
                    iso27001: "A.9.4.4",
                    pciDss: "7.2.2",
                    intuneRecommendation: "Devices > Configuration profiles > Endpoint protection > Local device security options > Elevation prompt behavior for administrators = Prompt for consent on the secure desktop"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "UAC Admin Consent Prompt Behavior",
                    requirement: "UAC must prompt for consent on the secure desktop for admin operations",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "2 (Prompt for consent on secure desktop)",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    nist: "AC-6(7)",
                    cis: "5.3",
                    iso27001: "A.9.4.4",
                    pciDss: "7.2.2"
                );
            }
        }

        private void CheckPromptOnSecureDesktop()
        {
            try
            {
                int promptSecureDesktop = RegistryHelper.GetDword(UacRegistryPath, "PromptOnSecureDesktop", -1);
                bool passed = promptSecureDesktop == 1;

                AddCheck(
                    check: "UAC Prompt on Secure Desktop",
                    requirement: "UAC elevation prompts must be displayed on the secure desktop",
                    passed: passed,
                    currentValue: promptSecureDesktop == -1 ? "Not configured" : (promptSecureDesktop == 1 ? "1 (Enabled)" : "0 (Disabled)"),
                    expectedValue: "1 (Enabled)",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Switch to the secure desktop when prompting for elevation = Enabled. Or set registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop = 1",
                    nist: "AC-6(7)",
                    cis: "5.3",
                    iso27001: "A.9.4.4",
                    pciDss: "7.2.2",
                    intuneRecommendation: "Devices > Configuration profiles > Endpoint protection > Local device security options > Switch to the secure desktop when prompting for elevation = Enabled"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "UAC Prompt on Secure Desktop",
                    requirement: "UAC elevation prompts must be displayed on the secure desktop",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "1 (Enabled)",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    nist: "AC-6(7)",
                    cis: "5.3",
                    iso27001: "A.9.4.4",
                    pciDss: "7.2.2"
                );
            }
        }

        private void CheckFilterAdministratorToken()
        {
            try
            {
                int filterToken = RegistryHelper.GetDword(UacRegistryPath, "FilterAdministratorToken", -1);
                bool passed = filterToken == 1;

                AddCheck(
                    check: "UAC Filter Administrator Token",
                    requirement: "Admin Approval Mode for the built-in Administrator account must be enabled",
                    passed: passed,
                    currentValue: filterToken == -1 ? "Not configured (defaults to 0)" : (filterToken == 1 ? "1 (Enabled)" : "0 (Disabled)"),
                    expectedValue: "1 (Enabled)",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > User Account Control: Admin Approval Mode for the Built-in Administrator account = Enabled. Or set registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken = 1",
                    nist: "AC-6(7)",
                    cis: "5.3",
                    iso27001: "A.9.4.4",
                    pciDss: "7.2.2",
                    intuneRecommendation: "Devices > Configuration profiles > Endpoint protection > Local device security options > Admin Approval Mode for the Built-in Administrator account = Enabled"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "UAC Filter Administrator Token",
                    requirement: "Admin Approval Mode for the built-in Administrator account must be enabled",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "1 (Enabled)",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    nist: "AC-6(7)",
                    cis: "5.3",
                    iso27001: "A.9.4.4",
                    pciDss: "7.2.2"
                );
            }
        }
    }
}
