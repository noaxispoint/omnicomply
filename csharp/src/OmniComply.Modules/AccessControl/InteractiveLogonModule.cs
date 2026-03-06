using System;
using System.ComponentModel.Composition;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.AccessControl
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Interactive Logon")]
    [ExportMetadata("Category", "Interactive Logon")]
    [ExportMetadata("Order", 22)]
    public class InteractiveLogonModule : ComplianceModuleBase
    {
        private const string PoliciesSystemPath = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        private const string WinlogonPath = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

        public override string Name => "Interactive Logon";
        public override string Description => "Validates interactive logon settings including legal notices, cached logons, and inactivity timeouts";
        public override string Category => "Interactive Logon";
        public override int Order => 22;

        protected override void RunChecks()
        {
            CheckLegalNoticeCaption();
            CheckLegalNoticeText();
            CheckCachedLogonsCount();
            CheckInactivityTimeout();
        }

        private void CheckLegalNoticeCaption()
        {
            try
            {
                string caption = RegistryHelper.GetString(PoliciesSystemPath, "LegalNoticeCaption", "");
                bool passed = !string.IsNullOrWhiteSpace(caption);

                AddCheck(
                    check: "Legal Notice Caption",
                    requirement: "A legal notice caption must be configured for interactive logon",
                    passed: passed,
                    currentValue: passed ? "Configured: \"" + (caption.Length > 80 ? caption.Substring(0, 80) + "..." : caption) + "\"" : "Not configured (empty)",
                    expectedValue: "A non-empty legal notice caption",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Message title for users attempting to log on. Set an appropriate legal warning caption.",
                    nist: "AC-8, AC-11",
                    cis: "2.3.7",
                    iso27001: "A.9.4.2"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Legal Notice Caption",
                    requirement: "A legal notice caption must be configured for interactive logon",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "A non-empty legal notice caption",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption",
                    nist: "AC-8, AC-11",
                    cis: "2.3.7",
                    iso27001: "A.9.4.2"
                );
            }
        }

        private void CheckLegalNoticeText()
        {
            try
            {
                string noticeText = RegistryHelper.GetString(PoliciesSystemPath, "LegalNoticeText", "");
                bool passed = !string.IsNullOrWhiteSpace(noticeText);

                AddCheck(
                    check: "Legal Notice Text",
                    requirement: "A legal notice text must be configured for interactive logon",
                    passed: passed,
                    currentValue: passed ? "Configured (" + noticeText.Length + " characters)" : "Not configured (empty)",
                    expectedValue: "A non-empty legal notice text",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Message text for users attempting to log on. Set an appropriate legal warning message.",
                    nist: "AC-8, AC-11",
                    cis: "2.3.7",
                    iso27001: "A.9.4.2"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Legal Notice Text",
                    requirement: "A legal notice text must be configured for interactive logon",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "A non-empty legal notice text",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText",
                    nist: "AC-8, AC-11",
                    cis: "2.3.7",
                    iso27001: "A.9.4.2"
                );
            }
        }

        private void CheckCachedLogonsCount()
        {
            try
            {
                string cachedLogonsStr = RegistryHelper.GetString(WinlogonPath, "CachedLogonsCount", "10");
                int cachedLogons;
                bool parsed = int.TryParse(cachedLogonsStr, out cachedLogons);

                if (!parsed)
                {
                    cachedLogons = 10; // Windows default
                }

                bool passed = cachedLogons <= 4;

                AddCheck(
                    check: "Cached Logons Count",
                    requirement: "The number of cached logon credentials must be 4 or fewer",
                    passed: passed,
                    currentValue: cachedLogons + " cached logon(s)",
                    expectedValue: "<= 4 cached logons",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Number of previous logons to cache = 4 or fewer. Or set registry HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount = 4",
                    nist: "AC-8, AC-11",
                    cis: "2.3.7",
                    iso27001: "A.9.4.2"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Cached Logons Count",
                    requirement: "The number of cached logon credentials must be 4 or fewer",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "<= 4 cached logons",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount",
                    nist: "AC-8, AC-11",
                    cis: "2.3.7",
                    iso27001: "A.9.4.2"
                );
            }
        }

        private void CheckInactivityTimeout()
        {
            try
            {
                int inactivityTimeout = RegistryHelper.GetDword(PoliciesSystemPath, "InactivityTimeoutSecs", -1);
                bool passed;
                string currentValue;

                if (inactivityTimeout == -1 || inactivityTimeout == 0)
                {
                    passed = false;
                    currentValue = inactivityTimeout == -1
                        ? "Not configured (no inactivity timeout)"
                        : "0 (disabled)";
                }
                else
                {
                    passed = inactivityTimeout <= 900;
                    currentValue = inactivityTimeout + " seconds (" + (inactivityTimeout / 60) + " minutes)";
                }

                AddCheck(
                    check: "Machine Inactivity Timeout",
                    requirement: "Machine inactivity timeout must be set to 900 seconds (15 minutes) or less",
                    passed: passed,
                    currentValue: currentValue,
                    expectedValue: "<= 900 seconds (15 minutes)",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Machine inactivity limit = 900 or fewer. Or set registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs = 900",
                    nist: "AC-8, AC-11",
                    cis: "2.3.7",
                    iso27001: "A.9.4.2"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Machine Inactivity Timeout",
                    requirement: "Machine inactivity timeout must be set to 900 seconds (15 minutes) or less",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "<= 900 seconds (15 minutes)",
                    remediation: "Verify registry access to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs",
                    nist: "AC-8, AC-11",
                    cis: "2.3.7",
                    iso27001: "A.9.4.2"
                );
            }
        }
    }
}
