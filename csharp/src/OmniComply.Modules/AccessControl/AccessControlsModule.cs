using System;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.AccessControl
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Access Controls")]
    [ExportMetadata("Category", "Access Controls")]
    [ExportMetadata("Order", 6)]
    public class AccessControlsModule : ComplianceModuleBase
    {
        public override string Name => "Access Controls";
        public override string Description => "Validates password policies, account lockout settings, and guest account status";
        public override string Category => "Access Controls";
        public override int Order => 6;

        protected override void RunChecks()
        {
            CheckMinimumPasswordLength();
            CheckPasswordComplexity();
            CheckPasswordHistory();
            CheckAccountLockoutThreshold();
            CheckGuestAccountDisabled();
        }

        private void CheckMinimumPasswordLength()
        {
            try
            {
                int minLength = SecurityPolicyHelper.GetMinimumPasswordLength();
                bool passed = minLength >= 12;

                AddCheck(
                    check: "Minimum Password Length",
                    requirement: "Minimum password length must be at least 12 characters",
                    passed: passed,
                    currentValue: minLength + " characters",
                    expectedValue: ">= 12 characters",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password length = 12 or greater",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02",
                    intuneRecommendation: "Devices > Configuration profiles > Endpoint protection > Windows encryption > Password > Minimum password length = 12"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Minimum Password Length",
                    requirement: "Minimum password length must be at least 12 characters",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: ">= 12 characters",
                    remediation: "Ensure secedit.exe is accessible and security policy can be exported",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02"
                );
            }
        }

        private void CheckPasswordComplexity()
        {
            try
            {
                bool complexityEnabled = SecurityPolicyHelper.GetPasswordComplexityEnabled();

                AddCheck(
                    check: "Password Complexity Requirements",
                    requirement: "Password complexity requirements must be enabled",
                    passed: complexityEnabled,
                    currentValue: complexityEnabled ? "Enabled (1)" : "Disabled (0)",
                    expectedValue: "Enabled (1)",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Password must meet complexity requirements = Enabled",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Password Complexity Requirements",
                    requirement: "Password complexity requirements must be enabled",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "Enabled (1)",
                    remediation: "Ensure secedit.exe is accessible and security policy can be exported",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02"
                );
            }
        }

        private void CheckPasswordHistory()
        {
            try
            {
                int historySize = SecurityPolicyHelper.GetPasswordHistorySize();
                bool passed = historySize >= 12;

                AddCheck(
                    check: "Password History Size",
                    requirement: "Password history must enforce at least 12 remembered passwords",
                    passed: passed,
                    currentValue: historySize + " passwords remembered",
                    expectedValue: ">= 12 passwords remembered",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy > Enforce password history = 12 or greater",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Password History Size",
                    requirement: "Password history must enforce at least 12 remembered passwords",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: ">= 12 passwords remembered",
                    remediation: "Ensure secedit.exe is accessible and security policy can be exported",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02"
                );
            }
        }

        private void CheckAccountLockoutThreshold()
        {
            try
            {
                int lockoutBadCount = SecurityPolicyHelper.GetLockoutBadCount();
                bool passed = lockoutBadCount >= 1 && lockoutBadCount <= 10;

                string currentDisplay;
                if (lockoutBadCount == 0)
                    currentDisplay = "0 (account lockout disabled)";
                else
                    currentDisplay = lockoutBadCount + " invalid logon attempts";

                AddCheck(
                    check: "Account Lockout Threshold",
                    requirement: "Account lockout threshold must be between 1 and 10 invalid logon attempts",
                    passed: passed,
                    currentValue: currentDisplay,
                    expectedValue: "1-10 invalid logon attempts",
                    remediation: "Configure via Group Policy: Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy > Account lockout threshold = 5 (recommended)",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02",
                    intuneRecommendation: "Devices > Configuration profiles > Endpoint protection > Local device security options > Account lockout threshold = 5"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Account Lockout Threshold",
                    requirement: "Account lockout threshold must be between 1 and 10 invalid logon attempts",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "1-10 invalid logon attempts",
                    remediation: "Ensure secedit.exe is accessible and security policy can be exported",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02"
                );
            }
        }

        private void CheckGuestAccountDisabled()
        {
            try
            {
                bool guestDisabled = true;
                string currentValue = "Could not determine";

                var guestAccount = WmiHelper.QueryFirstWhere(
                    "Win32_UserAccount",
                    "Name='Guest' AND LocalAccount=TRUE");

                if (guestAccount != null)
                {
                    bool disabled = WmiHelper.GetProperty(guestAccount, "Disabled", false);
                    guestDisabled = disabled;
                    currentValue = disabled ? "Disabled" : "Enabled";
                }
                else
                {
                    currentValue = "Guest account not found";
                    guestDisabled = true;
                }

                AddCheck(
                    check: "Guest Account Status",
                    requirement: "The built-in Guest account must be disabled",
                    passed: guestDisabled,
                    currentValue: currentValue,
                    expectedValue: "Disabled",
                    remediation: "Disable the Guest account: net user Guest /active:no, or via Computer Management > Local Users and Groups > Users > Guest > Account is disabled",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Guest Account Status",
                    requirement: "The built-in Guest account must be disabled",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "Disabled",
                    remediation: "Disable the Guest account: net user Guest /active:no",
                    nist: "IA-5(1)",
                    cis: "5.2",
                    iso27001: "A.9.4.3",
                    pciDss: "8.3.6",
                    sox: "ITGC-02"
                );
            }
        }
    }
}
