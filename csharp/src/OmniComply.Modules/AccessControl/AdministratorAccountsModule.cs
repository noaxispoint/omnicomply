using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.AccessControl
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Administrator Accounts")]
    [ExportMetadata("Category", "Administrator Accounts")]
    [ExportMetadata("Order", 13)]
    public class AdministratorAccountsModule : ComplianceModuleBase
    {
        public override string Name => "Administrator Accounts";
        public override string Description => "Validates administrator account security, including default account renaming, group membership, and stale account detection";
        public override string Category => "Administrator Accounts";
        public override int Order => 13;

        protected override void RunChecks()
        {
            CheckDefaultAdminRenamed();
            CheckAdminGroupMembership();
            CheckStaleAdminAccounts();
        }

        private void CheckDefaultAdminRenamed()
        {
            try
            {
                var defaultAdmin = WmiHelper.QueryFirstWhere(
                    "Win32_UserAccount",
                    "Name='Administrator' AND LocalAccount=TRUE");

                bool adminExists = defaultAdmin != null;
                bool passed = !adminExists;
                string currentValue;

                if (adminExists)
                {
                    string sid = WmiHelper.GetPropertyString(defaultAdmin, "SID") ?? "Unknown";
                    currentValue = "Default 'Administrator' account exists (SID: " + sid + ")";
                }
                else
                {
                    // The default admin account was renamed - try to find the account by well-known SID suffix -500
                    var allAccounts = WmiHelper.QueryAll("Win32_UserAccount WHERE LocalAccount=TRUE");
                    string renamedName = null;
                    foreach (var account in allAccounts)
                    {
                        string sid = WmiHelper.GetPropertyString(account, "SID");
                        if (sid != null && sid.EndsWith("-500"))
                        {
                            renamedName = WmiHelper.GetPropertyString(account, "Name");
                            break;
                        }
                    }

                    if (renamedName != null)
                        currentValue = "Default Administrator account renamed to '" + renamedName + "'";
                    else
                        currentValue = "Default Administrator account not found (renamed or disabled)";
                }

                AddCheck(
                    check: "Default Administrator Account Renamed",
                    requirement: "The default Administrator account must be renamed to reduce attack surface",
                    passed: passed,
                    currentValue: currentValue,
                    expectedValue: "Default 'Administrator' account should be renamed",
                    remediation: "Rename the default Administrator account via: Computer Management > Local Users and Groups > Users > Administrator > Rename, or via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Rename administrator account",
                    nist: "AC-2, AC-6",
                    cis: "5.1, 5.4",
                    iso27001: "A.9.2.1, A.9.2.5",
                    pciDss: "8.1.1, 8.1.4"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Default Administrator Account Renamed",
                    requirement: "The default Administrator account must be renamed to reduce attack surface",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "Default 'Administrator' account should be renamed",
                    remediation: "Ensure WMI is accessible and the Win32_UserAccount class is available",
                    nist: "AC-2, AC-6",
                    cis: "5.1, 5.4",
                    iso27001: "A.9.2.1, A.9.2.5",
                    pciDss: "8.1.1, 8.1.4"
                );
            }
        }

        private void CheckAdminGroupMembership()
        {
            try
            {
                var result = ProcessHelper.Run("net", "localgroup Administrators");
                int memberCount = 0;
                var memberNames = new List<string>();

                if (result.Success && !string.IsNullOrEmpty(result.StandardOutput))
                {
                    var lines = result.StandardOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    bool inMemberList = false;

                    foreach (var line in lines)
                    {
                        string trimmed = line.Trim();

                        if (trimmed.StartsWith("---"))
                        {
                            inMemberList = true;
                            continue;
                        }

                        if (inMemberList)
                        {
                            if (trimmed.StartsWith("The command completed"))
                                break;

                            if (!string.IsNullOrWhiteSpace(trimmed))
                            {
                                memberCount++;
                                memberNames.Add(trimmed);
                            }
                        }
                    }
                }

                bool passed = memberCount > 0 && memberCount <= 3;
                string currentValue = memberCount + " member(s): " + string.Join(", ", memberNames);

                AddCheck(
                    check: "Administrator Group Membership",
                    requirement: "The local Administrators group should have a minimal number of members (3 or fewer)",
                    passed: passed,
                    currentValue: currentValue,
                    expectedValue: "<= 3 members in the Administrators group",
                    remediation: "Review and remove unnecessary members from the local Administrators group: Computer Management > Local Users and Groups > Groups > Administrators. Apply the principle of least privilege.",
                    nist: "AC-2, AC-6",
                    cis: "5.1, 5.4",
                    iso27001: "A.9.2.1, A.9.2.5",
                    pciDss: "8.1.1, 8.1.4"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Administrator Group Membership",
                    requirement: "The local Administrators group should have a minimal number of members (3 or fewer)",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "<= 3 members in the Administrators group",
                    remediation: "Ensure 'net localgroup' command is accessible",
                    nist: "AC-2, AC-6",
                    cis: "5.1, 5.4",
                    iso27001: "A.9.2.1, A.9.2.5",
                    pciDss: "8.1.1, 8.1.4"
                );
            }
        }

        private void CheckStaleAdminAccounts()
        {
            try
            {
                var result = ProcessHelper.Run("net", "localgroup Administrators");
                var staleAccounts = new List<string>();
                var memberNames = new List<string>();
                int totalMembers = 0;

                if (result.Success && !string.IsNullOrEmpty(result.StandardOutput))
                {
                    var lines = result.StandardOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    bool inMemberList = false;

                    foreach (var line in lines)
                    {
                        string trimmed = line.Trim();

                        if (trimmed.StartsWith("---"))
                        {
                            inMemberList = true;
                            continue;
                        }

                        if (inMemberList)
                        {
                            if (trimmed.StartsWith("The command completed"))
                                break;

                            if (!string.IsNullOrWhiteSpace(trimmed))
                            {
                                totalMembers++;
                                memberNames.Add(trimmed);
                            }
                        }
                    }
                }

                // Check each local admin account for staleness via WMI
                foreach (string memberName in memberNames)
                {
                    // Skip domain accounts (contain backslash)
                    if (memberName.Contains("\\"))
                        continue;

                    var userAccount = WmiHelper.QueryFirstWhere(
                        "Win32_UserAccount",
                        "Name='" + memberName.Replace("'", "''") + "' AND LocalAccount=TRUE");

                    if (userAccount != null)
                    {
                        // Use net user to check last logon
                        var netUserResult = ProcessHelper.Run("net", "user \"" + memberName + "\"");
                        if (netUserResult.Success && !string.IsNullOrEmpty(netUserResult.StandardOutput))
                        {
                            var outputLines = netUserResult.StandardOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (var outputLine in outputLines)
                            {
                                if (outputLine.Trim().StartsWith("Last logon", StringComparison.OrdinalIgnoreCase))
                                {
                                    string lastLogonStr = outputLine.Substring(outputLine.IndexOf(' ', outputLine.IndexOf("logon", StringComparison.OrdinalIgnoreCase)) + 1).Trim();
                                    if (lastLogonStr.Equals("Never", StringComparison.OrdinalIgnoreCase))
                                    {
                                        staleAccounts.Add(memberName + " (never logged on)");
                                    }
                                    else
                                    {
                                        DateTime lastLogon;
                                        if (DateTime.TryParse(lastLogonStr, out lastLogon))
                                        {
                                            int daysSinceLogon = (int)(DateTime.Now - lastLogon).TotalDays;
                                            if (daysSinceLogon > 90)
                                            {
                                                staleAccounts.Add(memberName + " (" + daysSinceLogon + " days since last logon)");
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }

                bool passed = staleAccounts.Count == 0;
                string currentValue = passed
                    ? "No stale administrator accounts detected"
                    : staleAccounts.Count + " stale account(s): " + string.Join(", ", staleAccounts);

                AddCheck(
                    check: "Stale Administrator Accounts",
                    requirement: "Administrator accounts must have logged on within the last 90 days",
                    passed: passed,
                    currentValue: currentValue,
                    expectedValue: "No administrator accounts inactive for more than 90 days",
                    remediation: "Review and disable or remove administrator accounts that have not been used in over 90 days. Use: net user <username> /active:no, or remove from the Administrators group.",
                    nist: "AC-2, AC-6",
                    cis: "5.1, 5.4",
                    iso27001: "A.9.2.1, A.9.2.5",
                    pciDss: "8.1.1, 8.1.4"
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    check: "Stale Administrator Accounts",
                    requirement: "Administrator accounts must have logged on within the last 90 days",
                    passed: false,
                    currentValue: "Error: " + ex.Message,
                    expectedValue: "No administrator accounts inactive for more than 90 days",
                    remediation: "Ensure 'net localgroup' and 'net user' commands are accessible",
                    nist: "AC-2, AC-6",
                    cis: "5.1, 5.4",
                    iso27001: "A.9.2.1, A.9.2.5",
                    pciDss: "8.1.1, 8.1.4"
                );
            }
        }
    }
}
