using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;
using System.Management;
using OmniComply.Core.Engine;
using OmniComply.Core.Interfaces;
using OmniComply.Core.Helpers;

namespace OmniComply.Modules.EnterpriseCompliance
{
    [Export(typeof(IComplianceModule))]
    [ExportMetadata("Name", "Segregation Of Duties")]
    [ExportMetadata("Category", "Segregation Of Duties")]
    [ExportMetadata("Order", 34)]
    public class SegregationOfDutiesModule : ComplianceModuleBase
    {
        public override string Name => "Segregation Of Duties";
        public override string Description => "Validates administrator group size, service account restrictions, shared account detection, and remote desktop user controls";
        public override string Category => "Segregation Of Duties";
        public override int Order => 34;

        private const string Nist = "AC-5, AC-6";
        private const string Cis = "5.4";
        private const string Iso = "A.6.1.2, A.9.2.3";
        private const string PciDss = "7.1, 7.2";
        private const string Sox = "ITGC-01";

        protected override void RunChecks()
        {
            CheckAdminGroupSize();
            CheckServiceAccountRestrictions();
            CheckSharedAccounts();
            CheckRemoteDesktopUsersGroup();
        }

        private void CheckAdminGroupSize()
        {
            try
            {
                var result = ProcessHelper.RunCmd("net localgroup Administrators");

                bool passed = false;
                string currentValue = "Unable to query Administrators group";

                if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
                {
                    var members = ParseGroupMembers(result.StandardOutput);
                    int memberCount = members.Count;

                    passed = memberCount <= 5;
                    currentValue = string.Format("{0} member(s): {1}",
                        memberCount,
                        memberCount > 0 ? string.Join(", ", members) : "None");
                }
                else if (!string.IsNullOrEmpty(result.StandardError))
                {
                    currentValue = "Error querying group: " + result.StandardError.Trim();
                }

                AddCheck(
                    "Administrator Group Size",
                    "The local Administrators group must contain no more than 5 members to enforce least privilege",
                    passed,
                    currentValue,
                    "<= 5 members",
                    "Review and remove unnecessary accounts from the local Administrators group: net localgroup Administrators <account> /delete. Use dedicated admin accounts and implement just-in-time access where possible.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Endpoint Security > Account protection > Create Local user group membership policy. Define the allowed members of the local Administrators group. Use 'Replace' mode to enforce exact membership and remove unauthorized accounts."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Administrator Group Size",
                    "The local Administrators group must contain no more than 5 members to enforce least privilege",
                    false,
                    "Error: " + ex.Message,
                    "<= 5 members",
                    "Verify the scanner has permissions to query local group membership.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckServiceAccountRestrictions()
        {
            try
            {
                bool passed = true;
                string currentValue = "No service accounts found in Administrators group";

                // Get Administrators group members
                var adminResult = ProcessHelper.RunCmd("net localgroup Administrators");
                var adminMembers = new List<string>();
                if (adminResult.Success && !string.IsNullOrWhiteSpace(adminResult.StandardOutput))
                {
                    adminMembers = ParseGroupMembers(adminResult.StandardOutput);
                }

                // Get service accounts - services running as domain or specific user accounts
                var services = WmiHelper.QueryAll("Win32_Service");
                var serviceAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                if (services != null)
                {
                    foreach (var service in services)
                    {
                        string startName = WmiHelper.GetPropertyString(service, "StartName");
                        if (!string.IsNullOrWhiteSpace(startName)
                            && !startName.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase)
                            && !startName.Equals("NT AUTHORITY\\LocalService", StringComparison.OrdinalIgnoreCase)
                            && !startName.Equals("NT AUTHORITY\\NetworkService", StringComparison.OrdinalIgnoreCase)
                            && !startName.Equals("NT Authority\\System", StringComparison.OrdinalIgnoreCase)
                            && !startName.Equals("LocalService", StringComparison.OrdinalIgnoreCase)
                            && !startName.Equals("NetworkService", StringComparison.OrdinalIgnoreCase))
                        {
                            serviceAccounts.Add(startName);
                        }
                    }
                }

                // Check if any service accounts are also in the admin group
                var overlapping = new List<string>();
                foreach (var svcAccount in serviceAccounts)
                {
                    foreach (var admin in adminMembers)
                    {
                        // Compare account names - handle domain\user format
                        if (svcAccount.Equals(admin, StringComparison.OrdinalIgnoreCase)
                            || svcAccount.EndsWith("\\" + admin, StringComparison.OrdinalIgnoreCase)
                            || admin.EndsWith("\\" + svcAccount, StringComparison.OrdinalIgnoreCase))
                        {
                            overlapping.Add(svcAccount);
                            break;
                        }
                    }
                }

                if (overlapping.Count > 0)
                {
                    passed = false;
                    currentValue = string.Format("{0} service account(s) found in Administrators group: {1}",
                        overlapping.Count,
                        string.Join(", ", overlapping));
                }
                else if (serviceAccounts.Count > 0)
                {
                    currentValue = string.Format("{0} service account(s) detected, none in Administrators group",
                        serviceAccounts.Count);
                }

                AddCheck(
                    "Service Account Admin Restrictions",
                    "Service accounts should not be members of the local Administrators group to enforce segregation of duties",
                    passed,
                    currentValue,
                    "No service accounts in Administrators group",
                    "Remove service accounts from the Administrators group and grant only the specific permissions required for each service. Use Managed Service Accounts (gMSA) where possible to reduce credential exposure.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Devices > Scripts > Deploy a PowerShell proactive remediation script to detect service accounts in the Administrators group and alert via compliance reporting."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Service Account Admin Restrictions",
                    "Service accounts should not be members of the local Administrators group to enforce segregation of duties",
                    false,
                    "Error: " + ex.Message,
                    "No service accounts in Administrators group",
                    "Verify WMI access and local group query permissions.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckSharedAccounts()
        {
            try
            {
                bool passed = true;
                string currentValue = "No shared or generic accounts detected";

                var suspiciousNames = new[]
                {
                    "shared", "generic", "test", "temp", "common", "service",
                    "admin1", "admin2", "user1", "user2", "training", "demo"
                };

                var accounts = WmiHelper.QueryAll("Win32_UserAccount");
                var suspiciousAccounts = new List<string>();

                if (accounts != null)
                {
                    foreach (var account in accounts)
                    {
                        bool isLocal = WmiHelper.GetProperty(account, "LocalAccount", false);
                        bool isDisabled = WmiHelper.GetProperty(account, "Disabled", false);

                        if (isLocal && !isDisabled)
                        {
                            string name = WmiHelper.GetPropertyString(account, "Name");
                            if (!string.IsNullOrEmpty(name))
                            {
                                string lowerName = name.ToLowerInvariant();
                                foreach (var suspicious in suspiciousNames)
                                {
                                    if (lowerName.Contains(suspicious))
                                    {
                                        suspiciousAccounts.Add(name);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                if (suspiciousAccounts.Count > 0)
                {
                    passed = false;
                    currentValue = string.Format("{0} potentially shared/generic account(s) detected: {1}",
                        suspiciousAccounts.Count,
                        string.Join(", ", suspiciousAccounts));
                }

                AddCheck(
                    "Shared Account Detection",
                    "Shared or generic user accounts must not exist to ensure individual accountability",
                    passed,
                    currentValue,
                    "No shared or generic accounts detected",
                    "Disable or remove shared/generic accounts: net user <account> /active:no. Create individual named accounts for all users and ensure each person has a unique identity for audit trail purposes.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Devices > Compliance policies > Create custom compliance script to detect accounts with shared/generic naming patterns. Use Intune proactive remediations to flag non-compliant devices with shared accounts."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Shared Account Detection",
                    "Shared or generic user accounts must not exist to ensure individual accountability",
                    false,
                    "Error: " + ex.Message,
                    "No shared or generic accounts detected",
                    "Verify WMI access to Win32_UserAccount.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        private void CheckRemoteDesktopUsersGroup()
        {
            try
            {
                var result = ProcessHelper.RunCmd("net localgroup \"Remote Desktop Users\"");

                bool passed = false;
                string currentValue = "Unable to query Remote Desktop Users group";

                if (result.Success && !string.IsNullOrWhiteSpace(result.StandardOutput))
                {
                    var members = ParseGroupMembers(result.StandardOutput);
                    int memberCount = members.Count;

                    // Remote Desktop Users group should be limited - check for reasonable size
                    passed = memberCount <= 10;
                    currentValue = string.Format("{0} member(s)", memberCount);

                    if (memberCount > 0)
                    {
                        currentValue += ": " + string.Join(", ", members);
                    }
                    else
                    {
                        currentValue = "No members (group is empty)";
                        passed = true;
                    }
                }
                else if (!string.IsNullOrEmpty(result.StandardError))
                {
                    currentValue = "Error querying group: " + result.StandardError.Trim();
                }

                AddCheck(
                    "Remote Desktop Users Group Size",
                    "The Remote Desktop Users group must be limited to authorized personnel only (no more than 10 members)",
                    passed,
                    currentValue,
                    "<= 10 members with documented authorization",
                    "Review and remove unnecessary accounts from the Remote Desktop Users group: net localgroup \"Remote Desktop Users\" <account> /delete. Implement Network Level Authentication (NLA) and consider using Azure AD or VPN-based remote access instead.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox,
                    intuneRecommendation: "Endpoint Security > Account protection > Local user group membership policy. Define authorized Remote Desktop Users group members. Devices > Configuration profiles > Administrative Templates > Remote Desktop Services to enforce NLA."
                );
            }
            catch (Exception ex)
            {
                AddCheck(
                    "Remote Desktop Users Group Size",
                    "The Remote Desktop Users group must be limited to authorized personnel only (no more than 10 members)",
                    false,
                    "Error: " + ex.Message,
                    "<= 10 members with documented authorization",
                    "Verify the scanner has permissions to query local group membership.",
                    nist: Nist, cis: Cis, iso27001: Iso, pciDss: PciDss, sox: Sox
                );
            }
        }

        /// <summary>
        /// Parses the output of "net localgroup" to extract member names.
        /// The format has members listed between two lines of dashes.
        /// </summary>
        private List<string> ParseGroupMembers(string output)
        {
            var members = new List<string>();
            if (string.IsNullOrWhiteSpace(output))
                return members;

            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            bool inMemberSection = false;
            foreach (var rawLine in lines)
            {
                string line = rawLine.Trim();

                if (line.StartsWith("---"))
                {
                    inMemberSection = true;
                    continue;
                }

                if (inMemberSection)
                {
                    if (line.StartsWith("The command completed", StringComparison.OrdinalIgnoreCase))
                        break;

                    if (!string.IsNullOrWhiteSpace(line))
                    {
                        members.Add(line);
                    }
                }
            }

            return members;
        }
    }
}
